package com.oubliette.keystore

import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.CancellationSignal
// The FRAMEWORK keystore exception (public API since 33; present — and thrown
// as the cipher-failure cause — on every device back to minSdk 30; `is` checks
// resolve the class, and hidden-API enforcement restricts members, not class
// resolution). NOT java.security.KeyStoreException, which is a different type.
import android.security.KeyStoreException
import android.util.Log
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel.Result
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher

// android.hardware.biometrics.BiometricPrompt does NOT expose this as a
// resolvable named constant at this compileSdk (the build fails on a named ref;
// the symbol lives in androidx.biometric, which this plugin does not depend on).
// The value is stable platform API. The negative button is the user tapping
// "Cancel", so it is treated as a cancellation.
private const val BIOMETRIC_ERROR_NEGATIVE_BUTTON = 13

/** Maps a crypto exception to the stable error code the Dart layer expects. */
private fun encryptErrorCode(t: Throwable): String = when (t) {
  is KeyNotFoundException -> "key_not_found"
  is KeyInvalidatedException -> "key_invalidated"
  is KeyAuthTypeUnknownException -> "key_auth_type_unknown"
  else -> "encrypt_failed"
}

private fun decryptErrorCode(t: Throwable): String = when (t) {
  is KeyNotFoundException -> "key_not_found"
  is KeyInvalidatedException -> "key_invalidated"
  is KeyAuthTypeUnknownException -> "key_auth_type_unknown"
  else -> "decrypt_failed"
}

/**
 * Whether [t] — or anything in its bounded cause chain — is a bare framework
 * [KeyStoreException] carrying no stronger classification.
 *
 * On the authenticated paths, `Cipher.init` opens a keymaster operation BEFORE
 * the unbounded BiometricPrompt. Keymaster operation slots are a small
 * system-wide pool, so any other process doing crypto while our prompt waits on
 * the user can prune our operation; the post-auth `doFinal` then throws a bare
 * [KeyStoreException] ("operation expired" / "Key user not authenticated"),
 * usually wrapped in an `IllegalBlockSizeException` or `ProviderException`.
 * Both the key and the on-disk blob are healthy — a fresh init + prompt
 * succeeds — so this must surface as the recoverable `decrypt_interrupted`,
 * never the fatal fallback bucket whose documented remedy is "the blob is bad".
 *
 * [AEADBadTagException] anywhere in the chain vetoes the match: a failed GCM
 * tag is a genuine this-blob-does-not-authenticate signal (some keymasters
 * chain a KeyStoreException cause under it) and must stay `decrypt_failed`.
 * Permanent invalidation can never reach this classifier: the scheme wraps it
 * as [KeyInvalidatedException] first (see V1Scheme.isPermanentInvalidation),
 * and the post-auth code maps consult the typed classification before this one.
 */
private fun isTransientKeystoreInterruption(t: Throwable): Boolean {
  var current: Throwable? = t
  var depth = 0
  var sawKeyStoreException = false
  while (current != null && depth < 8) { // bounded: malicious/cyclic chains
    if (current is AEADBadTagException) return false
    if (current is KeyStoreException) sawKeyStoreException = true
    current = current.cause
    depth++
  }
  return sawKeyStoreException
}

/**
 * Post-authentication `doFinal` failures get one extra classification pass on
 * top of the typed code maps: a transient keymaster interruption (see
 * [isTransientKeystoreInterruption]) becomes the recoverable
 * `decrypt_interrupted` instead of the fatal fallback. Typed classifications
 * still win — a doFinal-deferred enrollment invalidation is genuine key loss
 * and must stay `key_invalidated`.
 *
 * Deliberately the SAME code on the encrypt path: the failure mode (operation
 * pruned during the prompt) and the remedy (retry; never purge) are identical,
 * and the Dart layer maps this one stable code to its one recoverable
 * "backend hiccup" exception.
 */
private fun postAuthEncryptErrorCode(t: Throwable): String {
  val code = encryptErrorCode(t)
  return if (code == "encrypt_failed" && isTransientKeystoreInterruption(t)) {
    "decrypt_interrupted"
  } else {
    code
  }
}

private fun postAuthDecryptErrorCode(t: Throwable): String {
  val code = decryptErrorCode(t)
  return if (code == "decrypt_failed" && isTransientKeystoreInterruption(t)) {
    "decrypt_interrupted"
  } else {
    code
  }
}

/**
 * Stable message for `decrypt_interrupted`. Fixed text, not `t.message`: the
 * underlying keymaster strings vary by vendor, and the guidance (retry, never
 * purge) is the part the caller must see. Diagnostic hygiene holds — no alias,
 * no payload content.
 */
private const val INTERRUPTED_MESSAGE =
  "Transient keystore operation failure (keymaster operation lost during authentication) — retry; do not purge."

private fun postAuthErrorMessage(code: String, t: Throwable): String =
  if (code == "decrypt_interrupted") INTERRUPTED_MESSAGE else t.message ?: t.toString()

internal fun KeystorePlugin.handleAuthenticateEncrypt(call: MethodCall, result: Result) {
  val plaintext = call.argument<ByteArray>("plaintext")
  val aad = call.argument<String>("aad")
  val alias = call.argument<String>("alias")
  val title = call.argument<String>("promptTitle") ?: "Authenticate"
  val subtitle = call.argument<String>("promptSubtitle") ?: "Confirm your identity"
  if (plaintext == null || aad == null || alias == null) {
    plaintext?.fill(0)
    result.error("bad_args", "Missing plaintext, aad, or alias.", null)
    return
  }

  // Cipher.init issues a keymaster Binder call that can block on busy hardware;
  // run it off the platform thread, then hop back to the main thread to show
  // BiometricPrompt (which must be built and shown on the UI thread).
  // postCrypto guards the dead-looper case: plaintext is wiped and the Future
  // failed instead of hanging if the plugin detached before this runs.
  postCrypto(result, onDead = { plaintext.fill(0) }) {
    val scheme = SchemeRegistry.schemeFor(SchemeRegistry.CURRENT_VERSION)
    if (scheme == null) {
      plaintext.fill(0)
      mainHandler.post { result.error("encrypt_failed", "Unsupported version.", null) }
      return@postCrypto
    }
    val cipher: Cipher
    val authenticators: KeyAuthenticators
    try {
      cipher = scheme.initEncryptCipher(alias)
      // Derive the prompt's authenticators from the KEY's own KeyInfo, never
      // from the caller — this is the only way they cannot mismatch. A null
      // (non-auth key) is a misuse of the authenticating path: fail closed.
      authenticators = scheme.keyAuthenticators(alias)
        ?: throw KeyAuthTypeUnknownException()
    } catch (e: Throwable) {
      plaintext.fill(0)
      mainHandler.post { result.error(encryptErrorCode(e), e.message ?: e.toString(), null) }
      return@postCrypto
    }
    mainHandler.post {
      authenticate(
        cipher, title, subtitle, authenticators, result,
        onError = { plaintext.fill(0) },
        onSuccess = { authenticatedCipher ->
          // doFinal is a keymaster Binder call; keep it off the platform thread
          // (this callback runs on the activity main executor) and hop back to
          // deliver the result. The cipher is already authorized by the
          // CryptoObject, so using it on the crypto thread is safe.
          val posted = cryptoHandler.post {
            try {
              val encryptResult = scheme.encryptWithCipher(authenticatedCipher, plaintext, aad)
              mainHandler.post {
                result.success(
                  mapOf(
                    "version" to encryptResult.version,
                    "nonce" to encryptResult.nonce,
                    "ciphertext" to encryptResult.ciphertext
                  )
                )
              }
            } catch (e: Exception) {
              // Classified, not hard-coded — in both directions. A keymaster
              // that defers the enrollment-invalidation check to doFinal throws
              // here (wrapped — see V1Scheme.isPermanentInvalidation), and that
              // key-loss must surface as key_invalidated, not as a retryable
              // encrypt_failed. Conversely, a keymaster operation pruned while
              // the prompt was up throws a bare KeyStoreException here, and
              // that transient loss must surface as the recoverable
              // decrypt_interrupted (see postAuthEncryptErrorCode), not as a
              // failure that reads like the key is broken.
              val code = postAuthEncryptErrorCode(e)
              mainHandler.post { result.error(code, postAuthErrorMessage(code, e), null) }
            } finally {
              plaintext.fill(0)
            }
          }
          // If the crypto looper is gone (plugin detached mid-auth) the runnable
          // never runs — wipe the plaintext and fail the Dart Future explicitly
          // so it cannot hang awaiting a result that will never arrive.
          if (!posted) {
            plaintext.fill(0)
            mainHandler.post {
              result.error("detached", "Plugin detached during authentication.", null)
            }
          }
        }
      )
    }
  }
}

internal fun KeystorePlugin.handleAuthenticateDecrypt(call: MethodCall, result: Result) {
  val version = call.versionArgument()
  val ciphertext = call.argument<ByteArray>("ciphertext")
  val nonce = call.argument<ByteArray>("nonce")
  val aad = call.argument<String>("aad")
  val alias = call.argument<String>("alias")
  val title = call.argument<String>("promptTitle") ?: "Authenticate"
  val subtitle = call.argument<String>("promptSubtitle") ?: "Confirm your identity"
  if (version == null || ciphertext == null || nonce == null || aad == null || alias == null) {
    result.error("bad_args", "Missing version, ciphertext, nonce, aad, or alias.", null)
    return
  }

  postCrypto(result) {
    val scheme = SchemeRegistry.schemeFor(version)
    if (scheme == null) {
      // Append-only, gapless registry + versionArgument()'s >= 1 floor: an
      // unknown version can only be a blob written by a NEWER release (app
      // rollback / sideloaded downgrade). Recoverable — upgrade the app; a
      // fatal decrypt_failed here would steer the caller toward purging a
      // healthy slot (see the identical branch in handleDecrypt).
      mainHandler.post {
        result.error(
          "unsupported_version",
          "Payload was written by a newer version of this library — upgrade the app; do not purge.",
          null
        )
      }
      return@postCrypto
    }
    val cipher: Cipher
    val authenticators: KeyAuthenticators
    try {
      cipher = scheme.initDecryptCipher(alias, nonce)
      // Authenticators derived from the key (see handleAuthenticateEncrypt).
      authenticators = scheme.keyAuthenticators(alias)
        ?: throw KeyAuthTypeUnknownException()
    } catch (e: Throwable) {
      // AND-1: Cipher.init on an AndroidKeyStore key issues keystore2 begin(),
      // which enforces UNLOCKED_DEVICE_REQUIRED at begin time (not just at
      // doFinal). Both authenticated profiles set unlockedDeviceRequired: true,
      // so a fetch fired while the screen is locked throws here — and without
      // this reclassification it collapses into the fatal decrypt_failed
      // (whose documented remedy purges an intact secret). Probe the lock state
      // and surface the recoverable device_locked, mirroring handleDecrypt.
      val code = if (isDeviceLocked()) "device_locked" else decryptErrorCode(e)
      mainHandler.post { result.error(code, e.message ?: e.toString(), null) }
      return@postCrypto
    }
    mainHandler.post {
      authenticate(
        cipher, title, subtitle, authenticators, result,
        onSuccess = { authenticatedCipher ->
          // doFinal off the main thread (see handleAuthenticateEncrypt).
          val posted = cryptoHandler.post {
            var decrypted: ByteArray? = null
            try {
              decrypted = scheme.decryptWithCipher(authenticatedCipher, ciphertext, aad)
              // Hand a copy to Flutter; the scheme's buffer is wiped below.
              val plaintextCopy = decrypted.copyOf()
              mainHandler.post {
                try {
                  result.success(plaintextCopy)
                } finally {
                  // success() serialises into the reply buffer synchronously,
                  // so the copy can be wiped the moment it returns — its heap
                  // lifetime shrinks from "until GC" to "until delivery".
                  plaintextCopy.fill(0)
                }
              }
            } catch (e: Exception) {
              // Classified (see the encrypt path): a doFinal-deferred
              // invalidation must map to key_invalidated, and a keymaster
              // operation pruned during the prompt must map to the recoverable
              // decrypt_interrupted — only a genuine GCM/tag failure (an
              // AEADBadTagException) stays in the fatal decrypt_failed bucket
              // (see postAuthDecryptErrorCode).
              val code = postAuthDecryptErrorCode(e)
              mainHandler.post { result.error(code, postAuthErrorMessage(code, e), null) }
            } finally {
              decrypted?.fill(0)
            }
          }
          // Crypto looper gone (plugin detached mid-auth): fail the Dart Future
          // explicitly rather than leaving it to hang (mirrors the encrypt path).
          if (!posted) {
            mainHandler.post {
              result.error("detached", "Plugin detached during authentication.", null)
            }
          }
        }
      )
    }
  }
}

/**
 * Shows a [BiometricPrompt] bound to [cipher] and routes the outcome.
 *
 * [onSuccess] runs on the main thread with the authenticated cipher. [onError]
 * is a finalizer invoked on every non-success terminal path (no activity,
 * authentication error/cancel, or a null authenticated cipher) so callers can
 * guarantee sensitive buffers are wiped regardless of how authentication ends.
 *
 * Exactly one terminal path fires: an internal claim guards against the platform
 * racing a late onAuthenticationError against a delivered success on some OEMs,
 * which would otherwise double-answer the Result or wipe a buffer mid-doFinal.
 *
 * LIFECYCLE CANCELLATION: the prompt's CancellationSignal is published to the
 * plugin's live set (pendingAuthCancellations) so activity destroy / rotation /
 * engine teardown force-cancels every in-flight prompt
 * (KeystorePlugin.cancelPendingAuthentication), each routing through
 * onAuthenticationError → claim() → onError (plaintext wipe). This closes the
 * window where an OEM that fails to fire ERROR_CANCELED on activity destruction
 * would otherwise leave the Future pending and an encrypt-path plaintext
 * unwiped until process death — for ALL concurrent prompts, not just the newest
 * (a single slot would let a second prompt evict the first from lifecycle
 * coverage). There is still no TIMEOUT, on purpose: a live prompt legitimately
 * waits on the user indefinitely, and a guessed deadline would cancel real
 * authentications — only a real lifecycle event triggers the cancellation.
 */
internal fun KeystorePlugin.authenticate(
  cipher: Cipher,
  title: String,
  subtitle: String,
  authenticators: KeyAuthenticators,
  result: Result,
  onSuccess: (Cipher) -> Unit,
  onError: () -> Unit = {}
) {
  // Single-delivery guard. MethodChannel.Result must be answered exactly once or
  // Flutter throws "Reply already submitted". The platform BiometricPrompt is
  // not contractually single-shot on every OEM: a late onAuthenticationError can
  // race a delivered success (e.g. the negative button cancelling just as auth
  // succeeds), and onError finalizers (plaintext wipe) must also run at most
  // once. claim() lets the first terminal path through and drops the rest.
  val delivered = AtomicBoolean(false)
  fun claim(): Boolean = delivered.compareAndSet(false, true)

  val currentActivity = activity
  if (currentActivity == null || currentActivity.isFinishing || currentActivity.isDestroyed) {
    if (claim()) {
      onError()
      result.error("auth_error", "No activity available for BiometricPrompt.", null)
    }
    return
  }

  val crypto = BiometricPrompt.CryptoObject(cipher)
  val executor = currentActivity.mainExecutor
  val cancellationSignal = CancellationSignal()
  // Publish the signal so a detach (activity destroy / rotation / engine
  // teardown) can force-cancel this prompt and trigger the onError plaintext
  // wipe — see KeystorePlugin.cancelPendingAuthentication. A SET of live
  // signals, so concurrent prompts each stay covered (a single slot would let
  // this prompt evict a previous one from lifecycle cancellation). Removal on
  // every terminal path is inherently ours-only: each prompt removes exactly
  // the signal instance it added (CancellationSignal uses identity equality),
  // so it can never strip a concurrent prompt's coverage — the same guarantee
  // the old single-slot identity check provided, now by construction.
  pendingAuthCancellations.add(cancellationSignal)
  val clearPending = { pendingAuthCancellations.remove(cancellationSignal) }
  val onErrorClearing = { clearPending(); onError() }
  val onSuccessClearing = { c: Cipher -> clearPending(); onSuccess(c) }

  // The prompt's allowed authenticators are DERIVED from the KEY's own KeyInfo
  // (see V1Scheme.keyAuthenticators), never from a caller flag — so they can
  // never mismatch the key. A key generated with enrollment-invalidation is
  // biometric-only (see Aes256GcmKeyGenerator); offering DEVICE_CREDENTIAL on
  // its prompt would produce an auth token that cannot authorize the cipher,
  // failing as an opaque encrypt/decrypt error after a "successful" PIN entry.
  // minSdk is 30 (R), so setAllowedAuthenticators is always available.
  val builder = BiometricPrompt.Builder(currentActivity)
    .setTitle(title)
    .setSubtitle(subtitle)
  when (authenticators) {
    KeyAuthenticators.BIOMETRIC_ONLY -> {
      builder.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
      // Without DEVICE_CREDENTIAL the platform prompt REQUIRES a negative
      // button. Tapping it cancels the signal, which routes the outcome through
      // onAuthenticationError(BIOMETRIC_ERROR_CANCELED) → auth_cancelled — a
      // single delivery path for the Result. The label is the platform's own
      // localized "Cancel" resource, never a hardcoded English literal — this
      // button gates access to the user's secrets and must be readable in the
      // device locale.
      builder.setNegativeButton(
        currentActivity.getString(android.R.string.cancel),
        executor
      ) { _, _ ->
        cancellationSignal.cancel()
      }
    }
    KeyAuthenticators.DEVICE_CREDENTIAL_ALLOWED -> {
      builder.setAllowedAuthenticators(
        BiometricManager.Authenticators.BIOMETRIC_STRONG or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL
      )
    }
  }
  val prompt = builder.build()

  try {
    promptAuthenticate(prompt, crypto, cancellationSignal, executor, result, ::claim, onSuccessClearing, onErrorClearing)
  } catch (e: Exception) {
    // authenticate() can throw on a dying activity/window (IllegalStateException,
    // BadTokenException on some OEMs) — uncaught it would crash the main thread
    // and leave the plaintext unwiped and the Dart Future hanging.
    if (claim()) {
      onErrorClearing()
      result.error("auth_error", e.message ?: e.toString(), null)
    }
  }
}

private fun promptAuthenticate(
  prompt: BiometricPrompt,
  crypto: BiometricPrompt.CryptoObject,
  cancellationSignal: CancellationSignal,
  executor: java.util.concurrent.Executor,
  result: Result,
  claim: () -> Boolean,
  onSuccess: (Cipher) -> Unit,
  onError: () -> Unit
) {
  prompt.authenticate(
    crypto,
    cancellationSignal,
    executor,
    object : BiometricPrompt.AuthenticationCallback() {
      override fun onAuthenticationSucceeded(authResult: BiometricPrompt.AuthenticationResult) {
        // claim() before touching the cipher/onSuccess: a late error must not be
        // able to wipe the plaintext (onError) out from under an in-flight
        // doFinal, nor double-answer the Result.
        if (!claim()) return
        val authedCipher = authResult.cryptoObject?.cipher
        if (authedCipher != null) {
          onSuccess(authedCipher)
        } else {
          onError()
          result.error("auth_failed", "Authenticated cipher is null.", null)
        }
      }

      override fun onAuthenticationFailed() {
        // A single recoverable mismatch (wrong finger); the prompt stays up and
        // will retry. NOT terminal — do not claim() or deliver a Result here.
        Log.w("KeystorePlugin", "Biometric attempt failed (retrying)")
      }

      override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
        // Terminal. Drop if success (or another error) already claimed delivery.
        if (!claim()) return
        onError()
        // Distinguish user-driven cancellation and biometric lockout from other
        // auth errors so the Dart layer sets AuthenticationFailedException's
        // cancelled / lockout flags accurately. All three remain recoverable
        // (retry, never purge) — only the flag differs.
        //
        // LOCKOUT / LOCKOUT_PERMANENT: too many failed biometric attempts. On a
        // biometric-only key (the authenticatedFatal profile) there is no
        // credential fallback, so the prompt is a dead-end until the user clears
        // the lockout by unlocking the device with the passcode. Surfacing the
        // distinct `biometry_lockout` lets the caller show that hint instead of a
        // bare "try again" — parity with Darwin's `biometry_lockout`.
        val code = when (errorCode) {
          BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED,
          BiometricPrompt.BIOMETRIC_ERROR_CANCELED,
          BIOMETRIC_ERROR_NEGATIVE_BUTTON -> "auth_cancelled"
          BiometricPrompt.BIOMETRIC_ERROR_LOCKOUT,
          BiometricPrompt.BIOMETRIC_ERROR_LOCKOUT_PERMANENT -> "biometry_lockout"
          else -> "auth_error"
        }
        result.error(code, "[$errorCode] $errString", null)
      }
    }
  )
}
