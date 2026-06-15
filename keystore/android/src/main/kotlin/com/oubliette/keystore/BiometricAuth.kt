package com.oubliette.keystore

import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.CancellationSignal
import android.util.Log
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel.Result
import java.util.concurrent.atomic.AtomicBoolean
import javax.crypto.Cipher

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
              // Classified, not hard-coded: keymasters that defer the
              // enrollment-invalidation check to doFinal throw here (wrapped —
              // see V1Scheme.isPermanentInvalidation), and that key-loss must
              // surface as key_invalidated, not as a retryable encrypt_failed.
              mainHandler.post { result.error(encryptErrorCode(e), e.message ?: e.toString(), null) }
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
      mainHandler.post { result.error("decrypt_failed", "Unsupported version.", null) }
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
      mainHandler.post { result.error(decryptErrorCode(e), e.message ?: e.toString(), null) }
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
              // invalidation must map to key_invalidated, not decrypt_failed.
              mainHandler.post { result.error(decryptErrorCode(e), e.message ?: e.toString(), null) }
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
 * RESIDUAL (platform contract, unguardable here): if an OEM prompt never invokes
 * ANY callback — the documented behaviour is ERROR_CANCELED on activity
 * destruction/rotation — the Dart Future stays pending and an encrypt-path
 * plaintext stays unwiped until process death. There is no timeout here on
 * purpose: a prompt legitimately waits on the user indefinitely, and a guessed
 * deadline would cancel real authentications.
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
      // single delivery path for the Result.
      builder.setNegativeButton("Cancel", executor) { _, _ ->
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
    promptAuthenticate(prompt, crypto, cancellationSignal, executor, result, ::claim, onSuccess, onError)
  } catch (e: Exception) {
    // authenticate() can throw on a dying activity/window (IllegalStateException,
    // BadTokenException on some OEMs) — uncaught it would crash the main thread
    // and leave the plaintext unwiped and the Dart Future hanging.
    if (claim()) {
      onError()
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
        // Distinguish user-driven cancellation from other auth errors so the
        // Dart layer sets AuthenticationFailedException.cancelled accurately.
        // Both remain recoverable (retry, never purge) — only the flag differs.
        val code = when (errorCode) {
          BiometricPrompt.BIOMETRIC_ERROR_USER_CANCELED,
          BiometricPrompt.BIOMETRIC_ERROR_CANCELED,
          13 -> "auth_cancelled" // 13 = BIOMETRIC_ERROR_NEGATIVE_BUTTON. The
          // platform android.hardware.biometrics.BiometricPrompt does NOT expose
          // it as a resolvable named constant at this compileSdk (verified: the
          // build fails on the named ref; it lives in androidx.biometric, which
          // we don't use here). The negative button is the user tapping
          // "Cancel", so it is a cancellation.
          else -> "auth_error"
        }
        result.error(code, "[$errorCode] $errString", null)
      }
    }
  )
}
