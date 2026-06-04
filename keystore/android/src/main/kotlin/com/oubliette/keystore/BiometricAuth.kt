package com.oubliette.keystore

import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.CancellationSignal
import android.util.Log
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel.Result
import javax.crypto.Cipher

/** Maps a crypto exception to the stable error code the Dart layer expects. */
private fun encryptErrorCode(t: Throwable): String = when (t) {
  is KeyNotFoundException -> "key_not_found"
  is KeyInvalidatedException -> "key_invalidated"
  else -> "encrypt_failed"
}

private fun decryptErrorCode(t: Throwable): String = when (t) {
  is KeyNotFoundException -> "key_not_found"
  is KeyInvalidatedException -> "key_invalidated"
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
  cryptoHandler.post {
    val scheme = SchemeRegistry.schemeFor(SchemeRegistry.CURRENT_VERSION)
    if (scheme == null) {
      plaintext.fill(0)
      mainHandler.post { result.error("encrypt_failed", "Unsupported version.", null) }
      return@post
    }
    val cipher = try {
      scheme.initEncryptCipher(alias)
    } catch (e: Throwable) {
      plaintext.fill(0)
      mainHandler.post { result.error(encryptErrorCode(e), e.message ?: e.toString(), null) }
      return@post
    }
    mainHandler.post {
      authenticate(
        cipher, title, subtitle, result,
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
              mainHandler.post { result.error("encrypt_failed", e.message ?: e.toString(), null) }
            } finally {
              plaintext.fill(0)
            }
          }
          // If the crypto looper is gone (plugin detached mid-auth) the runnable
          // never runs — wipe here so plaintext is never left in memory.
          if (!posted) plaintext.fill(0)
        }
      )
    }
  }
}

internal fun KeystorePlugin.handleAuthenticateDecrypt(call: MethodCall, result: Result) {
  val versionRaw = call.argument<Number>("version") ?: call.argument<Int>("version")
  val version = versionRaw?.toInt()
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

  cryptoHandler.post {
    val scheme = SchemeRegistry.schemeFor(version)
    if (scheme == null) {
      mainHandler.post { result.error("decrypt_failed", "Unsupported version.", null) }
      return@post
    }
    val cipher = try {
      scheme.initDecryptCipher(alias, nonce)
    } catch (e: Throwable) {
      mainHandler.post { result.error(decryptErrorCode(e), e.message ?: e.toString(), null) }
      return@post
    }
    mainHandler.post {
      authenticate(
        cipher, title, subtitle, result,
        onSuccess = { authenticatedCipher ->
          // doFinal off the main thread (see handleAuthenticateEncrypt).
          cryptoHandler.post {
            var decrypted: ByteArray? = null
            try {
              decrypted = scheme.decryptWithCipher(authenticatedCipher, ciphertext, aad)
              // Hand a copy to Flutter; the scheme's buffer is wiped below.
              val plaintextCopy = decrypted.copyOf()
              mainHandler.post { result.success(plaintextCopy) }
            } catch (e: Exception) {
              mainHandler.post { result.error("decrypt_failed", e.message ?: e.toString(), null) }
            } finally {
              decrypted?.fill(0)
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
 */
internal fun KeystorePlugin.authenticate(
  cipher: Cipher,
  title: String,
  subtitle: String,
  result: Result,
  onSuccess: (Cipher) -> Unit,
  onError: () -> Unit = {}
) {
  val currentActivity = activity
  if (currentActivity == null) {
    onError()
    result.error("auth_error", "No activity available for BiometricPrompt.", null)
    return
  }

  val crypto = BiometricPrompt.CryptoObject(cipher)
  val executor = currentActivity.mainExecutor

  // minSdk is 30 (R), so setAllowedAuthenticators is always available.
  val prompt = BiometricPrompt.Builder(currentActivity)
    .setTitle(title)
    .setSubtitle(subtitle)
    .setAllowedAuthenticators(
      BiometricManager.Authenticators.BIOMETRIC_STRONG or
          BiometricManager.Authenticators.DEVICE_CREDENTIAL
    )
    .build()
  val cancellationSignal = CancellationSignal()

  prompt.authenticate(
    crypto,
    cancellationSignal,
    executor,
    object : BiometricPrompt.AuthenticationCallback() {
      override fun onAuthenticationSucceeded(authResult: BiometricPrompt.AuthenticationResult) {
        val authedCipher = authResult.cryptoObject?.cipher
        if (authedCipher != null) {
          onSuccess(authedCipher)
        } else {
          onError()
          result.error("auth_failed", "Authenticated cipher is null.", null)
        }
      }

      override fun onAuthenticationFailed() {
        Log.w("KeystorePlugin", "Biometric attempt failed (retrying)")
      }

      override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
        onError()
        result.error("auth_error", "[$errorCode] $errString", null)
      }
    }
  )
}
