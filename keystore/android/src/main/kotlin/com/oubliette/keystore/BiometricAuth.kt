package com.oubliette.keystore

import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.util.Log
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel.Result
import javax.crypto.Cipher

internal fun KeystorePlugin.handleAuthenticateEncrypt(call: MethodCall, result: Result) {
  try {
    val plaintext = call.argument<ByteArray>("plaintext")
    val aad = call.argument<String>("aad")
    val alias = call.argument<String>("alias")
    val title = call.argument<String>("promptTitle") ?: "Authenticate"
    val subtitle = call.argument<String>("promptSubtitle") ?: "Confirm your identity"
    if (plaintext == null || aad == null || alias == null) {
      result.error("bad_args", "Missing plaintext, aad, or alias.", null)
      return
    }
    val scheme = SchemeRegistry.schemeFor(SchemeRegistry.CURRENT_VERSION)
      ?: run {
        result.error("encrypt_failed", "Unsupported version.", null)
        return
      }
    val cipher = scheme.initEncryptCipher(alias)
    authenticate(cipher, title, subtitle, result,
      onSuccess = { authenticatedCipher ->
        try {
          val encryptResult = scheme.encryptWithCipher(authenticatedCipher, plaintext, aad)
          plaintext.fill(0)
          result.success(
            mapOf(
              "version" to encryptResult.version,
              "nonce" to encryptResult.nonce,
              "ciphertext" to encryptResult.ciphertext
            )
          )
        } catch (e: Exception) {
          plaintext.fill(0)
          result.error("encrypt_failed", e.message ?: e.toString(), null)
        }
      }
    )
  } catch (e: KeyNotFoundException) {
    result.error("key_not_found", e.message ?: e.toString(), null)
  } catch (e: KeyInvalidatedException) {
    result.error("key_invalidated", e.message ?: e.toString(), null)
  } catch (e: Exception) {
    result.error("encrypt_failed", e.message ?: e.toString(), null)
  }
}

internal fun KeystorePlugin.handleAuthenticateDecrypt(call: MethodCall, result: Result) {
  try {
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
    val scheme = SchemeRegistry.schemeFor(version)
      ?: run {
        result.error("decrypt_failed", "Unsupported version.", null)
        return
      }
    val cipher = scheme.initDecryptCipher(alias, nonce)
    authenticate(cipher, title, subtitle, result,
      onSuccess = { authenticatedCipher ->
        try {
          val decrypted = scheme.decryptWithCipher(authenticatedCipher, ciphertext, aad)
          result.success(decrypted.copyOf())
          decrypted.fill(0)
        } catch (e: Exception) {
          result.error("decrypt_failed", e.message ?: e.toString(), null)
        }
      }
    )
  } catch (e: KeyNotFoundException) {
    result.error("key_not_found", e.message ?: e.toString(), null)
  } catch (e: KeyInvalidatedException) {
    result.error("key_invalidated", e.message ?: e.toString(), null)
  } catch (e: Exception) {
    result.error("decrypt_failed", e.message ?: e.toString(), null)
  }
}

internal fun KeystorePlugin.authenticate(
  cipher: Cipher,
  title: String,
  subtitle: String,
  result: Result,
  onSuccess: (Cipher) -> Unit
) {
  val currentActivity = activity
  if (currentActivity == null) {
    result.error("auth_error", "No activity available for BiometricPrompt.", null)
    return
  }

  val crypto = BiometricPrompt.CryptoObject(cipher)
  val executor = currentActivity.mainExecutor

  val promptBuilder = BiometricPrompt.Builder(currentActivity)
    .setTitle(title)
    .setSubtitle(subtitle)
  if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
    promptBuilder.setAllowedAuthenticators(
      BiometricManager.Authenticators.BIOMETRIC_STRONG or
          BiometricManager.Authenticators.DEVICE_CREDENTIAL
    )
  }

  val prompt = promptBuilder.build()
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
          result.error("auth_failed", "Authenticated cipher is null.", null)
        }
      }

      override fun onAuthenticationFailed() {
        Log.w("KeystorePlugin", "Biometric attempt failed (retrying)")
      }

      override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
        result.error("auth_error", "[$errorCode] $errString", null)
      }
    }
  )
}
