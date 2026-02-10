package com.example.keystore

import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.SecretKey

class KeystorePlugin : FlutterPlugin, MethodCallHandler, ActivityAware {

  private lateinit var channel: MethodChannel
  private lateinit var appContext: Context
  private var activity: Activity? = null

  private val keyStoreType = "AndroidKeyStore"

  override fun onAttachedToEngine(flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
    channel = MethodChannel(flutterPluginBinding.binaryMessenger, "keystore")
    appContext = flutterPluginBinding.applicationContext
    channel.setMethodCallHandler(this)
  }

  override fun onAttachedToActivity(binding: ActivityPluginBinding) {
    activity = binding.activity
  }

  override fun onDetachedFromActivityForConfigChanges() {
    activity = null
  }

  override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
    activity = binding.activity
  }

  override fun onDetachedFromActivity() {
    activity = null
  }

  override fun onMethodCall(call: MethodCall, result: Result) {
    when (call.method) {
      "containsAlias" -> handleContainsAlias(call, result)
      "generateKey" -> handleGenerateKey(call, result)
      "deleteEntry" -> handleDeleteEntry(call, result)
      "encrypt" -> handleEncrypt(call, result)
      "decrypt" -> handleDecrypt(call, result)
      "authenticateEncrypt" -> handleAuthenticateEncrypt(call, result)
      "authenticateDecrypt" -> handleAuthenticateDecrypt(call, result)
      "isStrongBoxAvailable" -> handleIsStrongBoxAvailable(result)
      else -> result.notImplemented()
    }
  }

  private fun handleContainsAlias(call: MethodCall, result: Result) {
    try {
      val alias = call.argument<String>("alias")
        ?: run {
          result.error("bad_args", "Missing alias.", null)
          return
        }
      result.success(getKey(alias) != null)
    } catch (e: Exception) {
      result.error("contains_alias_failed", e.message ?: e.toString(), null)
    }
  }

  private fun handleGenerateKey(call: MethodCall, result: Result) {
    try {
      val versionRaw = call.argument<Number>("version") ?: call.argument<Int>("version")
      val version = versionRaw?.toInt() ?: SchemeRegistry.CURRENT_VERSION
      val alias = call.argument<String>("alias")
        ?: run {
          result.error("bad_args", "Missing alias.", null)
          return
        }
      val unlockedDeviceRequired = call.argument<Boolean>("unlockedDeviceRequired")
        ?: run {
          result.error("bad_args", "Missing unlockedDeviceRequired.", null)
          return
        }
      val wantsStrongBox = call.argument<Boolean>("strongBox") ?: true
      val useStrongBox = wantsStrongBox &&
          appContext.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
      val userAuthenticationRequired = call.argument<Boolean>("userAuthenticationRequired") ?: false
      val scheme = SchemeRegistry.schemeFor(version)
      if (scheme == null) {
        result.error("generate_key_failed", "Unsupported version.", null)
        return
      }
      scheme.generateKey(alias, unlockedDeviceRequired, useStrongBox, userAuthenticationRequired)
      result.success(null)
    } catch (e: Exception) {
      result.error("generate_key_failed", e.message ?: e.toString(), null)
    }
  }

  private fun handleDeleteEntry(call: MethodCall, result: Result) {
    try {
      val alias = call.argument<String>("alias")
        ?: run {
          result.error("bad_args", "Missing alias.", null)
          return
        }
      val keyStore = KeyStore.getInstance(keyStoreType)
      keyStore.load(null)
      if (keyStore.containsAlias(alias)) {
        keyStore.deleteEntry(alias)
      }
      result.success(null)
    } catch (e: Exception) {
      result.error("delete_entry_failed", e.message ?: e.toString(), null)
    }
  }

  private fun handleEncrypt(call: MethodCall, result: Result) {
    try {
      val plaintext = call.argument<ByteArray>("plaintext")
      val aad = call.argument<String>("aad")
      val alias = call.argument<String>("alias")
      if (plaintext == null || aad == null || alias == null) {
        result.error("bad_args", "Missing plaintext, aad, or alias.", null)
        return
      }
      val scheme = SchemeRegistry.schemeFor(SchemeRegistry.CURRENT_VERSION)
        ?: run {
          result.error("encrypt_failed", "Unsupported version.", null)
          return
        }
      val encryptResult = scheme.encrypt(alias, plaintext, aad)
      result.success(
        mapOf(
          "version" to encryptResult.version,
          "nonce" to encryptResult.nonce,
          "ciphertext" to encryptResult.ciphertext
        )
      )
    } catch (e: Exception) {
      result.error("encrypt_failed", e.message ?: e.toString(), null)
    }
  }

  private fun handleDecrypt(call: MethodCall, result: Result) {
    try {
      val versionRaw = call.argument<Number>("version") ?: call.argument<Int>("version")
      val version = versionRaw?.toInt()
      val ciphertext = call.argument<ByteArray>("ciphertext")
      val nonce = call.argument<ByteArray>("nonce")
      val aad = call.argument<String>("aad")
      val alias = call.argument<String>("alias")
      if (version == null || ciphertext == null || nonce == null || aad == null || alias == null) {
        result.error("bad_args", "Missing version, ciphertext, nonce, aad, or alias.", null)
        return
      }
      val scheme = SchemeRegistry.schemeFor(version)
      if (scheme == null) {
        result.error("decrypt_failed", "Unsupported version.", null)
        return
      }
      val plaintext = scheme.decrypt(alias, ciphertext, nonce, aad)
      result.success(plaintext)
    } catch (e: Exception) {
      result.error("decrypt_failed", e.message ?: e.toString(), null)
    }
  }

  private fun handleIsStrongBoxAvailable(result: Result) {
    try {
      val available = appContext.packageManager
        .hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
      result.success(available)
    } catch (e: Exception) {
      result.error("is_strongbox_available_failed", e.message ?: e.toString(), null)
    }
  }

  private fun getKey(alias: String): SecretKey? {
    val keyStore = KeyStore.getInstance(keyStoreType)
    keyStore.load(null)
    return keyStore.getKey(alias, null) as? SecretKey
  }

  override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
    channel.setMethodCallHandler(null)
  }

 private fun handleAuthenticateEncrypt(call: MethodCall, result: Result) {
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
      val scheme = SchemeRegistry.schemeFor(SchemeRegistry.CURRENT_VERSION) as? V1Scheme
        ?: run {
          result.error("encrypt_failed", "Unsupported version.", null)
          return
        }
      val cipher = scheme.initEncryptCipher(alias)
      authenticate(cipher, title, subtitle, result,
        onSuccess = { authenticatedCipher ->
          try {
            val encryptResult = scheme.encryptWithCipher(authenticatedCipher, plaintext, aad)
            result.success(
              mapOf(
                "version" to encryptResult.version,
                "nonce" to encryptResult.nonce,
                "ciphertext" to encryptResult.ciphertext
              )
            )
          } catch (e: Exception) {
            result.error("encrypt_failed", e.message ?: e.toString(), null)
          }
        }
      )
    } catch (e: Exception) {
      result.error("encrypt_failed", e.message ?: e.toString(), null)
    }
  }

  private fun handleAuthenticateDecrypt(call: MethodCall, result: Result) {
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
      val scheme = SchemeRegistry.schemeFor(version) as? V1Scheme
        ?: run {
          result.error("decrypt_failed", "Unsupported version.", null)
          return
        }
      val cipher = scheme.initDecryptCipher(alias, nonce)
      authenticate(cipher, title, subtitle, result,
        onSuccess = { authenticatedCipher ->
          try {
            val decrypted = scheme.decryptWithCipher(authenticatedCipher, ciphertext, aad)
            result.success(decrypted)
          } catch (e: Exception) {
            result.error("decrypt_failed", e.message ?: e.toString(), null)
          }
        }
      )
    } catch (e: Exception) {
      result.error("decrypt_failed", e.message ?: e.toString(), null)
    }
  }

  private fun authenticate(
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
        }

        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
          result.error("auth_error", "[$errorCode] $errString", null)
        }
      }
    )
  }
}
