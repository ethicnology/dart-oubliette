package com.oubliette.keystore

import android.app.Activity
import android.content.Context
import android.content.pm.PackageManager
import android.os.Handler
import android.os.HandlerThread
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import java.security.KeyStore
import javax.crypto.SecretKey

class KeystorePlugin : FlutterPlugin, MethodCallHandler, ActivityAware {

    private lateinit var channel: MethodChannel
    private lateinit var appContext: Context
    internal var activity: Activity? = null

    private val keyStoreType = "AndroidKeyStore"
    private val cryptoThread = HandlerThread("oubliette-crypto").also { it.start() }
    private val cryptoHandler = Handler(cryptoThread.looper)

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
        val alias = call.argument<String>("alias")
            ?: run {
                result.error("bad_args", "Missing alias.", null)
                return
            }
        cryptoHandler.post {
            try {
                result.success(getKey(alias) != null)
            } catch (e: Exception) {
                result.error("contains_alias_failed", e.message ?: e.toString(), null)
            }
        }
    }

    private fun handleGenerateKey(call: MethodCall, result: Result) {
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
        val invalidatedByBiometricEnrollment = call.argument<Boolean>("invalidatedByBiometricEnrollment") ?: true
        cryptoHandler.post {
            try {
                val scheme = SchemeRegistry.schemeFor(version)
                if (scheme == null) {
                    result.error("generate_key_failed", "Unsupported version.", null)
                    return@post
                }
                scheme.generateKey(
                    alias,
                    unlockedDeviceRequired,
                    useStrongBox,
                    userAuthenticationRequired,
                    invalidatedByBiometricEnrollment
                )
                result.success(null)
            } catch (e: IllegalStateException) {
                result.error("already_exists", e.message ?: e.toString(), null)
            } catch (e: Exception) {
                result.error("generate_key_failed", e.message ?: e.toString(), null)
            }
        }
    }

    private fun handleDeleteEntry(call: MethodCall, result: Result) {
        val alias = call.argument<String>("alias")
            ?: run {
                result.error("bad_args", "Missing alias.", null)
                return
            }
        cryptoHandler.post {
            try {
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
    }

    private fun handleEncrypt(call: MethodCall, result: Result) {
        val plaintext = call.argument<ByteArray>("plaintext")
        val aad = call.argument<String>("aad")
        val alias = call.argument<String>("alias")
        if (plaintext == null || aad == null || alias == null) {
            result.error("bad_args", "Missing plaintext, aad, or alias.", null)
            return
        }
        cryptoHandler.post {
            try {
                val scheme = SchemeRegistry.schemeFor(SchemeRegistry.CURRENT_VERSION)
                    ?: run {
                        result.error("encrypt_failed", "Unsupported version.", null)
                        return@post
                    }
                val encryptResult = scheme.encrypt(alias, plaintext, aad)
                result.success(
                    mapOf(
                        "version" to encryptResult.version,
                        "nonce" to encryptResult.nonce,
                        "ciphertext" to encryptResult.ciphertext
                    )
                )
            } catch (e: KeyNotFoundException) {
                result.error("key_not_found", e.message ?: e.toString(), null)
            } catch (e: KeyInvalidatedException) {
                result.error("key_invalidated", e.message ?: e.toString(), null)
            } catch (e: Exception) {
                result.error("encrypt_failed", e.message ?: e.toString(), null)
            } finally {
                plaintext.fill(0)
            }
        }
    }

    private fun handleDecrypt(call: MethodCall, result: Result) {
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
        cryptoHandler.post {
            try {
                val scheme = SchemeRegistry.schemeFor(version)
                if (scheme == null) {
                    result.error("decrypt_failed", "Unsupported version.", null)
                    return@post
                }
                val plaintext = scheme.decrypt(alias, ciphertext, nonce, aad)
                result.success(plaintext.copyOf())
                plaintext.fill(0)
            } catch (e: KeyNotFoundException) {
                result.error("key_not_found", e.message ?: e.toString(), null)
            } catch (e: KeyInvalidatedException) {
                result.error("key_invalidated", e.message ?: e.toString(), null)
            } catch (e: Exception) {
                result.error("decrypt_failed", e.message ?: e.toString(), null)
            }
        }
    }

    private fun handleIsStrongBoxAvailable(result: Result) {
        cryptoHandler.post {
            try {
                val available = appContext.packageManager
                    .hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
                result.success(available)
            } catch (e: Exception) {
                result.error("is_strongbox_available_failed", e.message ?: e.toString(), null)
            }
        }
    }

    private fun getKey(alias: String): SecretKey? {
        val keyStore = KeyStore.getInstance(keyStoreType)
        keyStore.load(null)
        return keyStore.getKey(alias, null) as? SecretKey
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
        SchemeRegistry.shutdownAll()
        cryptoThread.quitSafely()
    }
}
