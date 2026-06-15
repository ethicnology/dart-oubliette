package com.oubliette.keystore

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Handler
import android.os.HandlerThread
import android.os.Looper
import android.security.keystore.StrongBoxUnavailableException
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import java.security.KeyStore

/**
 * Reads the scheme-version argument without silent Long→Int truncation: a Dart
 * int above 2^31−1 arrives over the channel as a Long, and a bare `toInt()`
 * would wrap it into a small — wrong — scheme version instead of rejecting it.
 * Returns null when the argument is absent or out of the valid range.
 */
internal fun MethodCall.versionArgument(): Int? {
    val raw = argument<Number>("version")?.toLong() ?: return null
    return if (raw in 1L..Int.MAX_VALUE.toLong()) raw.toInt() else null
}

class KeystorePlugin : FlutterPlugin, MethodCallHandler, ActivityAware {

    private lateinit var channel: MethodChannel
    private lateinit var appContext: Context
    internal var activity: Activity? = null

    private val keyStoreType = "AndroidKeyStore"

    /**
     * Background thread for keymaster Binder calls (Cipher.init, Cipher.doFinal,
     * key gen). Created in [onAttachedToEngine] and torn down in
     * [onDetachedFromEngine], then recreated on a subsequent attach — so a
     * re-attached plugin instance never posts to a dead looper (which would
     * silently drop the work and hang the awaiting Dart Future).
     */
    private lateinit var cryptoThread: HandlerThread
    internal lateinit var cryptoHandler: Handler

    /** Posts MethodChannel.Result callbacks back onto the platform thread. */
    internal val mainHandler = Handler(Looper.getMainLooper())

    /**
     * Posts [block] to the crypto thread. [block] MUST deliver its result via
     * [mainHandler] (MethodChannel.Result is @UiThread). If the looper is gone
     * (plugin detached mid-call) the runnable never runs — [onDead] is invoked
     * (e.g. to wipe a secret) and the Dart Future is failed explicitly so it
     * cannot hang awaiting a result that will never arrive.
     */
    internal fun postCrypto(result: Result, onDead: () -> Unit = {}, block: () -> Unit) {
        if (!cryptoHandler.post(block)) {
            onDead()
            mainHandler.post { result.error("detached", "Plugin detached during operation.", null) }
        }
    }

    override fun onAttachedToEngine(flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
        channel = MethodChannel(flutterPluginBinding.binaryMessenger, "keystore")
        appContext = flutterPluginBinding.applicationContext
        cryptoThread = HandlerThread("oubliette-crypto").also { it.start() }
        cryptoHandler = Handler(cryptoThread.looper)
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
        postCrypto(result) {
            try {
                // containsAlias, not getKey(): getKey actually loads the entry
                // and can throw UnrecoverableKeyException for a half-invalidated
                // key on some devices — turning "does it exist?" into an error.
                // An invalidated-but-present key must report true so the ensure-
                // key path doesn't try to regenerate it; the invalidation then
                // surfaces properly as key_invalidated at encrypt/decrypt.
                val keyStore = KeyStore.getInstance(keyStoreType)
                keyStore.load(null)
                val exists = keyStore.containsAlias(alias)
                mainHandler.post { result.success(exists) }
            } catch (e: Exception) {
                mainHandler.post { result.error("contains_alias_failed", e.message ?: e.toString(), null) }
            }
        }
    }

    private fun handleGenerateKey(call: MethodCall, result: Result) {
        val version = if (!call.hasArgument("version")) {
            SchemeRegistry.CURRENT_VERSION
        } else {
            call.versionArgument()
                ?: run {
                    result.error("bad_args", "Invalid version.", null)
                    return
                }
        }
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
        val strongBox = call.argument<Boolean>("strongBox")
            ?: run {
                result.error("bad_args", "Missing strongBox.", null)
                return
            }
        // Required, no default: an auth flag silently defaulting to "no auth"
        // would be a fail-open default. Every security-critical generation flag
        // is chosen explicitly by the caller (the Dart facade always sends it),
        // matching strongBox / unlockedDeviceRequired / invalidatedByBiometricEnrollment.
        val userAuthenticationRequired = call.argument<Boolean>("userAuthenticationRequired")
            ?: run {
                result.error("bad_args", "Missing userAuthenticationRequired.", null)
                return
            }
        val invalidatedByBiometricEnrollment = call.argument<Boolean>("invalidatedByBiometricEnrollment")
            ?: run {
                result.error("bad_args", "Missing invalidatedByBiometricEnrollment.", null)
                return
            }
        // Opt-in hardware backing, required (no default): refusing a
        // non-hardware-backed key is fail-closed, so absence must error rather
        // than silently fall open to "don't require hardware". Emulator/CI
        // leniency comes from the caller passing false explicitly, never from a
        // hidden default. Wallets pass true.
        val requireHardwareBacking = call.argument<Boolean>("requireHardwareBacking")
            ?: run {
                result.error("bad_args", "Missing requireHardwareBacking.", null)
                return
            }
        postCrypto(result) {
            try {
                // Fail closed: requesting StrongBox must yield StrongBox or a
                // clear error — never a silent TEE downgrade. The feature flag
                // is a pre-flight check; key generation below is the source of
                // truth and may still throw StrongBoxUnavailableException.
                if (strongBox &&
                    !appContext.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) {
                    mainHandler.post {
                        result.error(
                            "strongbox_unavailable",
                            "StrongBox requested but FEATURE_STRONGBOX_KEYSTORE is absent on this device.",
                            null
                        )
                    }
                    return@postCrypto
                }
                val scheme = SchemeRegistry.schemeFor(version)
                if (scheme == null) {
                    mainHandler.post { result.error("generate_key_failed", "Unsupported version.", null) }
                    return@postCrypto
                }
                scheme.generateKey(
                    alias,
                    unlockedDeviceRequired,
                    strongBox,
                    userAuthenticationRequired,
                    invalidatedByBiometricEnrollment,
                    requireHardwareBacking
                )
                mainHandler.post { result.success(null) }
            } catch (e: StrongBoxUnavailableException) {
                mainHandler.post { result.error("strongbox_unavailable", e.message ?: e.toString(), null) }
            } catch (e: HardwareUnavailableException) {
                mainHandler.post { result.error("hardware_unavailable", e.message ?: e.toString(), null) }
            } catch (e: KeyAlreadyExistsException) {
                // Exactly the duplicate-alias signal — never a broader
                // IllegalStateException, which would let an unrelated keystore
                // failure masquerade as "already exists" (treated as success
                // by the Dart ensure-key path).
                mainHandler.post { result.error("already_exists", e.message ?: e.toString(), null) }
            } catch (e: Exception) {
                mainHandler.post { result.error("generate_key_failed", e.message ?: e.toString(), null) }
            }
        }
    }

    private fun handleDeleteEntry(call: MethodCall, result: Result) {
        val alias = call.argument<String>("alias")
            ?: run {
                result.error("bad_args", "Missing alias.", null)
                return
            }
        postCrypto(result) {
            try {
                val keyStore = KeyStore.getInstance(keyStoreType)
                keyStore.load(null)
                if (keyStore.containsAlias(alias)) {
                    keyStore.deleteEntry(alias)
                }
                mainHandler.post { result.success(null) }
            } catch (e: Exception) {
                mainHandler.post { result.error("delete_entry_failed", e.message ?: e.toString(), null) }
            }
        }
    }

    private fun handleEncrypt(call: MethodCall, result: Result) {
        val plaintext = call.argument<ByteArray>("plaintext")
        val aad = call.argument<String>("aad")
        val alias = call.argument<String>("alias")
        if (plaintext == null || aad == null || alias == null) {
            plaintext?.fill(0)
            result.error("bad_args", "Missing plaintext, aad, or alias.", null)
            return
        }
        postCrypto(result, onDead = { plaintext.fill(0) }) {
            try {
                val scheme = SchemeRegistry.schemeFor(SchemeRegistry.CURRENT_VERSION)
                    ?: run {
                        mainHandler.post { result.error("encrypt_failed", "Unsupported version.", null) }
                        return@postCrypto
                    }
                val encryptResult = scheme.encrypt(alias, plaintext, aad)
                mainHandler.post {
                    result.success(
                        mapOf(
                            "version" to encryptResult.version,
                            "nonce" to encryptResult.nonce,
                            "ciphertext" to encryptResult.ciphertext
                        )
                    )
                }
            } catch (e: KeyNotFoundException) {
                mainHandler.post { result.error("key_not_found", e.message ?: e.toString(), null) }
            } catch (e: KeyInvalidatedException) {
                mainHandler.post { result.error("key_invalidated", e.message ?: e.toString(), null) }
            } catch (e: Exception) {
                mainHandler.post { result.error("encrypt_failed", e.message ?: e.toString(), null) }
            } finally {
                plaintext.fill(0)
            }
        }
    }

    private fun handleDecrypt(call: MethodCall, result: Result) {
        val version = call.versionArgument()
        val ciphertext = call.argument<ByteArray>("ciphertext")
        val nonce = call.argument<ByteArray>("nonce")
        val aad = call.argument<String>("aad")
        val alias = call.argument<String>("alias")
        if (version == null || ciphertext == null || nonce == null || aad == null || alias == null) {
            result.error("bad_args", "Missing version, ciphertext, nonce, aad, or alias.", null)
            return
        }
        postCrypto(result) {
            var plaintext: ByteArray? = null
            try {
                val scheme = SchemeRegistry.schemeFor(version)
                if (scheme == null) {
                    mainHandler.post { result.error("decrypt_failed", "Unsupported version.", null) }
                    return@postCrypto
                }
                plaintext = scheme.decrypt(alias, ciphertext, nonce, aad)
                val out = plaintext.copyOf()
                mainHandler.post {
                    try {
                        result.success(out)
                    } finally {
                        // success() serialises into the reply buffer synchronously,
                        // so the copy is wiped the moment delivery returns. The
                        // codec's own transfer buffer (and the Dart-side bytes) are
                        // outside our reach — see SECURITY.md on plaintext lifetime.
                        out.fill(0)
                    }
                }
            } catch (e: KeyNotFoundException) {
                mainHandler.post { result.error("key_not_found", e.message ?: e.toString(), null) }
            } catch (e: KeyInvalidatedException) {
                mainHandler.post { result.error("key_invalidated", e.message ?: e.toString(), null) }
            } catch (e: Exception) {
                // An UnlockedDeviceRequired key (the onlyUnlocked profile) cannot
                // DECRYPT while the screen is locked — Cipher.init throws a
                // non-invalidation exception that would otherwise collapse into the
                // FATAL `decrypt_failed`, steering a caller toward an irreversible
                // purge(). That condition is transient and recoverable (retry after
                // unlock), exactly as AndroidSecretAccess.unlockedDeviceRequired
                // documents. Probe the lock state and surface the distinct,
                // recoverable `device_locked` (mapped to AuthenticationFailedException
                // in the Dart layer, mirroring Darwin's `interaction_not_allowed`).
                // Only the lock-state branch is reclassified; a genuine decrypt
                // failure on an unlocked device stays `decrypt_failed`.
                val code = if (isDeviceLocked()) "device_locked" else "decrypt_failed"
                mainHandler.post { result.error(code, e.message ?: e.toString(), null) }
            } finally {
                plaintext?.fill(0)
            }
        }
    }

    private fun handleIsStrongBoxAvailable(result: Result) {
        postCrypto(result) {
            try {
                val available = appContext.packageManager
                    .hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
                mainHandler.post { result.success(available) }
            } catch (e: Exception) {
                mainHandler.post { result.error("is_strongbox_available_failed", e.message ?: e.toString(), null) }
            }
        }
    }

    /**
     * Whether the device is currently locked behind a secure lock screen. Used to
     * tell a transient locked-device decrypt failure (recoverable — retry after
     * unlock) apart from a genuine ciphertext/key decrypt failure (fatal). A
     * false positive only over-classifies as recoverable (the safe direction: a
     * caller retries instead of purging readable data); never the reverse.
     */
    private fun isDeviceLocked(): Boolean {
        val keyguard = appContext.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
        return keyguard?.isDeviceLocked == true
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
        // Only the per-instance HandlerThread is torn down — it is recreated on
        // the next attach. The schemes are stateless and process-static, so
        // there is nothing else to shut down (and nothing to leave dead).
        if (::cryptoThread.isInitialized) cryptoThread.quitSafely()
    }
}
