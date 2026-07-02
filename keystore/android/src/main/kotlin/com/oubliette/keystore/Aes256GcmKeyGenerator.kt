package com.oubliette.keystore

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory

object Aes256GcmKeyGenerator {
  private const val keyStoreType = "AndroidKeyStore"

  /**
   * Serializes the exists-check and the generation. AndroidKeyStore silently
   * REPLACES an existing entry when generating under an existing alias, so an
   * unguarded check-then-generate race (two Flutter engines in one process —
   * add-to-app, background isolates) could overwrite a live key and make every
   * blob encrypted under it permanently undecryptable. Process-wide because
   * this object is a singleton; cross-process generation remains the caller's
   * documented contract, as with the Dart-side locks.
   */
  private val generateLock = Any()

  fun generateKey(
    alias: String,
    unlockedDeviceRequired: Boolean,
    strongBox: Boolean,
    userAuthenticationRequired: Boolean,
    invalidatedByBiometricEnrollment: Boolean,
    requireHardwareBacking: Boolean
  ): Unit = synchronized(generateLock) {
    val keyStore = KeyStore.getInstance(keyStoreType)
    keyStore.load(null)
    if (keyStore.containsAlias(alias)) {
      throw KeyAlreadyExistsException()
    }
    val keyGenerator = KeyGenerator.getInstance(
      KeyProperties.KEY_ALGORITHM_AES,
      keyStoreType
    )
    val specBuilder = KeyGenParameterSpec.Builder(
      alias,
      KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    )
      .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
      .setKeySize(256)
      .setRandomizedEncryptionRequired(true)
      // setUnlockedDeviceRequired is honored on API 31+; on API 30 (the minSdk
      // floor) some OEM keymasters may silently no-op it. Unlike hardware
      // backing, KeyInfo exposes no reliable read-back to assert it took, so it
      // is NOT re-verified here — it is a secondary control layered on top of
      // setUserAuthenticationRequired, which remains the primary gate.
      .setUnlockedDeviceRequired(unlockedDeviceRequired)
    if (strongBox) {
      specBuilder.setIsStrongBoxBacked(true)
    }
    // minSdk is 30 (Android 11), so setUserAuthenticationParameters is always
    // available — no SDK gate, no silent downgrade of the authenticated
    // profiles. setUserAuthenticationRequired (API 23) and
    // setInvalidatedByBiometricEnrollment (API 24) are likewise unconditional.
    if (userAuthenticationRequired) {
      specBuilder.setUserAuthenticationRequired(true)
      specBuilder.setInvalidatedByBiometricEnrollment(invalidatedByBiometricEnrollment)
      // Keymaster only enforces enrollment-invalidation for keys that are
      // valid for biometric authentication ONLY. If AUTH_DEVICE_CREDENTIAL is
      // included, the key stays bound to the lock-screen SID and remains fully
      // usable via PIN/pattern/password after a new biometric is enrolled —
      // silently defeating the requested invalidation. So the requested
      // invalidation semantics decide the authenticator set: fatal profiles
      // get BIOMETRIC_STRONG only (no credential fallback — that fallback IS
      // the bypass), non-fatal authenticated profiles keep both.
      val authTypes = if (invalidatedByBiometricEnrollment) {
        KeyProperties.AUTH_BIOMETRIC_STRONG
      } else {
        KeyProperties.AUTH_DEVICE_CREDENTIAL or KeyProperties.AUTH_BIOMETRIC_STRONG
      }
      // timeout = 0 → per-operation auth: every cipher use needs a fresh
      // CryptoObject-bound prompt (no time-bound reuse window). Do NOT set a
      // nonzero timeout — that would let a cipher be reused without
      // re-authenticating inside the window, defeating the per-use guarantee.
      specBuilder.setUserAuthenticationParameters(0, authTypes)
    }
    keyGenerator.init(specBuilder.build())
    val key = keyGenerator.generateKey()
    // Opt-in strict mode. On a real device the Keystore key is hardware-backed
    // automatically, so this only changes behaviour on a software-only keystore
    // (emulators, some rooted/old devices): if requested, refuse rather than
    // silently keep a software key. Default is off so the library works in those
    // environments; wallet apps set requireHardwareBacking = true. (StrongBox
    // remains independently fail-closed via setIsStrongBoxBacked above.)
    // NOTE (gen-vs-use window): the hardware check runs AFTER generateKey, so
    // for one instant a not-yet-verified key exists under the alias. A
    // concurrent encrypt against that alias from another engine/isolate could
    // grab it before the fail-closed delete below, producing a blob whose key
    // is then removed. Such concurrent use of an alias still being generated
    // already violates the caller's serialization contract (the Dart layer
    // holds per-key locks and awaits ensure-key); documented here, not locked,
    // same as the cross-process caveat on [generateLock].
    if (requireHardwareBacking) assertHardwareBacked(alias, key)
  }

  /**
   * Fail-closed hardware check used only when the caller sets
   * `requireHardwareBacking`. If the freshly generated key is not hardware-backed
   * (TEE/StrongBox), delete it and refuse with [HardwareUnavailableException]
   * rather than keep a software key.
   */
  private fun assertHardwareBacked(alias: String, key: SecretKey) {
    if (!isHardwareBacked(key)) {
      deleteAlias(alias)
      // No alias in the message — hardware_unavailable passes through to app
      // logs unmapped (see the hygiene note in EncryptionScheme.kt).
      throw HardwareUnavailableException(
        "Generated key is not backed by secure hardware (software keystore or unverifiable); it was deleted."
      )
    }
  }

  /**
   * Whether [key] resides in secure hardware (TEE/StrongBox). **Fail-closed:**
   * any failure to determine this returns `false`, so an unverifiable key is
   * treated as not hardware-backed and refused (only when the caller opted into
   * `requireHardwareBacking`).
   */
  internal fun isHardwareBacked(key: SecretKey): Boolean = try {
    val factory = SecretKeyFactory.getInstance(key.algorithm, keyStoreType)
    val info = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
      // API 31+: the precise, non-deprecated check. Anything that is neither
      // SOFTWARE nor UNKNOWN counts as secure hardware (TEE, StrongBox, or a
      // secure level the framework can't further classify). Fail-closed.
      val level = info.securityLevel
      level != KeyProperties.SECURITY_LEVEL_SOFTWARE &&
        level != KeyProperties.SECURITY_LEVEL_UNKNOWN
    } else {
      // API 30: getSecurityLevel() does not exist; isInsideSecureHardware is the
      // correct call there (it is only deprecated from API 31).
      @Suppress("DEPRECATION")
      info.isInsideSecureHardware
    }
  } catch (e: Exception) {
    false
  }

  /** Best-effort removal of a key we are refusing to keep. */
  private fun deleteAlias(alias: String) {
    try {
      val keyStore = KeyStore.getInstance(keyStoreType)
      keyStore.load(null)
      if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias)
    } catch (_: Exception) {
      // Nothing more we can do; the key is unusable to the app regardless.
    }
  }
}
