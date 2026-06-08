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

  fun generateKey(
    alias: String,
    unlockedDeviceRequired: Boolean,
    strongBox: Boolean,
    userAuthenticationRequired: Boolean,
    invalidatedByBiometricEnrollment: Boolean
  ) {
    val keyStore = KeyStore.getInstance(keyStoreType)
    keyStore.load(null)
    if (keyStore.containsAlias(alias)) {
      throw IllegalStateException("A key already exists for alias \"$alias\". Call deleteEntry() first.")
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
      specBuilder.setUserAuthenticationParameters(
        0,
        KeyProperties.AUTH_DEVICE_CREDENTIAL or KeyProperties.AUTH_BIOMETRIC_STRONG
      )
    }
    keyGenerator.init(specBuilder.build())
    val key = keyGenerator.generateKey()
    assertHardwareBacked(alias, key)
  }

  /**
   * Fail-closed hardware check. A secret must live in secure hardware
   * (TEE/StrongBox), never the software keystore — that is the library's whole
   * premise. If the freshly generated key is not hardware-backed, delete it and
   * refuse with [HardwareUnavailableException] rather than silently keep a
   * software key. (StrongBox is already fail-closed at generation; this also
   * covers the default TEE path and software-only devices/emulators.)
   */
  private fun assertHardwareBacked(alias: String, key: SecretKey) {
    if (!isHardwareBacked(key)) {
      deleteAlias(alias)
      throw HardwareUnavailableException(
        "Key \"$alias\" is not backed by secure hardware (software keystore or unverifiable)."
      )
    }
  }

  /**
   * Whether [key] resides in secure hardware (TEE/StrongBox). **Fail-closed:**
   * any failure to determine this returns `false`, so an unverifiable key is
   * treated as not hardware-backed and refused. Used both right after generation
   * AND on every key retrieval ([V1Scheme.getKey]) — so a pre-existing or
   * orphaned software key (e.g. a `deleteEntry` that failed on a software-only
   * device) can never be silently reused for a hardware-bound secret.
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
