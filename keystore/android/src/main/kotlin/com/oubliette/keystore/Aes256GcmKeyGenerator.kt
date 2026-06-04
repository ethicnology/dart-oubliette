package com.oubliette.keystore

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.KeyGenerator

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
    keyGenerator.generateKey()
  }
}
