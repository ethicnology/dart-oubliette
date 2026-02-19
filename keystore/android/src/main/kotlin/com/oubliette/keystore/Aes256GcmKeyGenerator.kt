package com.oubliette.keystore

import android.os.Build
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
    if (userAuthenticationRequired && Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
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
