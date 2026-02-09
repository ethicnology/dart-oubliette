package com.example.secure_storage

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.security.KeyStore
import javax.crypto.KeyGenerator

object Aes256GcmKeyGenerator {
  private const val keyStoreType = "AndroidKeyStore"
  private const val tag = "Aes256GcmKeyGenerator"

  fun generateKey(alias: String, unlockedDeviceRequired: Boolean) {
    val keyStore = KeyStore.getInstance(keyStoreType)
    keyStore.load(null)
    if (keyStore.containsAlias(alias)) return
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
    try {
      specBuilder.setIsStrongBoxBacked(true)
    } catch (e: Exception) {
      Log.i(tag, "StrongBox not available", e)
    }
    keyGenerator.init(specBuilder.build())
    keyGenerator.generateKey()
  }
}
