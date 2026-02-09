package com.example.secure_storage

import java.nio.charset.StandardCharsets
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class V1Scheme(
  private val keyStoreType: String = "AndroidKeyStore",
  private val aesMode: String = "AES/GCM/NoPadding",
  private val ivSizeBytes: Int = 12,
  private val tagSizeBits: Int = 128
) : EncryptionScheme {

  override val version: Int get() = 1

  override fun encrypt(
    alias: String,
    plaintext: ByteArray,
    aad: String
  ): EncryptResult {
    val key = getKey(alias)
      ?: throw IllegalArgumentException("Key not found for alias.")
    val cipher = Cipher.getInstance(aesMode)
    cipher.init(Cipher.ENCRYPT_MODE, key)
    cipher.updateAAD(aad.toByteArray(StandardCharsets.UTF_8))
    val ciphertext = cipher.doFinal(plaintext)
    val nonce = cipher.iv
      ?: throw IllegalArgumentException("Invalid nonce.")
    if (nonce.size != ivSizeBytes) {
      throw IllegalArgumentException("Invalid nonce size.")
    }
    return EncryptResult(version, nonce, ciphertext)
  }

  override fun decrypt(
    alias: String,
    ciphertext: ByteArray,
    nonce: ByteArray,
    aad: String
  ): ByteArray {
    if (nonce.size != ivSizeBytes) {
      throw IllegalArgumentException("Invalid nonce size.")
    }
    val key = getKey(alias)
      ?: throw IllegalArgumentException("Key not found for alias.")
    val cipher = Cipher.getInstance(aesMode)
    cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(tagSizeBits, nonce))
    cipher.updateAAD(aad.toByteArray(StandardCharsets.UTF_8))
    return cipher.doFinal(ciphertext)
  }

  private fun getKey(alias: String): SecretKey? {
    val keyStore = KeyStore.getInstance(keyStoreType)
    keyStore.load(null)
    return keyStore.getKey(alias, null) as? SecretKey
  }
}
