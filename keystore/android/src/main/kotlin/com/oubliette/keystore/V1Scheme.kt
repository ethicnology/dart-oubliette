package com.oubliette.keystore

import android.security.keystore.KeyPermanentlyInvalidatedException
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.security.ProviderException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class V1Scheme(
  private val keyStoreType: String = "AndroidKeyStore",
  private val aesMode: String = "AES/GCM/NoPadding",
  private val ivSizeBytes: Int = 12,
  private val tagSizeBits: Int = 128,
  private val cipherInitTimeoutSeconds: Long = 5
) : EncryptionScheme {

  override val version: Int get() = 1

  private val timeoutExecutor = Executors.newSingleThreadExecutor()

  private fun initCipherWithTimeout(block: () -> Unit) {
    val future = timeoutExecutor.submit(block)
    try {
      future.get(cipherInitTimeoutSeconds, TimeUnit.SECONDS)
    } catch (e: TimeoutException) {
      future.cancel(true)
      throw ProviderException("timed out after ${cipherInitTimeoutSeconds}s — hardware backend may be busy")
    } catch (e: java.util.concurrent.ExecutionException) {
      throw e.cause ?: e
    }
  }

  override fun generateKey(alias: String, unlockedDeviceRequired: Boolean, strongBox: Boolean, userAuthenticationRequired: Boolean, invalidatedByBiometricEnrollment: Boolean) {
    Aes256GcmKeyGenerator.generateKey(alias, unlockedDeviceRequired, strongBox, userAuthenticationRequired, invalidatedByBiometricEnrollment)
  }

  override fun encrypt(
    alias: String,
    plaintext: ByteArray,
    aad: String
  ): EncryptResult {
    val cipher = initEncryptCipher(alias)
    return encryptWithCipher(cipher, plaintext, aad)
  }

  override fun decrypt(
    alias: String,
    ciphertext: ByteArray,
    nonce: ByteArray,
    aad: String
  ): ByteArray {
    val cipher = initDecryptCipher(alias, nonce)
    return decryptWithCipher(cipher, ciphertext, aad)
  }

  override fun initEncryptCipher(alias: String): Cipher {
    val key = getKey(alias)
      ?: throw KeyNotFoundException(alias)
    val cipher = Cipher.getInstance(aesMode)
    try {
      initCipherWithTimeout { cipher.init(Cipher.ENCRYPT_MODE, key) }
    } catch (e: KeyPermanentlyInvalidatedException) {
      throw KeyInvalidatedException(alias, e)
    }
    return cipher
  }

  override fun initDecryptCipher(alias: String, nonce: ByteArray): Cipher {
    if (nonce.size != ivSizeBytes) {
      throw IllegalArgumentException("Invalid nonce size.")
    }
    val key = getKey(alias)
      ?: throw KeyNotFoundException(alias)
    val cipher = Cipher.getInstance(aesMode)
    try {
      initCipherWithTimeout { cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(tagSizeBits, nonce)) }
    } catch (e: KeyPermanentlyInvalidatedException) {
      throw KeyInvalidatedException(alias, e)
    }
    return cipher
  }

  override fun encryptWithCipher(cipher: Cipher, plaintext: ByteArray, aad: String): EncryptResult {
    cipher.updateAAD(aad.toByteArray(StandardCharsets.UTF_8))
    val ciphertext = cipher.doFinal(plaintext)
    val nonce = cipher.iv
      ?: throw IllegalArgumentException("Invalid nonce.")
    if (nonce.size != ivSizeBytes) {
      throw IllegalArgumentException("Invalid nonce size.")
    }
    return EncryptResult(version, nonce, ciphertext)
  }

  override fun decryptWithCipher(cipher: Cipher, ciphertext: ByteArray, aad: String): ByteArray {
    cipher.updateAAD(aad.toByteArray(StandardCharsets.UTF_8))
    return cipher.doFinal(ciphertext)
  }

  override fun shutdown() {
    timeoutExecutor.shutdownNow()
  }

  private fun getKey(alias: String): SecretKey? {
    val keyStore = KeyStore.getInstance(keyStoreType)
    keyStore.load(null)
    return keyStore.getKey(alias, null) as? SecretKey
  }
}
