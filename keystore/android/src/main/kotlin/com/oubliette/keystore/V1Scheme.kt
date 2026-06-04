package com.oubliette.keystore

import android.security.keystore.KeyPermanentlyInvalidatedException
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.security.ProviderException
import java.util.concurrent.atomic.AtomicReference
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

  /**
   * Runs [block] (an AndroidKeyStore `Cipher.init`, which makes a Binder call
   * to keymaster that can hang on a busy/wedged secure element) on a throwaway
   * daemon thread and joins with a timeout.
   *
   * Deliberately stateless: there is no shared, shutdownable executor. A hung
   * hardware call leaks one daemon thread that dies with the process, but can
   * never wedge a future operation (the old single-thread executor would stay
   * stuck) nor be left permanently dead after a plugin re-attach (the old
   * executor was shut down on detach and never rebuilt).
   */
  private fun initCipherWithTimeout(block: () -> Unit) {
    val error = AtomicReference<Throwable?>()
    val worker = Thread {
      try {
        block()
      } catch (t: Throwable) {
        error.set(t)
      }
    }.apply {
      isDaemon = true
      name = "oubliette-cipher-init"
      start()
    }
    worker.join(cipherInitTimeoutSeconds * 1000)
    if (worker.isAlive) {
      worker.interrupt() // best effort; a native binder call may ignore it
      throw ProviderException("timed out after ${cipherInitTimeoutSeconds}s — hardware backend may be busy")
    }
    error.get()?.let { throw it }
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

  private fun getKey(alias: String): SecretKey? {
    val keyStore = KeyStore.getInstance(keyStoreType)
    keyStore.load(null)
    return keyStore.getKey(alias, null) as? SecretKey
  }
}
