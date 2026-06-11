package com.oubliette.keystore

import android.security.keystore.KeyPermanentlyInvalidatedException
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.security.ProviderException
import java.security.UnrecoverableKeyException
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

  override fun generateKey(alias: String, unlockedDeviceRequired: Boolean, strongBox: Boolean, userAuthenticationRequired: Boolean, invalidatedByBiometricEnrollment: Boolean, requireHardwareBacking: Boolean) {
    Aes256GcmKeyGenerator.generateKey(alias, unlockedDeviceRequired, strongBox, userAuthenticationRequired, invalidatedByBiometricEnrollment, requireHardwareBacking)
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
      ?: throw KeyNotFoundException()
    val cipher = Cipher.getInstance(aesMode)
    try {
      initCipherWithTimeout { cipher.init(Cipher.ENCRYPT_MODE, key) }
    } catch (e: Exception) {
      throw if (isPermanentInvalidation(e)) KeyInvalidatedException(e) else e
    }
    return cipher
  }

  override fun initDecryptCipher(alias: String, nonce: ByteArray): Cipher {
    if (nonce.size != ivSizeBytes) {
      throw IllegalArgumentException("Invalid nonce size.")
    }
    val key = getKey(alias)
      ?: throw KeyNotFoundException()
    val cipher = Cipher.getInstance(aesMode)
    try {
      initCipherWithTimeout { cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(tagSizeBits, nonce)) }
    } catch (e: Exception) {
      throw if (isPermanentInvalidation(e)) KeyInvalidatedException(e) else e
    }
    return cipher
  }

  override fun encryptWithCipher(cipher: Cipher, plaintext: ByteArray, aad: String): EncryptResult {
    cipher.updateAAD(versionedAad(aad))
    val ciphertext = try {
      cipher.doFinal(plaintext)
    } catch (e: Exception) {
      throw if (isPermanentInvalidation(e)) KeyInvalidatedException(e) else e
    }
    val nonce = cipher.iv
      ?: throw IllegalArgumentException("Invalid nonce.")
    if (nonce.size != ivSizeBytes) {
      throw IllegalArgumentException("Invalid nonce size.")
    }
    return EncryptResult(version, nonce, ciphertext)
  }

  override fun decryptWithCipher(cipher: Cipher, ciphertext: ByteArray, aad: String): ByteArray {
    cipher.updateAAD(versionedAad(aad))
    return try {
      cipher.doFinal(ciphertext)
    } catch (e: Exception) {
      throw if (isPermanentInvalidation(e)) KeyInvalidatedException(e) else e
    }
  }

  /**
   * Whether [t] — or anything in its cause chain — is the framework's
   * permanent-invalidation signal.
   *
   * [KeyPermanentlyInvalidatedException] is documented to be thrown by
   * `Cipher.init`, but on a number of devices the keymaster defers the check
   * to the operation itself: `doFinal` then fails with a *wrapping* exception
   * (typically `IllegalBlockSizeException` or `ProviderException`) whose cause
   * chain carries the real signal. Matching only at `init` would report those
   * as a generic — apparently transient — `encrypt_failed`/`decrypt_failed`,
   * and the caller would retry a permanently dead key forever instead of
   * surfacing the typed key-loss it must act on. Walking the chain classifies
   * them correctly on both the init and doFinal paths.
   *
   * Deliberately conservative — only the explicit framework type counts. A
   * `doFinal` failure caused by a bare `KeyStoreException` ("Key user not
   * authenticated", "operation expired", …) is NOT treated as invalidation:
   * it is indistinguishable from a prompt/key authenticator mismatch or a
   * pruned operation slot, and misclassifying a transient failure as key-loss
   * is the exact mistake the error taxonomy exists to prevent (the caller may
   * respond to key_invalidated with an irreversible purge).
   */
  private fun isPermanentInvalidation(t: Throwable): Boolean {
    var current: Throwable? = t
    var depth = 0
    while (current != null && depth < 8) { // bounded: malicious/cyclic chains
      if (current is KeyPermanentlyInvalidatedException) return true
      current = current.cause
      depth++
    }
    return false
  }

  /**
   * Binds this scheme's [version] into the AES-GCM AAD. The on-disk `version`
   * selects the decrypting scheme but is itself read from attacker-writable
   * storage; without binding it, a future v2 reusing v1's key alias could be
   * forced to a weaker v1 decrypt by flipping the stored version. Because the
   * version constant is mixed into the authenticated data, a mismatched
   * scheme/version fails the GCM tag. Both encrypt and decrypt go through this
   * single method, so the binding is symmetric by construction.
   */
  private fun versionedAad(aad: String): ByteArray =
    "v$version\u001D$aad".toByteArray(StandardCharsets.UTF_8)

  private fun getKey(alias: String): SecretKey? {
    val keyStore = KeyStore.getInstance(keyStoreType)
    keyStore.load(null)
    return try {
      keyStore.getKey(alias, null) as? SecretKey
    } catch (e: UnrecoverableKeyException) {
      // getKey returns null for a missing alias; UnrecoverableKeyException
      // means the entry EXISTS but its key material can no longer be loaded —
      // a corrupted or keymaster-undecryptable blob (classically after an OTA
      // that changed the keymaster implementation, or vendor data wipe). The
      // java.security contract makes this permanent: retrying can never
      // succeed, so reporting it as a generic encrypt/decrypt failure would
      // strand the caller in a retry loop on a dead key. Classified as
      // key_invalidated — the same "key effectively dead, data unreachable"
      // taxonomy as enrollment invalidation. The library still never deletes
      // the entry on its own; that irreversible decision stays with the caller.
      throw KeyInvalidatedException(e)
    }
  }
}
