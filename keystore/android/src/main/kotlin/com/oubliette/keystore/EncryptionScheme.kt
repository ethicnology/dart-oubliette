package com.oubliette.keystore

import javax.crypto.Cipher

interface EncryptionScheme {
    val version: Int

    fun generateKey(
        alias: String,
        unlockedDeviceRequired: Boolean,
        strongBox: Boolean,
        userAuthenticationRequired: Boolean,
        invalidatedByBiometricEnrollment: Boolean
    )

    fun encrypt(
        alias: String,
        plaintext: ByteArray,
        aad: String
    ): EncryptResult

    fun decrypt(
        alias: String,
        ciphertext: ByteArray,
        nonce: ByteArray,
        aad: String
    ): ByteArray

    fun initEncryptCipher(alias: String): Cipher
    fun initDecryptCipher(alias: String, nonce: ByteArray): Cipher
    fun encryptWithCipher(cipher: Cipher, plaintext: ByteArray, aad: String): EncryptResult
    fun decryptWithCipher(cipher: Cipher, ciphertext: ByteArray, aad: String): ByteArray

    /** Release resources (thread pools, etc.). Called once on plugin detach. */
    fun shutdown() {}
}

/** The Keystore alias does not correspond to any existing key. */
class KeyNotFoundException(alias: String) :
    IllegalStateException("Key not found for alias \"$alias\".")

/** The key exists but has been permanently invalidated (e.g. biometric enrollment changed). */
class KeyInvalidatedException(alias: String, cause: Throwable? = null) :
    IllegalStateException("Key permanently invalidated for alias \"$alias\".", cause)

data class EncryptResult(
    val version: Int,
    val nonce: ByteArray,
    val ciphertext: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as EncryptResult
        if (version != other.version) return false
        if (!nonce.contentEquals(other.nonce)) return false
        if (!ciphertext.contentEquals(other.ciphertext)) return false
        return true
    }

    override fun hashCode(): Int {
        var result = version
        result = 31 * result + nonce.contentHashCode()
        result = 31 * result + ciphertext.contentHashCode()
        return result
    }
}
