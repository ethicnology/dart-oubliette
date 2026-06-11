package com.oubliette.keystore

import javax.crypto.Cipher

interface EncryptionScheme {
    val version: Int

    fun generateKey(
        alias: String,
        unlockedDeviceRequired: Boolean,
        strongBox: Boolean,
        userAuthenticationRequired: Boolean,
        invalidatedByBiometricEnrollment: Boolean,
        requireHardwareBacking: Boolean
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
}

// DIAGNOSTIC HYGIENE — these messages deliberately do NOT interpolate the
// alias. They cross the MethodChannel as PlatformException.message, and codes
// the Dart layer passes through unmapped (already_exists, hardware_unavailable,
// encrypt_failed, …) reach app logs and crash reporters verbatim. An alias from
// a `custom` profile can encode a tenant or user id, so folding it into the
// message would exfiltrate it (mirrors the toString() rule in oubliette's
// errors.dart). The caller already knows which alias it asked about.

/** The Keystore alias does not correspond to any existing key. */
class KeyNotFoundException :
    IllegalStateException("No key exists under the requested alias.")

/**
 * A key already exists under the requested alias. Dedicated type so the plugin
 * maps exactly this — and not every [IllegalStateException] a keystore
 * internal might throw — to the `already_exists` code (which the Dart layer
 * treats as success in its idempotent ensure-key path).
 */
class KeyAlreadyExistsException :
    IllegalStateException("A key already exists under the requested alias. Call deleteEntry() first.")

/**
 * The key exists but is permanently unusable: biometric enrollment changed on
 * an enrollment-invalidated key, the secure lock screen was removed, or the
 * key blob itself can no longer be loaded (post-OTA keymaster mismatch —
 * surfaces as [java.security.UnrecoverableKeyException]). Retrying can never
 * succeed; recovery is the caller's explicit, data-destroying decision.
 */
class KeyInvalidatedException(cause: Throwable? = null) :
    IllegalStateException("Key permanently invalidated (enrollment change, lock-screen removal, or unrecoverable key blob).", cause)

/**
 * The freshly generated key is NOT backed by secure hardware (TEE/StrongBox) —
 * it landed in the software keystore. Fail-closed: a hardware-bound secret must
 * never silently fall back to software. Distinct from [KeyInvalidatedException]
 * (extends RuntimeException, not IllegalStateException) so it is not mapped to
 * the `already_exists` bucket.
 */
class HardwareUnavailableException(message: String) : RuntimeException(message)

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
