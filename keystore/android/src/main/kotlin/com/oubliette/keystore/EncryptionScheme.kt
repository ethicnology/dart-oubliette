package com.oubliette.keystore

import javax.crypto.Cipher

/**
 * The authenticator set a key's own keymaster record will accept, read from its
 * [android.security.keystore.KeyInfo] at crypto time. The BiometricPrompt's
 * allowed authenticators MUST be derived from this — never from a caller-supplied
 * flag — so the auth token the prompt produces can always authorize the key's
 * cipher (see [KeystorePlugin.authenticate]).
 */
enum class KeyAuthenticators {
    /** `AUTH_BIOMETRIC_STRONG` only — credential fallback would void enrollment invalidation. */
    BIOMETRIC_ONLY,

    /** `AUTH_DEVICE_CREDENTIAL` is set — PIN/pattern/password may authorize the key. */
    DEVICE_CREDENTIAL_ALLOWED
}

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

    /**
     * The authenticator set the key under [alias] will accept, read from its
     * `KeyInfo`. Returns null when the key does not require user authentication
     * (no prompt is needed). Throws [KeyNotFoundException] if the alias is
     * absent and [KeyAuthTypeUnknownException] if the key requires auth but its
     * authenticator type cannot be determined (fail-closed: never guess).
     */
    fun keyAuthenticators(alias: String): KeyAuthenticators?

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
 * A BiometricPrompt was requested, but a usable allowed-authenticator set could
 * not be derived from the key's `KeyInfo` — either the auth type is unreadable,
 * or the key does not require user authentication at all (so a prompt would not
 * actually gate it). Fail-closed: rather than guess (and risk offering
 * DEVICE_CREDENTIAL on a biometric-only key, whose auth token cannot authorize
 * the cipher — an opaque failure AFTER a successful PIN entry) or show a prompt
 * that protects nothing, the operation is refused. Recoverable — the key is
 * intact; the read may succeed on retry, or the caller should use the
 * non-authenticating path for a non-auth key.
 */
class KeyAuthTypeUnknownException(cause: Throwable? = null) :
    IllegalStateException("Cannot derive the prompt's authenticator set from the key (auth type unreadable or key is not auth-bound).", cause)

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
