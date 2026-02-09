package com.example.secure_storage

interface EncryptionScheme {
  val version: Int

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
}

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
