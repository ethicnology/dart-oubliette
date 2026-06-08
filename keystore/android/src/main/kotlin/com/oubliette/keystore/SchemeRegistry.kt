package com.oubliette.keystore

/**
 * Stateless registry of immutable encryption schemes. Holds no mutable
 * lifecycle state, so it stays valid across plugin attach/detach cycles — there
 * is nothing to shut down or rebuild.
 *
 * UPGRADE CONTRACT — this map is **append-only**. Every blob on disk records
 * the scheme [version] it was written with and is decrypted by that exact
 * scheme, so:
 *   - NEVER remove or mutate a shipped scheme (e.g. `1 to V1Scheme()`); doing so
 *     makes every blob written by that version permanently undecryptable on the
 *     next app update — silent data loss.
 *   - To rotate crypto, ADD a new version (e.g. `2 to V2Scheme()`) and bump
 *     [CURRENT_VERSION] so only *new* writes use it; existing blobs keep
 *     decrypting under their original version. (Tink-style keyset rotation.)
 * See SECURITY.md → "Stability & upgrade contract".
 */
object SchemeRegistry {
  /** The scheme used for new writes (the keyset "primary"). */
  const val CURRENT_VERSION = 1

  private val schemes: Map<Int, EncryptionScheme> = mapOf(
    // Append only — never delete a line below. See the class doc.
    1 to V1Scheme()
  )

  fun schemeFor(version: Int): EncryptionScheme? = schemes[version]
}
