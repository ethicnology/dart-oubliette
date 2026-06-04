package com.oubliette.keystore

/**
 * Stateless registry of immutable encryption schemes. Holds no mutable
 * lifecycle state, so it stays valid across plugin attach/detach cycles — there
 * is nothing to shut down or rebuild.
 */
object SchemeRegistry {
  const val CURRENT_VERSION = 1

  private val schemes: Map<Int, EncryptionScheme> = mapOf(
    1 to V1Scheme()
  )

  fun schemeFor(version: Int): EncryptionScheme? = schemes[version]
}
