package com.oubliette.keystore

object SchemeRegistry {
  const val CURRENT_VERSION = 1

  private val schemes: Map<Int, EncryptionScheme> = mapOf(
    1 to V1Scheme()
  )

  fun schemeFor(version: Int): EncryptionScheme? = schemes[version]

  /** Shut down all registered schemes. Called once during plugin detach. */
  fun shutdownAll() {
    schemes.values.forEach { it.shutdown() }
  }
}
