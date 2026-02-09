package com.example.keystore

object SchemeRegistry {
  const val CURRENT_VERSION = 1

  private val schemes: Map<Int, EncryptionScheme> = mapOf(
    1 to V1Scheme()
  )

  fun schemeFor(version: Int): EncryptionScheme? = schemes[version]
}
