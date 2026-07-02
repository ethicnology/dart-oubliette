package com.oubliette.keystore

import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Enforces the append-only upgrade contract of [SchemeRegistry] (SECURITY.md →
 * "Stability & upgrade contract"). These are pure-Kotlin assertions and run on
 * the JVM via `./gradlew test` — no Android runtime required.
 *
 * The actual AES-GCM round-trip is hardware-backed (Android Keystore) and can
 * only be exercised on device/emulator; that lives in the integration tests.
 */
internal class SchemeRegistryTest {

  @Test
  fun `the primary (current) version has a registered scheme`() {
    assertNotNull(
      SchemeRegistry.schemeFor(SchemeRegistry.CURRENT_VERSION),
      "CURRENT_VERSION must resolve to a scheme used for new writes",
    )
  }

  @Test
  fun `version 1 is present forever (append-only contract)`() {
    // The first shipped scheme. If this fails, someone removed `1 to V1Scheme()`
    // — every blob written by v1 just became permanently undecryptable on
    // upgrade. That is the silent data loss this library exists to prevent.
    assertNotNull(
      SchemeRegistry.schemeFor(1),
      "scheme version 1 must never be removed or mutated",
    )
  }

  @Test
  fun `every version from 1 through CURRENT_VERSION resolves (no gaps, no removals)`() {
    for (version in 1..SchemeRegistry.CURRENT_VERSION) {
      assertNotNull(
        SchemeRegistry.schemeFor(version),
        "scheme version $version must remain registered (append-only)",
      )
    }
  }

  @Test
  fun `unknown versions resolve to null, never a fallback scheme`() {
    // A missing version must be an explicit miss (caller surfaces a clear
    // error), never silently mapped to some default scheme that would decrypt
    // under the wrong parameters.
    assertNull(SchemeRegistry.schemeFor(0))
    assertNull(SchemeRegistry.schemeFor(-1))
    assertNull(SchemeRegistry.schemeFor(SchemeRegistry.CURRENT_VERSION + 1))
    assertNull(SchemeRegistry.schemeFor(Int.MAX_VALUE))
  }

  @Test
  fun `CURRENT_VERSION is the highest registered version (primary is newest)`() {
    // New writes use CURRENT_VERSION; it must be the newest scheme, otherwise a
    // newer-than-primary scheme exists that nothing writes with. Deliberately
    // NOT pinned to 1 — a legitimate v2 rotation must not fail this test, only
    // a removal/gap/inversion should.
    assertTrue(SchemeRegistry.CURRENT_VERSION >= 1)
    assertNull(
      SchemeRegistry.schemeFor(SchemeRegistry.CURRENT_VERSION + 1),
      "no scheme may be registered above CURRENT_VERSION",
    )
  }
}
