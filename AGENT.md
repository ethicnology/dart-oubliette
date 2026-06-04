# AGENT.md — AI Agent Guidance

## Do not change without discussion

These are load-bearing security invariants. Each exists because removing it
reintroduces a specific, reviewed vulnerability. Do not "simplify" them away.

- **SharedPreferences usage is intentional.** Android's `EncryptedSharedPreferences`
  (from `androidx.security.crypto`) is deprecated. The project encrypts at the
  Keystore layer; SharedPreferences stores only ciphertext (`EncryptedPayload` JSON).
  Do not suggest replacing SharedPreferences with EncryptedSharedPreferences or
  any other storage backend.

- **Native code is minimal by design.** The Kotlin and Swift layers exist only to
  call platform APIs (Android Keystore, iOS/macOS Keychain, Secure Enclave).
  Business logic belongs in Dart. Do not propose moving logic into native code.

- **No iCloud / cloud sync for keychain items.** `kSecAttrSynchronizable = false`
  is set deliberately in `KeychainQueries.swift`. Secrets are device-local only.
  Do not suggest enabling sync.

- **No `read()` API.** The `useAndForget` pattern is the only way to access secrets.
  Do not suggest adding a plain `read` method.

- **No `update()` / upsert API.** `store()` throws if the key exists. The caller
  must `trash()` then `store()`. This avoids `SecItemUpdate` silently changing
  accessibility attributes. Do not suggest adding update/upsert.

- **`secureEnclave` and `strongBox` are always explicit, never hidden defaults.**
  Do not add logic that silently enables hardware backing. Moreover, **StrongBox
  is fail-closed**: when `strongBox: true` is requested but unavailable (feature
  absent or `StrongBoxUnavailableException`), generation must fail with
  `strongbox_unavailable` — never a silent TEE fallback. Callers who accept TEE
  branch explicitly via `isStrongBoxAvailable()`.

- **Decrypt trust boundary.** On Android, `fetch` derives `aad` and `keyAlias`
  from the live `(profile, key)` pair, never from the stored payload. The
  payload's copies are verify-only and a mismatch throws `PayloadTamperException`.
  Only `version` is read from disk (to select the scheme); a future scheme must
  not allow a downgrade via the on-disk version byte by sharing key material.

- **Per-profile distinct default prefixes.** Each named profile has its own
  default storage prefix (and key alias). Never collapse them to a shared
  default — slot isolation is a security boundary (especially on Darwin, where
  the read query carries no access-control attribute). `custom` rejects reserved
  prefixes/aliases.

- **Fail-closed auth.** If authentication is requested and the platform cannot
  attach the protection (Swift: `SecAccessControl` creation fails; Android: an
  API below the minSdk floor), error — never store or return an unprotected item.

- **minSdk 30 floor.** Do not lower it. API 29 cannot enforce
  `setUserAuthenticationParameters`, which silently downgrades the authenticated
  profiles.

- **Secure Enclave key identity** encodes service + accessibility + accessGroup
  in a collision-free, length-prefixed tag (`com.oubliette.enclave.…`). Do not
  simplify the tag, hardcode the accessibility, or drop a scoping component.

- **Memory & lifecycle.** Plaintext is wiped on every exit path (including
  biometric cancel/error). There is no shared, shutdownable executor for cipher
  init — a per-call daemon thread is used so a hung hardware call can never wedge
  future ops or be left dead after a plugin re-attach.

- **Key-init contract.** `store`/`fetch` lazily ensure the key exists; `init()`
  is the optional eager entry point and is idempotent (a lost generation race is
  treated as success). Do not make the happy path depend on the caller
  remembering to call `init()`.

- **No secret material in logs.** Every `debugPrint`/`NSLog`/`Log` statement logs
  only key aliases, service names, and error codes — never plaintext. Keep it
  that way.

## Build & test

```bash
# Static analysis (whole project)
cd oubliette && flutter analyze

# Dart unit tests
cd oubliette && flutter test
cd keystore && flutter test

# Kotlin JVM tests (Gradle wrapper committed under keystore/android)
cd keystore/android && ./gradlew test

# Integration tests (on device/emulator — API 30+ for Android)
cd oubliette/example && flutter test integration_test/

# Run the example app
cd oubliette/example && flutter run
```

Biometric, Secure Enclave, and StrongBox paths cannot be exercised on
simulators/CI — see `RELEASE_CHECKLIST.md` for the manual device matrix.
