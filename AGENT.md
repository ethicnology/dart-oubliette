# AGENT.md — AI Agent Guidance

## Do not change without discussion

These are load-bearing security invariants. Each exists because removing it
reintroduces a specific, reviewed vulnerability. Do not "simplify" them away.

- **The AEAD is not key-committing.** AES-GCM (Android) and SE-ECIES-GCM (Darwin)
  are not key-committing AEADs. This is safe today because nothing ever tries to
  decrypt one blob under multiple candidate keys — each slot maps to exactly one
  key. **Never build a "try every key until one decrypts" path** (a multi-key
  decryption oracle); if a future scheme needs that, switch to a key-committing
  construction first. Also: the AES-GCM random-nonce safety bound is **per key**
  (~2^32 messages, NIST SP 800-38D) and is satisfied by the one-write-per-slot
  model — do not introduce a high-frequency re-encrypt loop on a single key.

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

- **Hardware backing is verified, fail-closed (Android).** Beyond StrongBox,
  *every* key is checked via `KeyInfo` (`getSecurityLevel()` on API 31+,
  `isInsideSecureHardware` on API 30) — at generation
  (`Aes256GcmKeyGenerator`) **and on every key retrieval** (`V1Scheme.getKey`,
  covering both the plain and biometric paths). A software-backed/unverifiable
  key is deleted/refused with `hardware_unavailable`. Do not remove the per-use
  check: it closes the orphan-reuse gap (a key left in the software keystore must
  never be silently used for a secret). `isHardwareBacked` is fail-closed
  (unverifiable → refused).

- **Every Darwin profile is `ThisDeviceOnly`.** `DarwinSecretAccess.custom`
  rejects non-device-local accessibility (`whenUnlocked`/`afterFirstUnlock`) via
  the `_deviceLocalAccessibility` allow-set; the four named profiles already
  comply. Do not relax this — a non-`ThisDeviceOnly` item rides an encrypted
  backup to another device (where its hardware key can't follow), which is both
  an exfiltration path and a guaranteed undecryptable-on-restore blob.

- **Decrypt trust boundary.** On Android, `fetch` derives `aad` and `keyAlias`
  from the live `(profile, key)` pair, never from the stored payload. The
  payload's copies are verify-only and a mismatch throws `PayloadTamperException`.
  Only `version` is read from disk (to select the scheme), and it is **bound
  into the AES-GCM AAD** (`V1Scheme.versionedAad` prepends `v{version}`),
  so a rewritten on-disk version byte fails the GCM tag — no downgrade even if a
  future scheme reuses a key alias. Keep this: every scheme MUST bind its own
  `version` into the AAD (it's free — both encrypt and decrypt route through the
  one `encryptWithCipher`/`decryptWithCipher` chokepoint). Do not remove it.

- **Per-profile distinct default prefixes.** Each named profile has its own
  default storage prefix (and key alias). Never collapse them to a shared
  default — slot isolation is a security boundary (especially on Darwin, where
  the read query carries no access-control attribute). `custom` rejects reserved
  prefixes/aliases.

- **Reserved slot separator (frozen).** A storage slot is
  `prefix + slotSeparator + key` where `slotSeparator = U+001D`
  (`oubliette/lib/src/slot.dart`), rejected in prefixes and keys. This string is
  the SharedPreferences key, the `kSecAttrAccount`, **and** the Android AES-GCM
  AAD. The separator's position encodes the prefix length, making `purge()`
  ownership exact — a profile whose prefix nests under another's (incl. two
  custom siblings like `app_` ⊂ `app_admin_`) can never wipe the other. Do not
  revert `purge()` to a bare `startsWith(prefix)`, change the separator, or drop
  the prefix/key validation — each reintroduces a nested-prefix data-loss bug.

- **Frozen on-disk format versions, both platforms.** Android: the
  `EncryptedPayload` JSON envelope is format v1 (field names + base64 +
  snake_case `key_alias` frozen). Darwin: every blob is prefixed with the frozen
  1-byte `_darwinFormatV1` header (`darwin_oubliette.dart`). Bump either only by
  *adding* a reader for a new value; never reinterpret an old one. The golden
  vectors in `keystore/test/encrypted_payload_test.dart` are **hardcoded
  literals** — a failure means you drifted the format; never "update" a golden
  string to make CI green.

- **Typed errors carry a `recoverable` flag.** Native codes map to sealed
  `OublietteException` subtypes (`oubliette/lib/src/errors.dart`). Set
  `recoverable` correctly: `AuthenticationFailedException` is recoverable (retry,
  never `purge()`); key-gone / decrypt / tamper / corrupt are not. Do not
  collapse a recoverable failure into a fatal-looking one — a caller may answer
  a "fatal" error with the irreversible `purge()`.

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

Use **`fvm flutter`** — the repo is pinned to Flutter 3.44.1 / Dart 3.12.1
(`.fvmrc`); a default-PATH `flutter` may be too old to resolve dependencies.

```bash
# Static analysis (whole project)
cd oubliette && fvm flutter analyze

# Dart unit tests
cd oubliette && fvm flutter test
cd keystore && fvm flutter test

# Kotlin JVM tests (Gradle wrapper committed under keystore/android)
cd keystore/android && ./gradlew test

# Integration tests (on device/emulator — API 30+ for Android)
cd oubliette/example && fvm flutter test integration_test/

# Run the example app
cd oubliette/example && fvm flutter run
```

Biometric, Secure Enclave, and StrongBox paths cannot be exercised on
simulators/CI — verify them manually on real devices with an enrolled credential
(biometric + device-credential, StrongBox where present) before a release.
