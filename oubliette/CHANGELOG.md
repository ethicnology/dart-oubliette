# Changelog

This is the single changelog for the whole project: the `oubliette` package and
its bundled platform plugins `keychain` (iOS/macOS) and `keystore` (Android).

## 1.0.0

First release. The project has never been published, so this version is free to
choose its final on-disk format — and from this release that format becomes a
**stable contract**: data written by any `1.x` is readable by every later `1.x`,
and upgrades never silently reset, re-key, or strand secrets (see
`SECURITY.md` → *Stability & upgrade contract*).

### Security & correctness

* **Decrypt trust boundary (Android):** `fetch` now derives the AAD and key
  alias from the live `(profile, key)` pair instead of reading them from the
  stored blob. A relocated or downgraded payload throws `PayloadTamperException`.
* **Fail-closed authentication:** the Darwin `secItemAdd` errors instead of
  storing an unprotected item when a `SecAccessControl` cannot be created; the
  Android authenticated profiles always apply `setUserAuthenticationParameters`.
* **StrongBox fail-closed:** requesting `strongBox: true` on a device without
  StrongBox now throws `strongbox_unavailable` instead of silently using the TEE.
* **Hardware-backing verified, fail-closed (Android):** every key is checked
  (`KeyInfo`: `getSecurityLevel()` on API 31+, `isInsideSecureHardware` on API 30) at generation **and on every
  encrypt/decrypt** — a software-backed key is deleted/refused with
  `hardware_unavailable`, so a secret is never silently kept in (nor an orphaned
  software key reused from) the software keystore.
* **Scheme `version` bound into the AES-GCM AAD (Android):** the on-disk version
  selects the decrypting scheme and is now authenticated, so a rewritten version
  byte can never force a downgrade to a weaker scheme (defeats the latent
  cross-version replay before any v2 ships).
* **Device-local only — enforced for every profile:** every Darwin keychain
  query sets `kSecAttrSynchronizable = false` (never iCloud-synced), and the
  `custom` constructor now **rejects** non-`ThisDeviceOnly` accessibility
  (`whenUnlocked`/`afterFirstUnlock`) so a hardware-bound secret can never ride
  an encrypted backup to another device.
* **Lazy key-ensure:** `store`/`fetch` generate the key on demand, so the happy
  path no longer depends on the caller invoking `init()` first. `init()` remains
  as an idempotent eager entry point.
* **Per-key store lock** makes the no-overwrite invariant hold under concurrent
  `store()` calls for the same key.
* **Memory hygiene:** plaintext is wiped on every exit path, including biometric
  cancel/error and bad-args early returns; biometric cipher init and `doFinal`
  run off the platform thread (ANR avoidance).
* **Plugin lifecycle:** the Android cipher-init timeout uses a per-call daemon
  thread; the shared shutdownable executor (which could wedge or die on
  re-attach) is gone, and the crypto thread is recreated on every engine attach.
* **Secure Enclave key identity** now encodes service + accessibility + access
  group in a collision-free tag (`com.oubliette.enclave.…`), threads
  accessibility into the access-control policy, and honors the access group.
* **Typed `KeyInvalidatedException`:** Android `store`/`fetch` translate the
  native `key_invalidated` error into a catchable Dart exception so callers can
  detect a wedged profile and recover, instead of string-matching a
  `PlatformException`.
* **`purge()` — explicit whole-profile destroy:** wipes every blob in a profile
  plus, on Android, the profile's Keystore key (Darwin retains the shared SE
  key). The only API that destroys key material, and only on an explicit call.
  Recovery from an invalidated profile is `purge()` then `init()`.
* **Reserved slot separator — exact `purge()` ownership:** a storage slot is
  `prefix + U+001D + key` (the separator is rejected in prefixes and keys).
  Because the separator's position encodes the prefix length, a profile whose
  prefix nests under another's can never collide with or `purge()` the other's
  data — including two *custom* sibling profiles (`app_` ⊂ `app_admin_`), the
  case a constructor check cannot catch. Replaces the earlier longest-prefix
  exclusion, which left a cross-launch gap for custom profiles.
* **Sealed `OublietteException` hierarchy with a `recoverable` flag:** Android
  and Darwin map native error codes to typed exceptions — `KeyInvalidatedException`,
  `KeyNotFoundException`, `DecryptionFailedException`, `AuthenticationFailedException`
  (the only `recoverable` one), `PayloadTamperException`, `PayloadCorruptException`.
  Callers branch on `recoverable` instead of string-matching codes, so a transient
  auth failure can no longer be mistaken for a fatal one and answered with a
  data-destroying `purge()`.
* **Hardened deserialization:** `EncryptedPayload` rejects a bad version, empty
  or non-base64 nonce/ciphertext with a clear `FormatException`, surfaced to the
  caller as `PayloadCorruptException` rather than an opaque `decrypt_failed`.
* **All Android Keystore results delivered on the platform thread** (`@UiThread`
  correctness) with a dead-looper guard that fails the Dart Future and wipes any
  secret instead of hanging.

### Stability & upgrade contract

* **Versioned, frozen on-disk format — on both platforms** with committed golden
  test vectors: CI fails if the current code can no longer read v1-format data.
  Android blobs carry a scheme `version` in the forward-compatible
  `EncryptedPayload` envelope; Darwin blobs (Keychain items have no envelope of
  their own) are now prefixed with a frozen 1-byte format header serving the
  same role — closing the prior gap where a future Darwin format change could
  not have been told apart from old data.
* **Append-only scheme registry** — a shipped scheme version is never removed;
  old blobs always decrypt by their on-disk version.
* From `1.0.0` the format, naming schema, and key identity are a stable
  contract. Because the format is versioned and the registry append-only, data
  written by any `1.x` stays readable by every later `1.x` with **no migration
  call required**; the only data-destroying API is the explicit `purge()`.

### Components

* **`keystore` (Android):** Android Keystore AES-256-GCM facade with a versioned
  `EncryptedPayload` (currently scheme v1).
* **`keychain` (iOS/macOS):** Keychain `SecItem` facade with shared Darwin
  source and Secure Enclave ECIES wrapping.

### Breaking changes (vs. pre-release code)

* **Per-profile default prefixes** — each named profile now defaults to a
  distinct storage prefix (`oubliette_only_unlocked_`, …) instead of a shared
  `oubliette_`. Different storage slots; no migration (no prior data).
* **Secure Enclave tag scheme + namespace** changed (`com.oubliette.se.` →
  `com.oubliette.enclave.` with structured components). Different SE key
  identity; no migration.
* **`minSdk` 29 → 30** (Android 11). Drops Android 10.
* **StrongBox no longer falls back to TEE** silently — see above.
* Removed the internal Android `shutdown()` machinery (not part of the public
  Dart API).
* Dropped the `dart_mappable` dependency; `EncryptedPayload` now hand-rolls its
  JSON. The on-disk JSON shape is unchanged.
* **Minimum Flutter 3.44 / Dart 3.12.** The Android build migrated to AGP 9 +
  built-in Kotlin (no `kotlin-android` plugin; Gradle 9.1.0, Kotlin 2.3.20).
* The iOS/macOS `keychain` plugin now ships a Swift Package Manager manifest
  (`darwin/keychain/Package.swift`) alongside the CocoaPods podspec; both are
  supported.
