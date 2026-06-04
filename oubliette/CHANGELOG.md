# Changelog

This is the single changelog for the whole project: the `oubliette` package and
its bundled platform plugins `keychain` (iOS/macOS) and `keystore` (Android).

## 1.0.0

Initial (unreleased) version. The items below are recorded for the first real
release; the project has never been published, so there is no stored data in
the wild and **no migration is required**.

### Security & correctness

* **Decrypt trust boundary (Android):** `fetch` now derives the AAD and key
  alias from the live `(profile, key)` pair instead of reading them from the
  stored blob. A relocated or downgraded payload throws `PayloadTamperException`.
* **Fail-closed authentication:** the Darwin `secItemAdd` errors instead of
  storing an unprotected item when a `SecAccessControl` cannot be created; the
  Android authenticated profiles always apply `setUserAuthenticationParameters`.
* **StrongBox fail-closed:** requesting `strongBox: true` on a device without
  StrongBox now throws `strongbox_unavailable` instead of silently using the TEE.
* **Device-local only:** every Darwin keychain query sets
  `kSecAttrSynchronizable = false`, so secrets are never synced to iCloud.
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
