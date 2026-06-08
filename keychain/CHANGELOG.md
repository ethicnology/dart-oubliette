# Changelog — `keychain`

`keychain` is the iOS/macOS (Darwin) sub-package of
[`oubliette`](../oubliette). The project ships a single consolidated changelog in
[`oubliette/CHANGELOG.md`](../oubliette/CHANGELOG.md); this file records the
changes scoped to this package.

## 1.0.0

First release. Keychain `SecItem` facade with a shared Darwin source and Secure
Enclave ECIES wrapping.

* **`SecItem` add / copy / delete** over a method channel, with
  `kSecAttrSynchronizable = false` on every query — secrets are never synced to
  iCloud.
* **Device-local accessibility by default** (`whenUnlockedThisDeviceOnly` /
  `afterFirstUnlockThisDeviceOnly`); authenticated profiles attach a
  `SecAccessControl`.
* **Secure Enclave ECIES** (`eciesEncryptionCofactorX963SHA256AESGCM`): the
  P-256 private key never leaves the SE chip. The SE key identity encodes
  `(service, accessibility, accessGroup)` in a collision-free tag.
* **Fail-closed authentication:** `secItemAdd` errors rather than storing an
  unprotected item when a `SecAccessControl` cannot be created.
* **`secItemDeleteByPrefix`** for profile-scoped `purge()`; account ownership is
  by exact `prefix + U+001D` boundary supplied by the `oubliette` layer.
* **macOS backends documented:** legacy file-based keychain (no signing, no
  auth) vs. Data Protection keychain (auth; requires signing + the
  `keychain-access-groups` entitlement).
