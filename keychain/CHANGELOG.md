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
* **Secure Enclave ECIES** (`eciesEncryptionCofactorVariableIVX963SHA256AESGCM`
  — Apple's recommended-for-new-code variant; the fixed-IV `…X963SHA256AESGCM`
  is now legacy): the
  P-256 private key never leaves the SE chip. The SE key identity encodes
  `(service, accessibility, accessGroup)` in a collision-free tag.
* **Fail-closed authentication:** `secItemAdd` errors rather than storing an
  unprotected item when a `SecAccessControl` cannot be created.
* **`secItemDeleteByPrefix`** for profile-scoped `purge()`; account ownership is
  by exact `prefix + U+001D` boundary supplied by the `oubliette` layer.
* **macOS backends documented:** legacy file-based keychain (no signing, no
  auth) vs. Data Protection keychain (auth; requires signing + the
  `keychain-access-groups` entitlement).
* **`ensureEnclaveKeyPair` is tri-state:** `true` (existed) / `false` (just
  created — the restore-detection signal) / error. A failed key lookup throws
  `se_key_fetch_failed` instead of misreporting an intact key as "just
  created", and the Dart facade throws on a `null` channel answer rather than
  defaulting to `false`.
* **Stable codes for environmental failures on every operation:**
  `missing_entitlement` (`errSecMissingEntitlement` — a signing/entitlement
  defect, not keychain state) and `interaction_not_allowed`
  (`errSecInteractionNotAllowed` — device locked; writes and deletes hit it
  too, not just reads).
* **Memory hygiene:** secret-bearing native paths drain an explicit
  `autoreleasepool`, and the read path's `LAContext` is invalidated
  immediately after use so a pre-authorized context cannot satisfy a later
  operation without UI.
