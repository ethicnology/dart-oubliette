# Changelog — `keychain`

`keychain` is the iOS/macOS (Darwin) sub-package of
[`oubliette`](../oubliette). The project ships a single consolidated changelog in
[`oubliette/CHANGELOG.md`](../oubliette/CHANGELOG.md); this file records the
changes scoped to this package.

## 1.0.0

* **`biometryCurrentSetOnly` without `authenticationRequired` is now rejected.**
  The `.biometryCurrentSet` access-control flag is only applied on the
  authenticated write branch, so setting `biometryCurrentSetOnly: true` with
  `authenticationRequired: false` previously stored an item with **no** access
  control — the strictest-sounding profile yielding the weakest item (fail-open
  against intent). `secItemAdd` now fails closed with
  `biometry_requires_authentication` and stores nothing; the biometry-lockout
  read probe is likewise gated on both flags.
* **Biometry lockout is now a distinct error.** Too-many-failed-attempts
  lockout previously folded into `auth_failed` (indistinguishable by `OSStatus`).
  The read path now probes a fresh `LAContext` with `canEvaluatePolicy` on
  `errSecAuthFailed` and emits `biometry_lockout` when `LAError.biometryLockout`
  is reported — still recoverable, but the caller can prompt the user to unlock
  with the passcode to re-enable biometry instead of a bare retry.
* **Read auth-context reuse window pinned to zero.** The read `LAContext` now
  sets `touchIDAuthenticationAllowableReuseDuration = 0` explicitly so a
  successful evaluation can never pre-authorize a later operation, regardless of
  a future SDK default.
* **`ensureEnclaveKeyPair` rejects a non-map argument** as `bad_args`, matching
  the strict arg-guard of every other handler.

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
* **Swift 6 strict-concurrency clean:** the native plugin builds under the
  Swift 6 language mode. The `@escaping FlutterResult` (a non-`Sendable`
  Objective-C block) is carried across the work-queue → main-thread hop in a
  `Sendable` wrapper that always delivers on the main thread, so the
  result is still invoked exactly once on main with no behavior change. The
  wrapper's `deliver(_:)` takes its `Any?` payload as a `sending` parameter so
  ownership transfers into the main-queue closure (an `Any?` is not `Sendable`);
  every call site passes a freshly built, non-reused value. The SPM manifest
  pins the Swift 6 language mode to match the podspec.
* **`secItemListByPrefix` added** — the read-only twin of `secItemDeleteByPrefix`
  backing `Oubliette.keys()`. It runs the same `SecItemCopyMatching` enumeration
  (`kSecMatchLimitAll` + `kSecReturnAttributes`, **never** `kSecReturnData`) and
  returns the matching `kSecAttrAccount` names — key names only, no value is read
  or decrypted, so it is not a `read()` back door.
