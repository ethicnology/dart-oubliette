# Changelog — `keystore`

`keystore` is the Android-only sub-package of [`oubliette`](../oubliette). The
project ships a single consolidated changelog in
[`oubliette/CHANGELOG.md`](../oubliette/CHANGELOG.md); this file records the
changes scoped to this package.

## 1.0.0

* **New recoverable error codes: `decrypt_interrupted` and `unsupported_version`.**
  A `KeyStoreException` at `doFinal` on the authenticated decrypt path (the
  keymaster operation opened before the unbounded biometric prompt can be
  pruned system-wide during it) now surfaces as `decrypt_interrupted` — a
  transient, retryable condition — instead of folding into the fatal
  `decrypt_failed`. A blob whose scheme version is newer than this reader
  (app downgrade: rollback, sideload) surfaces as `unsupported_version` —
  upgrade the app; the data is intact. Neither should ever be answered with
  destructive recovery.
* **Write-side payload cap.** The read path's per-field limit (64 Ki base64
  chars, ~48 KiB decoded) is now enforced symmetrically when building the
  `EncryptedPayload` at store time, so an oversized secret fails the write up
  front instead of storing a blob every later read would reject as corrupt.
* **The plugin manifest declares `USE_BIOMETRIC`.** The platform
  `BiometricPrompt#authenticate` requires it, and this plugin deliberately
  avoids androidx (whose manifest would have merged it in). It is now declared
  in the plugin's own `AndroidManifest.xml` and manifest-merged into every
  consumer, so the authenticated profiles no longer break at runtime in apps
  that forgot the permission.
* **`userAuthenticationRequired` is required in the Dart facade** (no
  fail-open `false` default on `Keystore.generateKey`), matching its sibling
  security flags (`strongBox`, `requireHardwareBacking`) and the Kotlin side's
  mandatory-args contract.
* **In-flight biometric prompts are cancelled on activity/engine detach.** The
  prompt's `CancellationSignal` is published to the plugin and force-cancelled on
  activity destroy, configuration-change (rotation), and engine teardown. This
  closes the window where an OEM that fails to fire `ERROR_CANCELED` on activity
  destruction would leave an encrypt-path plaintext unwiped until process death:
  the forced cancel routes through the existing `onError` finalizer (plaintext
  wipe) and fails the Dart Future. Still no timeout — a live prompt waits on the
  user indefinitely; only a real lifecycle event triggers cancellation.
* **`biometricOnly` flag removed.** The advisory, no-op `biometricOnly`
  parameter is gone from `Keystore.encrypt`/`decrypt` — the prompt's
  authenticator set is derived authoritatively from the key's `KeyInfo`, so the
  flag could never influence anything. Callers must drop the argument.
* **`userAuthenticationRequired` and `requireHardwareBacking` are required (no
  native default).** Both previously defaulted to `false` in the plugin's
  arg-parsing — a fail-open default for security-critical generation flags.
  They now error with `bad_args` when absent, matching `strongBox` /
  `invalidatedByBiometricEnrollment`; the Dart facade always sends them, so the
  contract is unchanged for in-tree callers.

* **BiometricPrompt authenticators are derived from the key, not the caller
  (closes the `biometricOnly` coupling footgun).** The authenticating
  encrypt/decrypt paths now read the key's own `KeyInfo`
  (`getUserAuthenticationType()`, API 30 = minSdk) and restrict the prompt to
  match: a biometric-only key (enrollment-invalidated → `AUTH_BIOMETRIC_STRONG`
  only) always gets a `BIOMETRIC_STRONG`-only prompt, and a credential-capable
  key gets the `DEVICE_CREDENTIAL` fallback. The Dart `biometricOnly` flag is
  now advisory only — it can no longer disagree with the key, so a mismatched
  caller can no longer trigger an opaque post-PIN cipher failure. **Fail-closed:**
  if the key requires auth but its authenticator type is unreadable (or the
  authenticating path is used on a non-auth key), the prompt is refused with a
  new `key_auth_type_unknown` error rather than shown with a guessed set. The
  security never silently weakens (a biometric-only key is never downgraded to
  accept device credential).
* **Test harness fix:** the JVM unit tests now bind to JUnit 5 via
  `kotlin-test-junit5`. Previously `kotlin-test` (JUnit4-default) ran under
  `useJUnitPlatform()` with no engine on the classpath, so the append-only
  `SchemeRegistry` contract tests were silently not executed.
* **Build hygiene:** dropped the unused `mockito-core` test dependency and the
  legacy `package` attribute from `AndroidManifest.xml` (AGP 9 errors on it; the
  namespace is declared in `build.gradle`).

First release. Android Keystore AES-256-GCM facade with a versioned,
self-describing `EncryptedPayload`.

* **AES-256-GCM via the Android Keystore** with a fresh hardware-randomized
  96-bit nonce per message (`setRandomizedEncryptionRequired(true)`); the key
  never leaves the TEE/StrongBox.
* **Versioned `EncryptedPayload` (scheme v1)** with an append-only
  `SchemeRegistry`: a shipped scheme version is never removed or mutated, so old
  blobs always decrypt by their on-disk version.
* **Frozen, forward-compatible JSON envelope** (`version`, `nonce`,
  `ciphertext`, `aad`, snake_case `key_alias`) — readers ignore unknown fields.
  Committed golden vectors fail CI on any format drift.
* **Hardened deserialization:** `EncryptedPayload.fromMap` rejects a version
  below 1, empty nonce/ciphertext, and non-base64 fields with a descriptive
  `FormatException` instead of letting corruption reach the cipher as an opaque
  `decrypt_failed`.
* **StrongBox fail-closed:** `strongBox: true` on a device without StrongBox
  throws `strongbox_unavailable` — never a silent TEE downgrade.
* **Hardware-backing check (opt-in via the **required** `requireHardwareBacking` flag):**
  when set, key generation verifies the key is in secure hardware (`KeyInfo`:
  `getSecurityLevel()` on API 31+, `isInsideSecureHardware` on API 30) and
  deletes/refuses a software key with `hardware_unavailable`. Off by default so
  the library runs on software-only keystores (emulators); real devices are
  hardware-backed regardless.
* **AAD bound end-to-end** and applied natively; on-disk metadata is verify-only.
  The scheme `version` is bound into the AES-GCM AAD, so a rewritten version
  fails the tag (no scheme downgrade).
