# Changelog — `keystore`

`keystore` is the Android-only sub-package of [`oubliette`](../oubliette). The
project ships a single consolidated changelog in
[`oubliette/CHANGELOG.md`](../oubliette/CHANGELOG.md); this file records the
changes scoped to this package.

## 1.0.0

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
* **Hardware-backing verified, fail-closed:** every key is checked
  (`KeyInfo`: `getSecurityLevel()` on API 31+, `isInsideSecureHardware` on API 30) at generation **and on every encrypt/decrypt**;
  a software-backed key is deleted/refused with `hardware_unavailable`, so an
  orphaned software key can never be silently reused.
* **AAD bound end-to-end** and applied natively; on-disk metadata is verify-only.
  The scheme `version` is bound into the AES-GCM AAD, so a rewritten version
  fails the tag (no scheme downgrade).
