# Oubliette vs. `flutter_secure_storage`

An honest, scoped comparison. `flutter_secure_storage` (FSS) is a mature,
general-purpose, widely-used plugin and the right default for many apps.
Oubliette is narrower on purpose: hardware-backed secrets for wallet-grade apps,
with **upgrade-safety and explicit security posture** as first-class goals.

Claims about Oubliette below are backed by code and tests in this repo. Claims
about FSS describe its documented/observed behaviour and known issues; verify
against the FSS version you use before relying on them.

## Summary

| Concern | `flutter_secure_storage` | Oubliette |
|---|---|---|
| Android at-rest | historically `EncryptedSharedPreferences` (`androidx.security.crypto`, deprecated); **removed in FSS v10**, which moved to its own RSA-OAEP + AES-GCM scheme | Direct Android Keystore AES-256-GCM; SharedPreferences holds **only** ciphertext |
| iOS/macOS at-rest | Keychain item | Keychain item, optional Secure Enclave ECIES wrap |
| Upgrade data-loss | Recurring class of reported issues (key reset / unreadable data after upgrades, OEM/backup edge cases) | **Designed against it**: versioned + frozen format, append-only scheme registry, frozen slot naming, golden vectors fail CI on drift |
| On-disk format versioning | None exposed | Per-blob scheme `version` (Android) + 1-byte format header (Darwin) |
| Security profiles | Per-call `IOSOptions`/`AndroidOptions`; easy to vary accidentally | Four named profiles (`evenLocked`/`onlyUnlocked`/`authenticated`/`authenticatedFatal`) pinning a fixed flag set; `custom` for the rest |
| Hardware backing | StrongBox best-effort (retries without it on failure) | Hardware-backed automatically on real devices; StrongBox/SE never silently downgrade; **opt-in `requireHardwareBacking`** verifies + refuses a software-only keystore at key generation (`hardware_unavailable`) |
| Per-operation auth | Supported via options | Bound to the Keystore key / `SecAccessControl`; auth is cryptographic, not cosmetic |
| Error model | Largely `PlatformException` strings | Sealed `OublietteException` with a `recoverable` flag so callers never `purge()` recoverable data |
| Key invalidation | Often surfaces as opaque failure / silent loss | Typed `KeyInvalidatedException`; key never auto-deleted; explicit `purge()` recovery |
| Memory hygiene | Returns `String` | `Uint8List` + `useAndForget` zeroes the buffer in a `finally` |
| API surface | Broad (`read`/`write`/`readAll`/`deleteAll`/…) | Deliberately small (`init`/`store`/`fetch` via `useAndForget`/`trash`/`exists`/`purge`); no `read`, no `update` |
| Scope / maturity | General-purpose, battle-tested, huge install base | Narrow, wallet-focused, new |

## Where Oubliette is deliberately stricter

- **No silent decisions.** It never auto-deletes/regenerates keys, never
  silently downgrades hardware backing, and never re-keys or resets on error.
  Every destructive action is an explicit `purge()`. See `SECURITY.md`.
- **Upgrade contract is enforced, not promised.** Hardcoded golden vectors and
  an append-only scheme registry make "old data stays readable" a CI gate, not a
  hope. Slot naming uses a reserved separator so `purge()` ownership is exact
  even for nested custom prefixes.
- **Fail-closed everywhere.** StrongBox/SE/auth requested-but-unavailable is an
  error, never a quiet fallback to a weaker store.

## Where FSS is the better choice

- You need a **general key/value secure store** with `readAll`/`deleteAll`,
  broad platform coverage (incl. Linux/Windows/web), and a large community.
- You want **string values** and a minimal mental model rather than profiles,
  `Uint8List`, and `useAndForget`.
- You need a **proven, widely-deployed** dependency today; Oubliette is new and
  its native paths are validated on CI/device rather than by years of field use.

## Honest limitations of Oubliette

- New and less battle-tested than FSS.
- Android + iOS/macOS only (no Linux/Windows/web).
- Hardware-backed crypto, biometric, and on-device upgrade behaviour are
  validated on CI/device — not from a pure-Dart checkout.
- `authenticatedFatal` and SE/StrongBox strictness can surface more "the user
  must re-enter the secret" cases by design; that is the security trade, made
  explicit rather than hidden.
