# Oubliette

An [oubliette](https://en.wikipedia.org/wiki/Oubliette) is a secret dungeon whose only entrance is a trapdoor in the ceiling. Once something goes in, it's meant to be forgotten. A fitting name for a storage that locks secrets away in hardware-backed storage.

<img src="oubliette.png" alt="Oubliette definition" width="300">

<sub>Image credit: [idlecartulary.com](https://idlecartulary.com/2025/11/24/bathtub-review-oubliette-n-0-1/)</sub>

| Platform | Backing store |
|----------|--------------|
| iOS | [Keychain Services](https://developer.apple.com/documentation/security/keychain_services) |
| macOS | System Keychain (traditional file-based, no entitlements required) |
| Android | [Android Keystore](https://developer.android.com/training/articles/keystore) (AES-256-GCM) + `SharedPreferences` |
| Linux | [Secret Service](https://specifications.freedesktop.org/secret-service/latest/) via [libsecret](https://gnome.pages.gitlab.gnome.org/libsecret/) (gnome-keyring / KWallet) — **software tier, not hardware-backed** |


## Quick start

```dart
import 'dart:convert';
import 'dart:typed_data';

import 'package:oubliette/oubliette.dart';

final storage = Oubliette(
  android: const AndroidSecretAccess.onlyUnlocked(strongBox: false),
  darwin: const DarwinSecretAccess.onlyUnlocked(secureEnclave: false),
);

final mnemonic = Uint8List.fromList(utf8.encode('zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong'));
await storage.store('mnemonic', mnemonic);

final transaction = [1, 2, 3, 4, 5]; // some bitcoin transaction bytes

final signature = await storage.useAndForget('mnemonic', (bytes) async {
  final mnemonicWords = utf8.decode(bytes);
  final mnemonic = Mnemonic.fromSentence(mnemonicWords);
  final signature = sign(transaction, mnemonic);
  return signature;
} );
```

> **Recommended defaults:** Use `secureEnclave: true` on Darwin and
> `strongBox: true` on Android for hardware-backed key protection.
>
> StrongBox is **fail-closed**: requesting `strongBox: true` on a device with no
> StrongBox secure element throws `strongbox_unavailable` rather than silently
> downgrading to the TEE. Callers willing to accept TEE must opt in explicitly:
>
> ```dart
> final strongBox = await Keystore().isStrongBoxAvailable();
> final storage = Oubliette(
>   android: AndroidSecretAccess.onlyUnlocked(strongBox: strongBox),
>   darwin: const DarwinSecretAccess.onlyUnlocked(secureEnclave: true),
> );
> ```

## Key Design Decisions

### Use-and-Forget, Not Read

There is no `read()`. Consumers must use `useAndForget(key, action)`, which retrieves the secret, passes it to a callback, then zeroes the buffer in a `finally` block. The happy path is the secure path.

### No Update — Store and Trash

`store(key, value)` throws if the key already exists. `trash(key)` then `store(key, newValue)`. This eliminates race conditions around partial updates and avoids `SecItemUpdate` silently changing accessibility attributes.

`trash(key)` removes only the stored data — not the underlying cryptographic key. On Android, the encrypted payload is deleted from `SharedPreferences` but the Keystore key is retained. On Darwin, the Keychain item is deleted but the Secure Enclave key pair (when enabled) is retained. On both platforms the cryptographic key is shared across all secrets in a given security profile — deleting it would break every other secret encrypted under the same profile.

### Destroy a Whole Profile — `purge()`

`purge()` is the profile-level counterpart to `trash`: it removes **every** secret in the profile *and* its key material (on Android, the Keystore key; on Darwin the shared Secure Enclave key is retained, since its identity may be shared with a sibling profile and it is never invalidated). It is the **only** API that destroys key material, and only when you call it.

The primary use is recovering a profile wedged by a permanently-invalidated key (`KeyInvalidatedException` — e.g. a new biometric was enrolled, or the secure lock screen was removed): the dead key blocks re-provisioning, so

```dart
await vault.purge();   // wipe the dead key + its (already-unreadable) blobs
await vault.init();    // mint a fresh key
```

`purge()` is profile-scoped: purging one profile never touches another, even when one profile's prefix nests inside another's — the reserved `U+001D` separator between prefix and key makes slot ownership exact. It is also the "forget everything" / logout primitive. **Irreversible** — there is no recovery of the wiped secrets.

### Security Profiles, Not Flags

| Profile | Meaning |
|---------|---------|
| `evenLocked` | Accessible even when the device is locked (after first unlock). |
| `onlyUnlocked` | Accessible only while the device is unlocked. |
| `authenticated` | Requires user authentication (biometric, PIN, pattern, or password). Survives enrollment changes. |
| `authenticatedFatal` | Requires user authentication. Permanently invalidated if biometric enrollment changes. |
| `custom` | Full manual control for advanced use cases. |

Hardware-backing (`strongBox` on Android, `secureEnclave` on Darwin) is always an explicit, required choice — never a hidden default.

Each named profile owns a **distinct default storage prefix** (`oubliette_only_unlocked_`, `oubliette_authenticated_`, …). The storage slot key is `prefix + U+001D + key` — a reserved separator (rejected in prefixes and keys) whose position encodes the prefix length, so the same logical key stored under two profiles can never collide and `purge()` ownership stays exact even when prefixes nest. Slot isolation is a security boundary, not a convenience. `custom` requires a unique prefix and key alias and rejects any that collide with a reserved profile's.

### Fail-Closed Authentication

Asking for protection and silently getting none is the worst failure mode in a secret store, so every "did the platform actually attach the protection?" question is answered by erroring, never by falling through:

- **Darwin** (`secItemAdd`): if `authenticationRequired` is set but the `SecAccessControl` cannot be created, the item is **not** stored — the call returns an error instead of writing an unprotected item.
- **Android** (`KeyGenParameterSpec`): the authenticated profiles always call `setUserAuthenticationRequired(true)` + `setUserAuthenticationParameters(...)`. This requires API 30 (Android 11), which is the enforced `minSdk` floor — there is no API level on which the requirement is silently dropped.
- **StrongBox**: requesting `strongBox: true` without a StrongBox element throws `strongbox_unavailable` (see Quick start).

### The Stored Blob Is Never Trusted to Decrypt Itself

On Android the encrypted payload lives in attacker-writable `SharedPreferences`. Its `aad` and `key_alias` fields are therefore **verify-only**: on `fetch`, the library recomputes the expected AAD (the full slot, `prefix + U+001D + key`) and key alias from the live profile and compares them against the blob. A mismatch — a payload relocated to another slot, or its decrypting key downgraded — throws `PayloadTamperException`. Only the scheme `version` is read from the blob to drive decryption (it must be, to select the scheme); it is **bound into the AES-GCM AAD**, so a rewritten version fails the GCM tag and can never force a downgrade across schemes that share key material.

### The Key Never Leaves Hardware

On both platforms, the cryptographic key is hardware-bound. On Android the AES-256-GCM key lives in the Keystore (TEE or StrongBox). On iOS/macOS with Secure Enclave enabled, a P-256 key pair is generated inside the SE chip. The private key never enters the application process. On a real device the Android Keystore key is hardware-backed (TEE/StrongBox) automatically; for the software-only case (emulators, some rooted/old devices) you opt into strict mode with `requireHardwareBacking: true` (a required choice — no default; pass `false` to allow software-only keystores like emulators), which makes key **generation** verify secure-hardware backing (`KeyInfo`) and refuse with `hardware_unavailable` rather than keep a software key — recommended for wallet seeds.

The Secure Enclave key's identity encodes **everything that scopes it** — service, accessibility, and access group — in a single collision-free, length-prefixed tag (`com.oubliette.enclave.…`). Two differently-scoped keys can never share a tag (so `service=nil`, `service=""`, and `service="default"` are all distinct), the SE access-control policy is threaded from the profile's accessibility (not hardcoded), and changing any scoping input regenerates the key rather than silently reusing the old policy.

### One Key per Profile, Hardware-Randomized Nonces

Each security profile uses a single AES-256-GCM key with a fresh hardware-randomized 96-bit nonce per message (`setRandomizedEncryptionRequired(true)`). This is the strongest AEAD the Android Keystore offers. Random-nonce GCM stays safe below ~2³² messages **per key** ([NIST SP 800-38D]); for this library's volume — a handful of secrets per profile, re-encrypted on the rare store/trash/store cycle — that ceiling is never approached.

[NIST SP 800-38D]: https://csrc.nist.gov/pubs/sp/800/38/d/final

### Versioned Encryption (Android)

Every `EncryptedPayload` carries its scheme version. A future V2 can be introduced without breaking existing data — old payloads continue to decrypt with V1. No migration, ever. On Darwin, where Keychain items have no envelope of their own, each stored blob is prefixed with a frozen 1-byte format header serving the same role, so the same guarantee holds on iOS/macOS.

```json
{
  "version": 1,
  "nonce": "base64...",
  "ciphertext": "base64...",
  "aad": "oubliette_only_unlocked_␝my_key",
  "key_alias": "oubliette_only_unlocked"
}
```

(The `␝` in `aad` is the reserved **U+001D** slot separator — the slot is
`prefix + ␝ + key`.) `aad` and `key_alias` are persisted for diagnostics and are
**verify-only** on read (see "The Stored Blob Is Never Trusted to Decrypt
Itself" above) — they are
never used to choose how the blob is decrypted.

The encrypted payload is stored in standard `SharedPreferences` (not `EncryptedSharedPreferences`, which is deprecated). Since the payload is already AES-256-GCM encrypted by the Android Keystore, double-encryption would add complexity without meaningful security benefit.

### No Cloud Sync

On Darwin, `kSecAttrSynchronizable` is explicitly set to `false` on every keychain query. Secrets never leave the device via iCloud Keychain. This is deliberate: mnemonic phrases must remain device-local to prevent cloud-based exfiltration. Every profile is device-local by construction — the `custom` constructor rejects non-`ThisDeviceOnly` accessibility (`whenUnlocked`/`afterFirstUnlock`), so a secret can't ride an encrypted backup to another device either.

### macOS: Two Keychains, Explicit Choice

Legacy file-based keychain (`useDataProtection = false`) works without code signing but **cannot enforce authentication** — the file-based keychain rejects `kSecAttrAccessControl`, so an authenticated write fails closed with `errSecParam` (-50). The Data Protection keychain (`useDataProtection = true`) is the only macOS backend that supports authentication (Touch ID/Face ID/password) and requires code signing + the `keychain-access-groups` entitlement. The `authenticated`/`authenticatedFatal` profiles set Data Protection automatically; with `custom`, pairing `authenticationRequired: true` with `useDataProtection: false` on macOS will not work.

### Linux: Secret Service, a Software Tier

On Linux, secrets are stored in the freedesktop Secret Service via `libsecret`
(gnome-keyring, KWallet, or any `org.freedesktop.secrets` provider). This is a
**software-encrypted** keyring protected by your login password — the Linux
analog of the macOS legacy file-based keychain, and **not** hardware-backed.
Each secret is stored as a **distinct Secret Service item** keyed by its slot
(`prefix + U+001D + key`), never as one shared blob, so per-slot isolation,
fail-closed `store`, and prefix-exact `purge()` all behave like the other
platforms. The value carries the same frozen 1-byte format header as Darwin.

Because the keyring is unlocked at login and readable by any same-user process,
and because there is no hardware-backed or per-operation-auth tier on the Linux
desktop, `LinuxSecretAccess` deliberately exposes only `evenLocked`,
`onlyUnlocked`, and `custom` — there is **no** `authenticated`/`authenticatedFatal`
profile and no hardware-backing knob (requesting one would only ever fail
closed). A missing or locked keyring surfaces as a typed `BackendUnavailableException`
/ `KeyringLockedException`, never silent data loss. See `SECURITY.md` → *Linux
(Secret Service tier)* for the full posture. The `linux` argument to the
`Oubliette` factory is optional (defaults to `onlyUnlocked`) since Linux has no
security-relevant alternative to choose.

### Memory Hygiene at Every Layer

Sensitive buffers are zeroed in Swift (`Data`), Kotlin (`ByteArray`), and Dart (`Uint8List`). This is best-effort. The following sources of residual plaintext are outside our control:

- **GC compaction**: the Dart VM may relocate objects during garbage collection. Previous memory locations retain stale bytes until overwritten.
- **Method Channel buffers**: Flutter's `FlutterStandardTypedData` creates intermediate copies during native-to-Dart serialisation. These buffers are unmodifiable and cannot be zeroed.
- **OS-level leaks**: swap, memory-mapped files, and core dumps may persist plaintext on disk.
- **Compiler dead-store elimination**: in theory the JIT/AOT compiler could optimise away the `fillRange(0)` call, though this is unlikely in practice for `Uint8List`.

These limitations are inherent to managed runtimes. If you need guaranteed memory erasure, a native-only implementation with `mlock` / `SecureZeroMemory` is required.

`store(key, value)` cannot zero the caller's `value` buffer — the caller owns it and may need it afterwards. The library only wipes the buffers it owns: the native-side copies and the `useAndForget` read buffer.

## Errors

All typed failures extend the sealed `OublietteException`, which exposes a
single decision-critical flag: **`recoverable`**.

- `recoverable == true` → transient. Retry (often after the user unlocks the
  device or re-authenticates). **Never** call `purge()` in response — you would
  destroy data a retry would have returned.
- `recoverable == false` → the secret behind this operation is unreadable. The
  only way forward is the explicit, data-destroying recovery: `purge()` →
  `init()` → have the user re-enter the secret.

| Exception (`recoverable`) | Native code | Meaning / reaction |
|---------------------------|-------------|--------------------|
| `AuthenticationFailedException` (`true`) | `auth_failed`, `auth_error`, `auth_cancelled`, `interaction_not_allowed`, `device_locked`, `biometry_lockout`, `key_auth_type_unknown` | User cancelled/failed the prompt, the device was locked, or biometry is locked out (unlock with the passcode to re-enable). Data is intact — offer a retry. Never purge. |
| `BackendUnavailableException` (`true`) | `encrypt_failed`, `detached`, `delete_entry_failed` (Android); `sec_item_add_failed`, `sec_item_delete_failed` (Darwin); `backend_unavailable`, `secret_service_error`, `keyring_timeout` (Linux) | An environmental backend/IO failure — the Keychain/Keystore/Secret Service was unavailable or returned a transient error. The secret itself is intact: fix the environment and retry. **Never** purge. |
| `KeyringLockedException` (`true`) | `keyring_locked` (Linux) | The Secret Service keyring is locked. Unlock it (gnome-keyring / KWallet) and retry. **Never** purge. |
| `PayloadTamperException` (`false`) | — (Dart, Android) | Stored blob's slot metadata doesn't match the live profile (relocated/tampered). Treat the secret as compromised; overwrite via `trash()` + `store()`. |
| `PayloadCorruptException` (`false`) | — (Dart) | Stored blob is malformed (bad version/nonce/ciphertext, or unknown Darwin format header). On-disk corruption; recover the slot via `trash()` + `store()` or `purge()`. |
| `KeyInvalidatedException` (`false`) | `key_invalidated` | Key permanently invalidated by the OS — a new biometric enrolled (`authenticatedFatal`) or the secure lock screen removed/reset (**any** authenticated profile). Secrets under it are unrecoverable; recover with `purge()` then `init()`. |
| `KeyNotFoundException` (`false`) | `key_not_found` | The profile key alias is gone (Keystore cleared, or restored from a backup without key material) but a blob remains — the blob is unreadable. Recover with `purge()` then `init()`. |
| `DecryptionFailedException` (`false`) | `decrypt_failed`, `se_decrypt_failed` | The key is intact but this blob failed authenticated decryption (corruption/tamper/key mismatch). Overwrite the slot or `purge()`. |

The native codes above are platform-specific (e.g. `se_decrypt_failed` and `interaction_not_allowed` are Darwin-only; `device_locked`/`key_auth_type_unknown`/`key_invalidated`/`key_not_found` are Android-only; `biometry_lockout` is Android + Darwin) — match on the typed exception, not the code.

Errors still surfaced as raw `PlatformException` (operational, not data-semantic):
`strongbox_unavailable` (StrongBox requested but absent — pre-flight with
`isStrongBoxAvailable()`), `hardware_unavailable` (only when
`requireHardwareBacking: true` — the generated key is not secure-hardware-backed;
the key is deleted and generation fails), `already_exists` (a value/key exists —
`trash()` first, or treat as idempotent success during `init()`), and the
various `*_failed` generation/IO codes.

## Platform requirements

- **Android:** `minSdkVersion` **30** (Android 11) — required so `setUserAuthenticationParameters` is always available; on API 29 the authenticated profiles would silently generate a key with no user-auth requirement. Apps using `authenticated`/`authenticatedFatal` profiles must declare `<uses-permission android:name="android.permission.USE_BIOMETRIC" />`. StrongBox (dedicated SE chip) is optional and explicitly requested via the `strongBox` parameter (fail-closed).
- **iOS:** iOS 13+. Apps using `authenticated`/`authenticatedFatal` profiles must add an `NSFaceIDUsageDescription` string to `Info.plist`, or Face ID prompts crash.
- **macOS:** macOS 10.15+. The legacy file-based keychain works with no code signing. The `authenticated`/`authenticatedFatal` profiles use the Data Protection keychain, which requires code signing and the `keychain-access-groups` entitlement.

## Toolchain (reproducible builds)

Downstream wallet pipelines that need reproducible builds should pin to this
matrix. The repo pins what it can; bit-identical output is ultimately the
consuming app's pipeline responsibility.

| Tool | Version | Pinned by |
|------|---------|-----------|
| Flutter | 3.44.1 | `.fvmrc` |
| Dart | 3.12.1 (via Flutter pin) | every `pubspec.yaml` (`sdk: 3.12.1`) |
| AGP | 9.2.0 (built-in Kotlin) | `keystore/android/build.gradle`, example |
| Gradle | 9.5.1 (+ `distributionSha256Sum`) | wrapper `gradle-wrapper.properties` |
| Kotlin | 2.4.0 | `build.gradle` |
| JDK | 17 (vendor per CI) | `compileOptions` / `jvmTarget` |
| Xcode / Swift | Swift 6.0 | document per release (`.xcode-version` recommended) |
| CocoaPods | 1.16.2 | `Podfile.lock` |
| compile SDK / build-tools | 36 / 36.0.0 | `build.gradle` |

NDK is not applicable — this plugin has no native C/C++; the engine's NDK is
fixed by the Flutter version. Runtime deps are kept to official packages only
(`shared_preferences`, `meta`); `dart_mappable` and the `build_runner` codegen
step were removed.

## Running the example

```bash
cd oubliette/example && flutter run
```

## Integration tests

```bash
cd oubliette/example && flutter test integration_test/
```

## Packages

This repository is a monorepo with three packages:

| Package | Description |
|---------|-------------|
| [`oubliette/`](oubliette/) | Main plugin — platform-agnostic `init`/`store`/`useAndForget`/`trash`/`exists`/`purge` API over `Uint8List` values. Delegates to `keychain` and `keystore` via `default_package`. |
| [`keychain/`](keychain/) | Standalone Flutter plugin wrapping the iOS/macOS Keychain (`SecItem` API). Shared Swift source for both platforms. |
| [`keystore/`](keystore/) | Standalone Flutter plugin wrapping the Android Keystore. Versioned encryption schemes (currently AES-256-GCM v1) with `EncryptedPayload` serialisation. |

`keychain` and `keystore` can be used independently if you only need direct access to the native APIs.

## AI agent guidance

See [AGENTS.md](AGENTS.md) for constraints that AI coding assistants should follow.
