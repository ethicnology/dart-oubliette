# keystore

A standalone Flutter plugin wrapping the Android Keystore (AES-256-GCM), with
versioned `EncryptedPayload` serialisation (currently scheme v1).

This package is part of the [Oubliette](https://github.com/ethicnology/dart-oubliette)
monorepo. Most apps should use the higher-level `oubliette` package, which adds
security profiles, the decrypt trust boundary, slot isolation, and the
`useAndForget` pattern. Use `keystore` directly only if you need raw Keystore
access.

## API

```dart
final keystore = Keystore();

final strongBox = await keystore.isStrongBoxAvailable();
await keystore.generateKey(
  alias: 'my_key',
  unlockedDeviceRequired: true,
  strongBox: strongBox,             // fail-closed: throws strongbox_unavailable if true & absent
);

final payload = await keystore.encrypt(alias: 'my_key', plaintext: bytes, aad: 'slot');
final plain = await keystore.decrypt(
  version: payload.version,
  alias: 'my_key',
  ciphertext: payload.ciphertext,
  nonce: payload.nonce,
  aad: 'slot',
);
```

## Notes

- **StrongBox is fail-closed.** Requesting `strongBox: true` on a device without
  a StrongBox element throws `strongbox_unavailable` — no silent TEE fallback.
- **Hardware backing (opt-in).** Pass `requireHardwareBacking: true` to
  `generateKey` and it verifies the new key is in secure hardware (`KeyInfo`:
  `getSecurityLevel()` on API 31+, `isInsideSecureHardware` on API 30), deleting
  and refusing a software key with `hardware_unavailable`. Required (no default):
  pass `false` to allow software keystores (emulators), `true` to refuse. Real
  devices are hardware-backed regardless.
- The encrypted blob is stored by the caller (the `oubliette` package puts it in
  `SharedPreferences`). The payload is already AES-256-GCM encrypted, so it does
  not need a second encryption layer.
- `version` is the only field a decrypt path reads from an untrusted blob — it
  selects the scheme — and it is **bound into the AES-GCM AAD**, so a rewritten
  version fails the tag (no scheme downgrade). `aad` is supplied by the caller,
  not the blob.
- Cipher init runs under a per-call daemon-thread timeout (no shared executor);
  plaintext is wiped on every exit path.

## Native error-code surface (stable contract)

Every failure crosses the `MethodChannel` as a `PlatformException` whose `code`
is one of the values below. These codes are a **stable contract** consumed by the
higher-level `oubliette` package, which maps them to its typed exceptions — do
not rename an existing code; add new ones (and update the oubliette mapping).
Messages deliberately never interpolate the alias (it can encode a tenant/user
id) — see the diagnostic-hygiene note in `EncryptionScheme.kt`.

| Code | Recoverable? | Meaning |
|------|--------------|---------|
| `bad_args` | yes | A required argument was missing or wrong-typed. |
| `already_exists` | n/a | A key already exists under the alias (the ensure-key path treats this as success). |
| `key_not_found` | no | No key exists under the alias. |
| `key_invalidated` | **no — data is permanently unreachable** | Enrollment changed on a biometric-only key, the secure lock screen was removed, or the key blob is unloadable (post-OTA keymaster mismatch). Recovery is the caller's explicit, data-destroying decision; the library never deletes the key itself. |
| `key_auth_type_unknown` | yes (retryable) | A prompt was requested but the allowed-authenticator set could not be read from the key's `KeyInfo`, or the authenticating path was used on a non-auth key. Fail-closed: the prompt is refused rather than shown with a guessed set. |
| `strongbox_unavailable` | no | `strongBox: true` but StrongBox is absent — never a silent TEE downgrade. |
| `hardware_unavailable` | no | `requireHardwareBacking: true` but the new key landed in the software keystore (it is deleted). |
| `auth_cancelled` | yes | The user cancelled the BiometricPrompt (incl. the negative button). |
| `auth_error` | yes | A non-cancellation auth error (no activity, dying window, OEM auth error). |
| `auth_failed` | yes | Auth reported success but the authenticated cipher was null. |
| `detached` | yes | The plugin detached mid-operation; the Future is failed explicitly rather than hung. |
| `encrypt_failed` / `decrypt_failed` | yes | Any other crypto failure not classified above. A deferred-invalidation failure is reclassified to `key_invalidated`, never left here. |
| `generate_key_failed` | yes | Any other key-generation failure. |
| `contains_alias_failed` / `delete_entry_failed` / `is_strongbox_available_failed` | yes | Keystore-load/teardown failures on the respective calls. |

## Requirements

`minSdk` 30 (Android 11): required so `setUserAuthenticationParameters` is always
available for authenticated keys.
