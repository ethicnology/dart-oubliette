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

## Requirements

`minSdk` 30 (Android 11): required so `setUserAuthenticationParameters` is always
available for authenticated keys.
