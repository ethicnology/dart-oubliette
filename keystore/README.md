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
- The encrypted blob is stored by the caller (the `oubliette` package puts it in
  `SharedPreferences`). The payload is already AES-256-GCM encrypted, so it does
  not need a second encryption layer.
- `version` is the only field a decrypt path reads from an untrusted blob — it
  selects the scheme. `aad` is supplied by the caller, not the blob.
- Cipher init runs under a per-call daemon-thread timeout (no shared executor);
  plaintext is wiped on every exit path.

## Requirements

`minSdk` 30 (Android 11): required so `setUserAuthenticationParameters` is always
available for authenticated keys.
