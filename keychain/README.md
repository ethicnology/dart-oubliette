# keychain

A standalone Flutter plugin wrapping the iOS/macOS Keychain (`SecItem` API),
with optional Secure Enclave encryption. Shared Swift source for both platforms.

This package is part of the [Oubliette](https://github.com/ethicnology/dart-oubliette)
monorepo. Most apps should use the higher-level `oubliette` package, which adds
security profiles, slot isolation, and the `useAndForget` pattern. Use
`keychain` directly only if you need raw `SecItem` access.

## API

```dart
final keychain = Keychain(config: KeychainConfig(
  service: 'com.example.app',
  accessibility: KeychainAccessibility.whenUnlockedThisDeviceOnly,
  useDataProtection: false,
  authenticationRequired: false,
  biometryCurrentSetOnly: false,
  authenticationPrompt: null,
  secureEnclave: false,
  accessGroup: null,
));

await keychain.secItemAdd('alias', bytes);     // throws already_exists if present
final out = await keychain.secItemCopyMatching('alias');
final present = await keychain.contains('alias');
await keychain.secItemDelete('alias');
await keychain.ensureEnclaveKeyPair();          // when secureEnclave: true
```

## Notes

- There is no `secItemUpdate` — items are immutable once stored. `SecAccessControl`
  is bound at add time. To replace a value, delete then add.
- `kSecAttrSynchronizable` is always `false`: items never sync to iCloud.
- `secItemAdd` is **fail-closed**: if `authenticationRequired` is set but the
  access control can't be created, the item is not stored.
- The Secure Enclave key identity is scoped by service + accessibility + access
  group via a collision-free tag.

## Requirements

iOS 13+ / macOS 10.15+. The Data Protection keychain (`useDataProtection: true`,
used by auth profiles on macOS) requires code signing and the
`keychain-access-groups` entitlement.
