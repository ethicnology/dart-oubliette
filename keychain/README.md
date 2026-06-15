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
- Secure Enclave wrapping and `authenticationRequired` are **independent
  layers**: the keychain item's `SecAccessControl` gates *access* (biometry /
  passcode on read), while the SE key (`.privateKeyUsage` only) binds the
  ciphertext to this device's hardware. A profile may use either, both, or
  neither.

## Error codes

Native failures surface as `PlatformException`s with stable codes (the
`oubliette` layer branches on them):

| code | meaning | recoverable |
|------|---------|-------------|
| `already_exists` | `store()` on an existing alias (items are immutable) | n/a |
| `se_key_missing` | SE-profile item present but its SE key is gone (e.g. after device migration) — ciphertext is permanently unreadable | no |
| `se_key_fetch_failed` | SE key lookup errored (entitlement / locked / domain) — key may be intact | yes, retry |
| `se_key_gen_failed` / `se_encrypt_failed` / `se_decrypt_failed` | SE generate / ECIES encrypt / decrypt failed | yes (nothing stored on the write-side codes) |
| `access_control_failed` | `authenticationRequired` set but `SecAccessControl` could not be created — fail-closed, nothing stored | yes |
| `auth_cancelled` / `auth_failed` | user cancelled / failed the auth prompt on read (biometry *lockout* also folds into `auth_failed` — `SecItemCopyMatching` does not expose the `LAError` domain, so it is indistinguishable from a single failed attempt by `OSStatus`) | yes |
| `interaction_not_allowed` | device locked | yes, retry when unlocked |
| `missing_entitlement` | code-signing / `keychain-access-groups` defect | no (fix the build) |
| `se_requires_device_only_accessibility` | SE paired with a non-`*ThisDeviceOnly` class | no (fix config) |
| `macos_auth_requires_data_protection` | macOS auth without `useDataProtection: true` | no (fix config) |

## Requirements

iOS 13+ / macOS 10.15+. The Data Protection keychain (`useDataProtection: true`,
used by auth profiles on macOS) requires code signing and the
`keychain-access-groups` entitlement.
