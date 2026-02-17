# oubliette

Flutter plugin to store sensitive data (bytes) on iOS, macOS, and Android using each platform's secure backing store.

- **iOS:** Values are stored in the [Keychain](https://developer.apple.com/documentation/security/keychain_services) (generic password items). Data is protected by the system; no extra encryption layer in the plugin. With the `biometric` and `biometricFatal` profiles, data is additionally encrypted using a Secure Enclave P-256 key via `eciesEncryptionCofactorX963SHA256AESGCM`.
- **macOS:** Values are stored in the system Keychain (traditional file-based keychain). No entitlements or code signing are required; the plugin works out of the box. Data is encrypted at rest and protected by the system.
- **Android:** A non-exportable AES-256-GCM key is created in [Android Keystore](https://developer.android.com/training/articles/keystore). Values are encrypted in native code with that key and the encrypted payload is persisted via `SharedPreferences`. The secret never sits in plain text in app storage. **Important:** you must configure backup exclusion rules in your app to prevent `SharedPreferences` data from being included in backups (see [Android backup exclusion](#android-backup-exclusion) below).

## API

Values are **bytes** (`Uint8List`). Keys are strings.

| Method | Description |
|--------|-------------|
| `store(key, value)` | Store bytes under `key`. **Fails** if the key already exists — call `trash` first to replace. |
| `useAndForget(key, action)` | Fetch bytes, pass them to `action`, then zero the buffer. Returns `null` if key not found. |
| `trash(key)` | Remove the entry for `key`. |
| `exists(key)` | Return whether a value exists for `key`. |
| `storeString(key, value)` | Convenience: store a UTF-8 string (same as `store(key, utf8.encode(value))`). |
| `useStringAndForget(key, action)` | Convenience: fetch as UTF-8 string, pass to `action`, then zero the underlying buffer. |

Stored keys are namespaced with a `prefix` (default: `oubliette`), so the stored key is `prefix + key`. The prefix is per platform: set `IosOptions(prefix: '...')` for iOS/macOS and `AndroidOptions(prefix: '...', keyAlias: '...')` for Android. On Android, a single Keystore key is used for all entries (default alias: `default_key`).

## Usage

```dart
import 'dart:convert';
import 'package:oubliette/oubliette.dart';

final storage = Oubliette(
  android: const AndroidSecretAccess.onlyUnlocked(strongBox: false),
  darwin: const DarwinSecretAccess.onlyUnlocked(),
);

// Store bytes
await storage.store('api_token', Uint8List.fromList(utf8.encode('eyJ...')));

// Read and zero — the buffer is wiped after the callback returns
final decoded = await storage.useAndForget<String>('api_token', (bytes) async {
  return utf8.decode(bytes);
});

// Or use string helpers
await storage.storeString('api_token', 'eyJ...');
final token = await storage.useStringAndForget<String>('api_token', (value) async {
  return value;
});

await storage.trash('api_token');
```

## Android backup exclusion

Encrypted payloads are stored in `SharedPreferences`. By default, Android may back up this data to Google servers. To prevent leaking ciphertext into backups, add a `dataExtractionRules` XML to your app:

**1. Create `android/app/src/main/res/xml/data_extraction_rules.xml`:**

```xml
<?xml version="1.0" encoding="utf-8"?>
<data-extraction-rules>
  <cloud-backup>
    <exclude domain="sharedpref" path="."/>
  </cloud-backup>
  <device-transfer>
    <exclude domain="sharedpref" path="."/>
  </device-transfer>
</data-extraction-rules>
```

**2. Reference it in your `AndroidManifest.xml`:**

```xml
<application
    android:dataExtractionRules="@xml/data_extraction_rules"
    ...>
```

This excludes all shared preferences from cloud backup and device-to-device transfer. The Android Keystore key is already non-exportable and device-bound, so backed-up ciphertext would be unusable anyway, but excluding it avoids unnecessary data leakage.

## Setup

Add the dependency:

```yaml
dependencies:
  oubliette:
    path: ../path/to/oubliette  # or use git/version
```

- **Android:** Requires `minSdkVersion` 29 or higher (Keystore API used by the plugin).
- **iOS:** No extra setup. Keychain is available by default.
- **macOS:** No extra setup. The plugin uses the traditional keychain (no `keychain-access-groups` entitlement or development team required). To use the Data Protection keychain (iOS-style) instead, add the `keychain-access-groups` entitlement and sign the app with a team (free Apple ID may work for development).

## Example

The `example/` app demonstrates saving, loading, and deleting a secret with a simple UI and a short explanation of where data is stored on each platform.

Run it with:

```bash
cd example && flutter run
```

## Integration tests

Integration tests (including `store`, `useAndForget`, `useStringAndForget`, `trash`, `exists`) live in `example/integration_test/`. Run them from the example app on a device or simulator:

```bash
cd example && flutter test integration_test/
```

## License

See the repository for license information.
