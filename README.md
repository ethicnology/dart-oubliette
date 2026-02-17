# Oubliette

Are you tired of flutter_secure_storage migration failures that end up wiping your data? 

Oubliette is an alternative solution that delegates to each platform's native secrets API.

An [oubliette](https://en.wikipedia.org/wiki/Oubliette) is a secret dungeon whose only entrance is a trapdoor in the ceiling, once something goes in, it's meant to be forgotten. A fitting name for a vault that locks secrets away in hardware-backed storage.

<img src="oubliette.png" alt="Oubliette definition" width="300">

<sub>Image credit: [idlecartulary.com](https://idlecartulary.com/2025/11/24/bathtub-review-oubliette-n-0-1/)</sub>


| Platform | Backing store |
|----------|--------------|
| iOS | [Keychain Services](https://developer.apple.com/documentation/security/keychain_services) |
| macOS | System Keychain (traditional file-based, no entitlements required) |
| Android | [Android Keystore](https://developer.android.com/training/articles/keystore) (AES-256-GCM) + `SharedPreferences` |

## Packages

This repository is a monorepo with three packages:

| Package | Description |
|---------|-------------|
| [`oubliette/`](oubliette/) | Main plugin — platform-agnostic `store`/`useAndForget`/`trash`/`exists` API over `Uint8List` values. Delegates to `keychain` and `keystore` via `default_package`. |
| [`keychain/`](keychain/) | Standalone Flutter plugin wrapping the iOS/macOS Keychain (`SecItem` API). Shared Swift source for both platforms. |
| [`keystore/`](keystore/) | Standalone Flutter plugin wrapping the Android Keystore. Versioned encryption schemes (currently AES-256-GCM v1) with `EncryptedPayload` serialisation. |

`keychain` and `keystore` can be used independently if you only need direct access to the native APIs.

## Quick start

```dart
import 'package:oubliette/oubliette.dart';

final storage = Oubliette(
  android: const AndroidSecretAccess.onlyUnlocked(strongBox: false),
  darwin: const DarwinSecretAccess.onlyUnlocked(),
);

await storage.storeString('api_token', 'eyJ...');
final token = await storage.useStringAndForget<String>('api_token', (v) async => v);
await storage.trash('api_token');
```

## Platform requirements

- **Android:** `minSdkVersion` 29+
- **iOS:** No extra setup
- **macOS:** No extra setup (traditional keychain, no code signing required)

## Running the example

```bash
cd oubliette/example && flutter run
```

## Integration tests

```bash
cd oubliette/example && flutter test integration_test/
```
