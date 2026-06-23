# Oubliette

Cross-platform secure storage for Flutter — stores small secrets (mnemonics, API
tokens) in each platform's hardware-backed key store behind one typed Dart API.

An [oubliette](https://en.wikipedia.org/wiki/Oubliette) is a secret dungeon whose
only entrance is a trapdoor in the ceiling: once something goes in, it is meant
to be forgotten — a fitting name for storage that locks secrets away in hardware.

| Platform | Backing store |
|----------|--------------|
| iOS | [Keychain Services](https://developer.apple.com/documentation/security/keychain_services), optionally wrapped by a Secure Enclave P-256 key |
| macOS | System Keychain (Secure Enclave optional) |
| Android | [Android Keystore](https://developer.android.com/training/articles/keystore) (AES-256-GCM, TEE/StrongBox) + `SharedPreferences` |
| Linux | [Secret Service](https://specifications.freedesktop.org/secret-service/latest/) via [libsecret](https://gnome.pages.gitlab.gnome.org/libsecret/) — **software tier, not hardware-backed** |

## Quick start

```dart
import 'dart:convert';
import 'dart:typed_data';

import 'package:oubliette/oubliette.dart';

final storage = Oubliette(
  android: const AndroidSecretAccess.onlyUnlocked(strongBox: false),
  darwin: const DarwinSecretAccess.onlyUnlocked(secureEnclave: false),
);

await storage.store(
  'mnemonic',
  Uint8List.fromList(utf8.encode('zoo zoo zoo ... wrong')),
);

// Read with `useAndForget`: the plaintext is zeroed after your callback returns.
final signature = await storage.useAndForget('mnemonic', (bytes) async {
  return sign(transaction, Mnemonic.fromSentence(utf8.decode(bytes)));
});
```

> **Recommended defaults:** `secureEnclave: true` on Darwin and `strongBox: true`
> on Android for hardware-backed key protection. StrongBox is **fail-closed** —
> requesting it on a device without a StrongBox secure element throws
> `strongbox_unavailable` rather than silently downgrading to the TEE.

## Design highlights

- **Use-and-forget, not read.** There is no plain `read()`; secrets are exposed
  only through `useAndForget`, which wipes the plaintext after the callback.
- **Fail-closed.** Requesting authentication or StrongBox yields the protection
  or a clear, typed error — never a silent downgrade.
- **The library never destroys key material** except via the explicit `purge()`.
- **Per-profile slot isolation**; on Android the scheme version is bound into the
  AES-GCM AAD for tamper-evidence against data-dir writes.

See the [repository README](https://github.com/ethicnology/dart-oubliette#readme)
for the full guide, the [security policy](https://github.com/ethicnology/dart-oubliette/blob/main/SECURITY.md)
for the threat model, and the [example app](example/) for end-to-end usage.

## License

MIT — see [LICENSE](https://github.com/ethicnology/dart-oubliette/blob/main/LICENSE).
