# secretservice

Flutter plugin exposing the freedesktop [Secret Service](https://specifications.freedesktop.org/secret-service/latest/)
on **Linux** via [libsecret](https://gnome.pages.gitlab.gnome.org/libsecret/),
with a typed Dart facade. Part of the [oubliette](https://github.com/ethicnology/dart-oubliette)
monorepo (the Linux sibling of `keychain` for Darwin and `keystore` for Android).

> **Software tier.** The Secret Service is a software-encrypted keyring
> (gnome-keyring, KWallet, …) protected by your login password — it is **not**
> hardware-backed, and it is readable by any process running as your user once
> unlocked. This is the Linux analog of the macOS legacy file-based keychain.
> See oubliette's `SECURITY.md`.

## Design vs `flutter_secure_storage`

`flutter_secure_storage` stores **all** key/value pairs as one JSON blob in a
single Secret Service item, rewritten on every write — concurrent writers
clobber each other and there is no per-slot isolation. `secretservice` instead
stores **one item per slot** (keyed by the `slot` attribute), so reads/writes
are independent, `store` fails closed on a duplicate slot, and a profile purge
deletes exactly its own items by prefix.

## Build dependency

`libsecret-1 >= 0.20.4` and its dev headers:

- Debian/Ubuntu: `sudo apt install libsecret-1-dev`
- Fedora: `sudo dnf install libsecret-devel`
- Arch: `sudo pacman -S libsecret`

A running Secret Service provider (a keyring daemon) is required at runtime; a
headless/server session without one fails closed with `backend_unavailable`.

## API

```dart
final service = SecretService();
await service.add('slot', bytes);   // throws PlatformException(already_exists) if present
final bytes = await service.get('slot');
final present = await service.contains('slot');
await service.delete('slot');
await service.deleteByPrefix('profile');
```
