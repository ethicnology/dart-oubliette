# secret_service

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
clobber each other and there is no per-slot isolation. `secret_service` instead
stores **one item per slot** (keyed by the `slot` attribute), so reads/writes
are independent, `store` fails closed on a duplicate slot, and a profile purge
deletes exactly its own items by prefix.

## Build dependency

`libsecret-1 >= 0.20.4` and its dev headers:

- Debian/Ubuntu: `sudo apt install libsecret-1-dev`
- Fedora: `sudo dnf install libsecret-devel`
- Arch: `sudo pacman -S libsecret`

A running Secret Service provider (a keyring daemon) is required at runtime; a
headless/server session without one fails closed with `backend_unavailable`. A
present-but-locked collection surfaces `keyring_locked` (recoverable: retry once
unlocked) or `auth_cancelled` if the user dismisses the unlock prompt — a
locked/erroring keyring is **never** reported as empty.

## Threat model & limitations (software tier)

- **Not hardware-backed.** Values are encrypted by the keyring provider with a
  key derived from your login password. Any process running as your user can
  read them once the keyring is unlocked; there is no per-app sandbox and no
  per-operation authentication gate (no `SecAccessControl` / Keystore-bound
  `setUserAuthenticationRequired` analog).
- **No per-item AAD.** The Secret Service has no authenticated-additional-data
  channel like an AEAD cipher. Item *attributes* (the `slot` string, `fmt`) are
  stored **in the clear** for lookup and are **not** cryptographically bound to
  the value — a local attacker with write access could move/relabel an item.
  Integrity of the value itself is whatever the oubliette envelope provides;
  this backend adds none.
- **Blocking calls.** libsecret's `*_sync` calls run on the platform (GTK main)
  thread and block it for the duration of the D-Bus round-trip — including, on a
  locked keyring, the interactive unlock prompt (bounded by a ~20 s watchdog so
  a headless session cannot hang forever). Keep stored values small and avoid
  bursts of calls on a frame-critical path.

## API

```dart
final service = SecretService();
await service.add('slot', bytes);   // throws PlatformException(already_exists) if present
final bytes = await service.get('slot');
final present = await service.contains('slot');
await service.delete('slot');
await service.deleteByPrefix('profile');
```
