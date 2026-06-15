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
  this backend adds none. (The Darwin/Android backends bind the storage-slot
  version into the cipher's AAD; the Secret Service has no equivalent, so this
  backend deliberately carries none.)
- **App scoping is by attribute, not by schema.** The schema is declared
  `SECRET_SCHEMA_NONE`, so libsecret does **not** match the implicit
  `xdg:schema` name — items match purely on attributes. Every store writes
  `fmt=v1`, and every lookup/delete/search matches on it, so an item is treated
  as ours only when both `slot` **and** `fmt` match. A foreign application that
  merely reuses an attribute named `slot` therefore cannot collide with, be read
  as, or be deleted as one of our items.
- **Transport session.** `secret_service_get_sync` negotiates a DH-encrypted
  session (`dh-ietf1024-sha256-aes128-cbc-pkcs7`) when the provider supports it
  (gnome-keyring and KWallet do), so the secret is **not** in cleartext on the
  bus in the common case; it falls back to the `plain` algorithm only against a
  daemon that lacks DH. Either way, transport encryption guards only against
  passive bus snooping — it does **not** protect against the keyring daemon
  itself or any other process running as your user (which can read the value
  once the keyring is unlocked).
- **Blocking calls.** libsecret's `*_sync` calls run on the platform (GTK main)
  thread and block it for the duration of the D-Bus round-trip — including, on a
  locked keyring, the interactive unlock prompt. **Every** call that can trigger
  a prompt is bounded by a ~20 s watchdog (a detached timer that cancels the
  call's `GCancellable`): the warmup unlock, and each per-operation
  lookup/store/clear/search/delete — so a re-locked keyring or a
  `SECRET_SEARCH_UNLOCK`-reached collection cannot hang the thread forever. Keep
  stored values small and avoid bursts of calls on a frame-critical path.
- **Native secret buffers are wiped; transit copies are not.** Every
  secret-bearing buffer the native plugin *owns* is freed with
  `secret_password_free`, which wipes it (libsecret allocates lookup results in
  non-pageable secure memory and zeroes on free): the value returned by every
  `secret_password_lookup_sync` in `contains`/`read`/`write` is wiped, not merely
  `g_free`d. The `value` passed to `store` is libsecret-owned once handed off and
  is wiped by libsecret internally. What the plugin does **not** control: the
  value also transits the method channel — the engine's codec buffers, the native
  `FlValue` copy and the Dart `String`/`Uint8List` are ordinary GC/heap memory
  that is **not** zeroed on free (Dart's GC gives no reliable zeroization hook). A
  memory dump while (or shortly after) a secret is in flight can recover it —
  inherent to the platform-channel transport, not something the native layer can
  close.
- **Warmup unlocks only the *default* collection.** All items this plugin
  writes live there. The purge search passes `UNLOCK`, so an externally created
  item in *another*, locked collection — or a keyring that re-locks (daemon
  restart) between the warmup and the operation — can trigger an unlock prompt on
  the operation itself. That per-operation prompt is now **also** bounded by the
  same ~20 s watchdog (the cancellable is threaded through every
  lookup/store/clear/search/delete), so it can no longer hang the platform thread
  past the timeout; a timed-out call fails closed with `secret_service_error`
  rather than blocking or being read as empty.
- **No atomic put-if-absent.** `add`'s duplicate check is lookup-then-store;
  the Secret Service offers no compare-and-set. A concurrent **external**
  writer can race it, and `CreateItem(replace=true)` replaces on exact
  attribute match — so the fail-closed `already_exists` guarantee is
  per-process. Likewise an external process can create a *second* item with
  identical attributes, in which case a lookup returns an arbitrary one. (Such
  an attacker can already read every secret — see the first bullet.)

## API

```dart
final service = SecretService();
await service.add('slot', bytes);   // throws PlatformException(already_exists) if present
final bytes = await service.get('slot');
final present = await service.contains('slot');
await service.delete('slot');
await service.deleteByPrefix('profile');
```
