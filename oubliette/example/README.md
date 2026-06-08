# oubliette_example

Example app for the [`oubliette`](../) plugin. It exercises the four security
profiles (`evenLocked` / `onlyUnlocked` / `authenticated` / `authenticatedFatal`)
plus a `custom` profile, and demonstrates `store` / `useAndForget` / `trash` /
`exists` / `purge` against the real platform Keystore (Android) and Keychain
(iOS/macOS).

> ⚠️ Demo only. For clarity the UI holds fetched secrets as `String` in widget
> state — a real app must keep secrets in `Uint8List`, read them via
> `useAndForget`, and never place them in UI state, logs, or the clipboard.

## Run

```bash
cd oubliette/example
fvm flutter run            # device/emulator; authenticated profiles need an enrolled credential
```

## Tests

```bash
fvm flutter test                       # widget smoke test
fvm flutter test integration_test/     # on a device/emulator — real Keystore/Keychain
```

Biometric / Secure-Enclave / StrongBox paths require a real device — see the
project `SECURITY.md` and the CI matrix.
