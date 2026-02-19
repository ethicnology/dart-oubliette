# AGENT.md — AI Agent Guidance

## Do not change without discussion

- **SharedPreferences usage is intentional.** Android's `EncryptedSharedPreferences`
  (from `androidx.security.crypto`) is deprecated. The project encrypts at the
  Keystore layer; SharedPreferences stores only ciphertext (`EncryptedPayload` JSON).
  Do not suggest replacing SharedPreferences with EncryptedSharedPreferences or
  any other storage backend.

- **Native code is minimal by design.** The Kotlin and Swift layers exist only to
  call platform APIs (Android Keystore, iOS/macOS Keychain, Secure Enclave).
  Business logic belongs in Dart. Do not propose moving logic into native code.

- **No iCloud / cloud sync for keychain items.** `kSecAttrSynchronizable = false`
  is set deliberately in `KeychainQueries.swift`. Secrets are device-local only.
  Do not suggest enabling sync.

- **No `read()` API.** The `useAndForget` pattern is the only way to access secrets.
  Do not suggest adding a plain `read` method.

- **No `update()` / upsert API.** `store()` throws if the key exists. The caller
  must `trash()` then `store()`. This avoids `SecItemUpdate` silently changing
  accessibility attributes. Do not suggest adding update/upsert.

- **`secureEnclave` and `strongBox` are always explicit, never hidden defaults.**
  Do not add logic that silently enables hardware backing.

## Build & test

```bash
# Run integration tests (on device/emulator)
cd oubliette/example && flutter test integration_test/

# Run the example app
cd oubliette/example && flutter run
```
