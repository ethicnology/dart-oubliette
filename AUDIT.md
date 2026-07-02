# Security & Release Audit — dart-oubliette

**Date:** 2026-07-02 (second audit — supersedes the previous AUDIT.md of the same date)
**Scope:** Full repository — `oubliette/` (Dart core, all platform facades, `PassphraseVault`), `keystore/` (Android/Kotlin), `keychain/` (iOS/macOS/Swift), `secret_service/` (Linux), all tests, CI, package metadata, and every cryptographic claim in `README.md`, `SECURITY.md`, `COMPARISON.md`, and `PLATFORM_DEEP_DIVE.md`.
**Method:** Five independent expert reviews run in parallel — (1) iOS/macOS Keychain & Secure Enclave, (2) Android Keystore & BiometricPrompt, (3) Flutter/Dart architecture & federated-plugin wiring, (4) applied cryptography (payload formats, KDF, cross-platform consistency, docs-vs-code claims), (5) pub.dev release engineering (dry-run publishes, analyze, format, full test runs actually executed). Each reviewer first re-verified the previous audit's fixes in code, then hunted for new issues from angles the previous audit did not cover. Every finding below was verified against actual code (or an actually-executed command), not inferred. Findings that two reviewers independently reported are merged and noted.

---

## Executive summary

**The previous audit's findings are genuinely fixed.** All five reviewers independently spot-checked the prior findings relevant to their domain — every code fix (H-1, M-1…M-14, L-1…L-15, and the Info items) was verified as landed in the current tree, with regression tests where promised. Two Info-level items were deliberately carried over unfixed (synchronous Argon2id on the calling isolate; the `_maxIterations = 64` envelope work ceiling) and remain accepted trade-offs.

**No Critical findings. No plaintext-disclosure, auth-bypass, or slot-forgery path was found by any reviewer.** The cryptographic core was re-verified sound: Android's AES-256-GCM with the scheme version injectively bound into the AAD, `CryptoObject`-bound biometrics with authenticators derived from the key's own `KeyInfo`, the never-create-on-read Secure Enclave key lifecycle, `kSecAttrSynchronizable = false` on every Darwin query including enumeration, the vault's header-authenticating envelope with fresh salt per store, and fail-closed behavior enforced at every layer.

The new findings cluster in four themes:

1. **Release blocker (mechanical):** the package name `keychain` is already taken on pub.dev by an unrelated abandoned 2020 package, which makes the entire family unpublishable under current names (REL-1).
2. **Cross-profile isolation gaps reachable by ordinary configuration** — the "purge() of one profile never touches another" guarantee can be violated on Darwin via nil-`service` profiles (DAR-1) and Unicode-equivalent prefixes (DAR-3), and on Android via the shared key alias behind prefix-overridden named profiles (AND-2) and unguarded custom-profile prefix collisions (AND-3/DART-7).
3. **Error-taxonomy regressions of the class the previous audit fixed** — three new paths steer a compliant caller toward the irreversible `purge()` for a transient or user-recoverable condition: locked-device decrypt on authenticated Android profiles (AND-1), a mistyped vault passphrase (DART-2), and the nil-service Darwin cross-service fetch (part of DAR-1).
4. **Documentation overclaims** — the post-quantum paragraph is wrong for the Secure Enclave tier (CRYPTO-1), the "hardware-encrypted at rest" headline does not hold for macOS legacy-keychain profiles (CRYPTO-2/DAR-2), and the pub.dev-facing `oubliette/README.md` quick-start does not compile (REL-2).

| Severity | Count |
|----------|-------|
| Critical | 0 |
| Release blocker | 1 (pub.dev name collision) |
| Medium | 7 |
| Low | 14 |
| Info | ~12 (recorded; hardening notes / accepted trade-offs) |

### Verdicts by reviewer

| Layer | Verdict |
|---|---|
| Darwin native (Keychain/SE) | ready-with-caveats — fix or document DAR-1/DAR-2 before advertising multi-service and macOS non-SE use; DAR-3 is a two-line fix worth taking now |
| Android native (Keystore) | ready-with-caveats — land AND-1 and AND-2 before a release wallet apps build on |
| Dart layer & plugin architecture | ready-with-caveats — gate on DART-1 and DART-2; rest is fast-follow polish |
| Cryptography | sound-with-caveats — no exploitable defect; caveats are documentation-level (CRYPTO-1/2/3) |
| Release mechanics | not-ready as-is; ship-after-fixes once REL-1 is resolved (all four `pub publish --dry-run` pass with 0 warnings; analyze/format clean; 278 tests pass) |

### Recommended release gate

Fix before first publish: **REL-1** (name), **AND-1**, **AND-2**, **DAR-1**, **DAR-3**, **DART-1**, **DART-2**, **REL-2**, **REL-3**. All are small and localized except REL-1, which is a rename or a pub.dev name-transfer request. Everything else below can ship as fast-follow.

---

## Release blocker

### REL-1 — Package name `keychain` is already taken on pub.dev
`https://pub.dev/api/packages/keychain` returns HTTP 200: `keychain 0.0.8`, published 2020-06-16 by github.com/kirklink/keychain (an unrelated env-variable utility, pre-null-safety, abandoned). Publishing `keychain 1.0.0` requires uploader rights the project doesn't have, and `oubliette/pubspec.yaml` depends on `keychain: ^1.0.0`, so the **whole family is unpublishable under current names**. `oubliette`, `keystore`, and `secret_service` all return 404 (available). Options: (a) email pub.dev support to request the abandoned name under their transfer policy (discretionary, can take weeks — start now if desired); (b) rename (e.g. `oubliette_keychain`) and update the package name, `oubliette`'s dependency, the podspec `s.name`/Package.swift target, the `default_package:` entries for ios/macos in `oubliette/pubspec.yaml`, the example Podfile.locks, and doc references. Publish order is dependency-forced either way: the three leaves first, then `oubliette` (already noted in a pubspec comment).

---

## Medium findings

### DAR-1 — Darwin: `service == nil` profiles match, fetch, and purge across every service
`KeychainQueries.swift:129-134` (and `:321-331`, `:391-399` for enumeration) set `kSecAttrService`/`kSecAttrAccessGroup` only when non-nil, and every named `DarwinSecretAccess` constructor defaults `service` to `null` (`darwin_secret_access.dart:123-207`). `SecItemAdd` without a service stores under the default service, but every read/delete/enumeration query with `service == nil` matches **any** service. Consequences, all verified against the query-construction code: (1) `purge()` on a nil-service profile enumerates the app's entire generic-password class and deletes every account under its prefix **regardless of service** — destroying a sibling `onlyUnlocked(service: 'tenantA')` profile's data and violating the "purge() of one profile never touches another" pledge in the service dimension; (2) `fetch()` with `kSecMatchLimitOne` is nondeterministic when the same account exists under two services, and for SE profiles the nil-service instance can fetch tenantA's ciphertext and fail to decrypt it with its own (nil-tag) SE key → `se_decrypt_failed` → `DecryptionFailedException(recoverable: false)` — steering a compliant caller to `purge()` an intact secret; (3) `trash()` deletes all matches across services. **Fix:** make nil-service writes and reads symmetric (always send an explicit default service sentinel, or set `kSecAttrService = ""` on queries when null); at minimum document that mixing nil-service and service-scoped profiles with a shared prefix breaks isolation.

### DAR-2 / CRYPTO-2 — macOS legacy keychain: device-locality and lock-state guarantees are documented but not enforced for `evenLocked`/`onlyUnlocked` (found independently by two reviewers)
On macOS, `kSecAttrAccessible` (including the `*ThisDeviceOnly` classes) is only honored by the data-protection keychain. The two non-authenticated named profiles default to `useDataProtection: false` (`darwin_secret_access.dart:50-56`, `:123-156`), so their items land in the legacy file-based login keychain: software-encrypted under a key derived from the login password, readable whenever the login keychain is unlocked (typically the whole session, independent of screen lock), and the keychain file rides Time Machine/Migration Assistant to another Mac where it decrypts with the login password. This contradicts the unconditional claims at `darwin_secret_access.dart:25-36` ("never … restored to another device"), `SECURITY.md:17-20` ("Secrets at rest are hardware-encrypted"), and `PLATFORM_DEEP_DIVE.md:107,210-214,481`. SE profiles are materially protected regardless (the SE key cannot migrate — restored ciphertext fails closed), and authenticated profiles are forced onto the DP keychain, so the gap is exactly `evenLocked`/`onlyUnlocked` with `secureEnclave: false` on macOS. **Fix:** qualify the class doc and the three doc claims ("iOS, and macOS data-protection keychain only; macOS legacy-keychain profiles are the software tier — describe alongside Linux"), and consider defaulting `useDataProtection: true` on macOS for the non-auth profiles (with the entitlement caveat) or steering macOS users toward `secureEnclave: true`.

### DAR-3 — Darwin: prefix filtering uses Unicode canonical equivalence, not bytes — cross-profile purge with mixed NFC/NFD prefixes
`KeychainQueries.swift:343-344` and `:411-413` filter enumeration results with Swift `String.hasPrefix`, which compares under Unicode canonical equivalence, while every store/fetch/delete query on `kSecAttrAccount` is code-point-exact and `slot.dart` allows non-ASCII prefixes. Two custom profiles with canonically-equivalent but differently-composed prefixes (NFC `café_` vs NFD `cafe\u{301}_`) are distinct slots to store/fetch yet match each other's filter: `purge()` on one enumerates and deletes the other's items, and `keys()` + `substring(owned.length)` (`darwin_oubliette.dart:355`, UTF-16 code units) returns garbage logical keys. The codebase itself treats composition as significant (`SecureEnclave.swift:90-96` warns NFC/NFD service strings mint distinct SE keys), so this is an internal inconsistency. Exotic precondition, high impact (silent cross-profile destruction). **Fix (two lines):** filter on UTF-8 bytes — `Array(account.utf8).starts(with: Array(prefix.utf8))` — for both the prefix and `excludePrefixes` checks.

### AND-1 — Android: locked-device `Cipher.init` on authenticated profiles lands in fatal `decrypt_failed` (purge-steering)
`BiometricAuth.kt:244-254` deliberately omits the `isDeviceLocked()` reclassification that the plain path has (`KeystorePlugin.kt:381-394`), on the stated premise that `Cipher.init` for a per-op-auth key "performs no crypto" and doesn't hit the UnlockedDeviceRequired gate. That premise is wrong: `Cipher.init` on an AndroidKeyStore cipher issues keystore2 `begin()` (which produces the operation challenge the `CryptoObject` binds), keystore2 enforces `UNLOCKED_DEVICE_REQUIRED` at `begin` time, and on Android 14+ UDR keys are additionally superencrypted while locked. Both authenticated profiles set `unlockedDeviceRequired: true` (`android_secret_access.dart:251,284`). A `fetch()` fired while the screen is locked (foreground service, FCM handler, user locks the phone as the call starts — the activity is still attached, so the no-activity guard doesn't intercept) throws a bare `KeyStoreException` → `decrypt_failed` → `DecryptionFailedException(recoverable: false)`, whose documented remedy purges an intact secret. This is exactly the M-4/M-5 taxonomy failure class the previous audit fixed elsewhere. **Fix:** make `KeystorePlugin.isDeviceLocked()` `internal` and apply the same probe in this catch (`if (isDeviceLocked()) "device_locked" else decryptErrorCode(e)`), mirroring `handleDecrypt`.

### AND-2 — Android: prefix-overridden named profiles share one Keystore key; `purge()` of one destroys the other's data
Every named `AndroidSecretAccess` constructor accepts a `prefix` override while pinning the key alias (`android_secret_access.dart:201-290`), and `purge()` deletes the shared alias after removing only its own prefix's slots (`android_oubliette.dart:305-326`). Two tenants on `evenLocked(prefix: 'user1_')` / `evenLocked(prefix: 'user2_')` both encrypt under `oubliette_even_locked`; user 1's logout `purge()` (per SECURITY.md's own guidance) deletes the shared key, and user 2's blobs become permanently undecryptable — worse, user 2's next `init()` re-mints a fresh key so the loss surfaces as fatal `decrypt_failed` instead of a diagnosable `key_not_found`. This violates SECURITY.md's "purge() of one profile never touches another" (`SECURITY.md:63-65`), which is argued purely in slot terms and ignores key material. The project's own integration tests use exactly this override pattern, so it is expected usage. **Fix:** generalize the L-2 registry to a per-isolate `Map<alias, prefix>` claimed by *every* constructor — same alias + same prefix idempotent, same alias + different prefix throws; longer-term consider deriving distinct aliases per prefix (breaking, needs migration), and correct SECURITY.md.

### DART-1 / AND-6 — Custom-alias registry rejects legitimate re-construction; the shipped example app crashes on it (found independently by two reviewers)
`android_secret_access.dart:352-361` — the L-2 fix registers the alias in a `Set<String>` for the isolate's lifetime and throws `ArgumentError` on any second construction, without distinguishing "conflicting security domain" from "identical profile re-created". Constructing the same custom profile twice with byte-identical config — widget rebuild, DI re-resolution, retry after failed `init`, hot reload preserving static state — throws, even though the backends explicitly support multiple instances of one profile (static `_locks` "spans separate instances", `android_oubliette.dart:22-26`). A discarded instance permanently bricks its alias for the isolate (`resetCustomAliasRegistry()` is `@visibleForTesting` only). Concrete repro in the repo: `custom_profile_page.dart:114-123` constructs the access inside a `MaterialPageRoute` builder — tapping Launch a second time on Android crashes the example. **Fix:** store `alias → canonical config fingerprint`; identical config re-claims idempotently, differing config throws (composes with the AND-2 registry generalization).

### DART-2 — Vault: wrong passphrase surfaces as `DecryptionFailedException` (`recoverable: false`), steering a compliant caller to purge over a typo
`passphrase_vault.dart:471-476` maps every `InvalidCipherTextException` — wrong passphrase, wrong key, or tampered blob — to `DecryptionFailedException`, whose `recoverable == false` contract (`errors.dart:26-29`) documents "the only way forward is `purge()` → `init()` → re-enter". A mistyped passphrase, the single most common failure for a passphrase vault, is fully recoverable by retyping, yet lands in the bucket whose documented remedy destroys the blob — the exact misclassification class the previous audit's M-4/M-5/M-6 purged from the platform layers, reintroduced at the vault layer (`DecryptionFailedException`'s doc doesn't even mention the wrong-passphrase cause). **Fix:** a distinct `WrongPassphraseOrTamperedException` (or a `mayBeWrongPassphrase: true` field set only in passphrase mode) documented as "re-prompt the user before considering recovery"; keyring-mode tag failures keep the fatal classification.

---

## Major release findings (doc-only, but first-day-visible)

### REL-2 — The pub.dev-facing `oubliette/README.md` quick-start does not compile
`oubliette/README.md:26` calls `const AndroidSecretAccess.onlyUnlocked(strongBox: false)` but the constructor (`android_secret_access.dart:219-223`) requires `requireHardwareBacking`. The repo-root README was fixed (previous M-12); the package-level README — the one pub.dev renders and the first code every visitor copies — drifted. **Fix:** add `requireHardwareBacking: false, // allow software keystores (emulators)`; also consider marking the snippet's undefined `sign(...)`/`Mnemonic.fromSentence` as pseudo-code.

### REL-3 — (Resolved by this document) the previous AUDIT.md listed fixed findings as open
The prior AUDIT.md carried zero resolution annotations while every finding was in fact fixed, publicly advertising apparently-open Medium security issues. This file replaces it; the verification table below records the evidence.

---

## Low findings

### AND-3 / DART-7 — Two `custom` profiles may share a *prefix* (aliases guarded, prefixes not; all three platforms)
`android_secret_access.dart:295-362`, `darwin_secret_access.dart:252-259`, `linux_secret_access.dart:76-83` — the prefix is validated only against the four reserved prefixes and only the alias is registered. Two custom profiles with different aliases but an identical prefix share a slot namespace: `purge()` of one deletes the other's blobs, and on Android a cross-profile `fetch` surfaces `PayloadTamperException` ("treat the secret as compromised") for what is a configuration collision. **Fix:** a prefix registry mirroring the alias registry, with the DART-1 identical-config allowance.

### AND-4 — Android: backup-restore surfaces as `decrypt_failed`, never the documented `KeyNotFoundException`, because `init()` regenerates a missing alias
`android_oubliette.dart:46-74` — `fetch()` deliberately skips `_ensureKey()` so a restored-without-key state surfaces as a clear `key_not_found`, but `init()` performs exactly that regeneration first, and the documented flow is init-at-startup. After an Auto Backup/D2D restore (prefs restored, Keystore keys not), `init()` mints a fresh key and every fetch fails as `AEADBadTagException` → fatal `decrypt_failed`; README.md:239's promised `KeyNotFoundException` row is unreachable. **Fix:** in `_ensureKey`, when the alias is absent but owned slots already exist in prefs, throw the typed `KeyNotFoundException` (or a distinct restored-without-key signal) instead of silently minting; or amend the README row.

### AND-5 — Android: plain (non-authenticated) decrypt path lacks the transient-`KeyStoreException` classification the authenticated path got
`KeystorePlugin.kt:381-394` vs `BiometricAuth.kt:61-72` — the M-5 `isTransientKeystoreInterruption` → `decrypt_interrupted` classifier applies only post-auth; a keystore-daemon death or operation pruning on the plain path lands in fatal `decrypt_failed` when the device is unlocked. The classifier already exists in the same module and already vetoes `AEADBadTagException`. **Fix:** run the `handleDecrypt` catch-all through it (after the `device_locked` probe).

### AND-7 — Android: no test exercises the U+001D slot key surviving a legacy SharedPreferences XML round-trip across process restart
Every stored prefs key embeds U+001D (`slot.dart:22`) and persists via the legacy platform `SharedPreferences` XML file; 0x1D is not a legal XML 1.0 character, AOSP's `FastXmlSerializer` writes sub-0x20 characters raw, and reload survival depends on `KXmlParser` leniency. Device behavior could not be verified from the repo — but the test gap is verified: all integration tests run in one process where the in-memory prefs cache serves every read, so a serialize→parse defect would surface only in production after process restart, and a legacy prefs parse failure discards the whole `FlutterSharedPreferences` file. **Fix:** a device test forcing reload from disk (kill/restart between store and fetch), or migrate to `SharedPreferencesAsync` (DataStore backend — no XML restrictions, durable awaited writes, also fixes the unchecked `setString` result at `android_oubliette.dart:116`).

### DAR-4 — Darwin: native zeroization is systematically COW-defeated; call-site comments overstate what `wipe()` achieves
Every actual `Data.wipe()` call site operates on shared storage: the write path's `var dataToStore = Data(data)` (`KeychainQueries.swift:251`) shares storage with the still-alive `payload`, so the wipes at `:254,259,261,279` zero a fresh COW copy while the real plaintext buffer survives; the read path's `rawData` is the bridged `NSData` still retained by the in-scope `item` (`KeychainPlugin.swift:354,364`), so the wipes at `:383,387,406,410,416` — including the plaintext case for non-SE profiles — are no-ops on the surviving buffer. The `wipe()` docstring itself explains the COW hazard; the call sites don't heed it. SECURITY.md's best-effort stance keeps this Low, but comments claiming "wipe discipline" describe zeroing that never touches the secret. **Fix:** copy into deliberately unique buffers where wiping is intended to be real, or downgrade the comments and delete the placebo wipes.

### DAR-5 — Darwin: ECIES algorithm identity is not bound into the frozen v1 blob format
The 1-byte format header (`darwin_oubliette.dart:42`) freezes layout but not cipher suite; the pre-release fixed-IV→variable-IV swap (commit `0b6b72f`) changed decryption semantics under the same header, proving a future algorithm change has no dual-read hook. No shipped data affected (1.0.0 is first release). **Fix:** document in `SecureEnclave.swift` that `enclaveAlgorithm` is frozen by format v1 (any change requires a header bump plus dual-algorithm reader); note the pre-release swap in the changelog.

### DAR-6 — Darwin: no Secure Enclave capability signal — SE-less hardware gets "environmental, retry"
On hardware with no SE (Intel Macs without T2, some simulators), `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave` fails permanently, lands in `se_key_gen_failed` → `BackendUnavailableException` ("fix the environment and retry") — a compliant caller retries forever instead of falling back to a non-SE profile. **Fix:** emit a distinct `se_unavailable` when a capability probe (e.g. CryptoKit `SecureEnclave.isAvailable`) says the SEP is absent, or expose `isSecureEnclaveAvailable()` on the facade.

### DAR-7 — Darwin: write-path auth-class statuses collapse into generic `sec_item_add_failed`
`SecItemAdd` of a `.userPresence`/`.biometryCurrentSet` item on a device with no passcode fails with an auth-class status but lands in generic `sec_item_add_failed` (`KeychainPlugin.swift:271-272` routes only through `statusFlutterError`), so the caller can't render "set a device passcode" — a first-run scenario for `authenticatedFatal`. **Fix:** route the `.completed(status)` fallback through `authStatusFlutterError` first, as the read path does.

### DART-3 — Interface doc contradicts implementation on cross-process duplicate stores
`oubliette.dart:104-110` says a cross-process race surfaces the native `already_exists`; the Darwin and Linux backends now translate it to the same `StateError` as the precheck (`darwin_oubliette.dart:131-137`, `linux_oubliette.dart:121-127`). Doc-only fix: both races surface as `StateError`.

### DART-4 — Linux: plaintext crosses the Dart layer as immutable, un-zeroable base64 `String`s
`secret_service.dart:85-91,97-114` — every Linux write and read creates a full base64 copy of the plaintext as a Dart `String` (immutable, alive until GC) alongside the decoded buffer that *is* zeroed. A deterministic library-created plaintext copy — a different class from the documented "GC copies" caveat — quietly weakening the vault's "both layers wipe" claim on Linux. **Fix:** send `Uint8List` over the channel (StandardMethodCodec and `FlValue` support typed data) and encode into a wipeable `gchar*` natively; at minimum document the Linux-specific exposure next to the wire-format note.

### DART-5 / DAR-8 / AND-10b — Null-protocol-reply handling is inconsistent across the three platform facades, and two land in wrong buckets
Same failure (native returns `null` where the contract says non-null), three outcomes: `keychain.dart:132-143` throws `keychain_contains_failed`, which is **unmapped** in `darwin_oubliette.dart:_mapError` — a raw `PlatformException` escapes `exists()`, breaking the typed-exception contract; `keystore.dart:8-13` `containsAlias` returns `result ?? false` — **fail-open** ("alias absent", steering `_ensureKey` toward regeneration); `keystore.dart:146-151` decrypt-null maps to fatal `DecryptionFailedException` (purge remedy) for a channel protocol violation; only `secret_service.dart:69-78,145-157` fails closed into a typed recoverable error (the correct model). **Fix:** synthesize codes mapping to `BackendUnavailableException` on all three; make `containsAlias` throw on null.

### DART-6 — `unsupported_version` maps to `BackendUnavailableException`, whose retry contract can never succeed
`android_oubliette.dart:224-225` — for an app rollback reading a v2 blob, no retry succeeds until the app is upgraded; a compliant retry loop spins forever (the same unwinnable-loop critique as the old M-6). Purge-avoidance is right, granularity is wrong. **Fix:** distinct `UnsupportedFormatVersionException` (or a `remedy` hint field) so callers can show "update the app".

### DART-8 — Facade leaks a platform-package type: `DarwinSecretAccess.toConfig()` is public API returning `KeychainConfig`
`darwin_secret_access.dart:277-287` — exists solely for `DarwinOubliette`'s constructor but is public and undocumented, welding the `keychain` package's type into `oubliette`'s public surface (a breaking change there becomes a breaking change here). **Fix:** mark `@internal`.

### CRYPTO-1 — SECURITY.md's post-quantum claim is false for the Darwin Secure Enclave tier
`SECURITY.md:257-263` claims the at-rest confidentiality primitive is AES-256 and that an SE-wrapped blob "is not a harvest-now-decrypt-later target". Verified against `SecureEnclave.swift:9` (`eciesEncryptionCofactorVariableIVX963SHA256AESGCM` over a 256-bit `kSecAttrKeyTypeECSECPrimeRandom` key): (a) Apple's ECIES uses a **16-byte AES-GCM key for curves ≤ 256 bits** — the SE tier's symmetric primitive is AES-128-GCM, not AES-256; (b) the ECIES ciphertext embeds the ephemeral public key, so a future CRQC runs Shor on the ephemeral point, computes the ECDH shared secret against the obtainable static public key, applies the X9.63-SHA256 KDF, and decrypts **without the Secure Enclave** — an exfiltrated SE blob **is** an HNDL target; "the key never leaves the chip" protects live use, not recorded ciphertext. **Fix:** scope the AES-256 sentence to Android/PassphraseVault, state AES-128-GCM + P-256 ECDH for the SE tier, and invert the HNDL sentence for SE-wrapped blobs. (The Grover-on-AES-256 and PQC-is-transport parts of the paragraph are accurate.)

### REL-4 — No `example/` in `keychain`, `keystore`, `secret_service`
Each leaf loses pub.dev pub-points ("Provide an example"); only `oubliette/example` exists (and it is complete). **Fix:** a one-file `example/lib/main.dart` or `example.md` per leaf, or accept the score hit knowingly.

### REL-6 / REL-7 — Aggressive toolchain floors, partly undocumented
All pubspecs require `sdk >=3.12.1` / `flutter >=3.44.1` (June 2026 stable) — deliberate but excludes anyone not on newest stable; document the floor in READMEs if kept. `keystore/android/build.gradle` uses AGP 9.2.0 / Kotlin 2.4.0 idioms (built-in Kotlin, no kotlin-android plugin) — consumer apps on AGP 8.x will likely fail to evaluate it, and no minimum AGP/Gradle is documented (minSdk 30 is documented well).

---

## Info (recorded — hardening notes, accepted trade-offs, polish)

- **CRYPTO-3 — No freshness/anti-rollback on any platform or in the vault.** An attacker with storage write access can replace a slot's blob with any *older valid blob for the same slot* (the stale AAD authenticates). SECURITY.md carefully claims only relocation/downgrade/scheme-forcing protection, so this is not an overclaim — but add one sentence to "What is NOT protected": same-slot replay of a previously valid value is not detected (relevant to e.g. a wallet reverting to a rotated-away seed).
- **CRYPTO-4 — Darwin SE ciphertext is not slot-bound** (no AAD facility in `SecKeyCreateEncryptedData`; honestly documented as past the trust boundary in SECURITY.md:90-97). If parity is ever wanted: a v2 Darwin format could embed the slot string after the format header *inside* the ECIES plaintext and verify on read — tamper-evident slot binding with no native change.
- **Carried over, still open (accepted):** synchronous Argon2id on the calling isolate (`passphrase_vault.dart:697-709` — the `sensitive` preset freezes the UI isolate for seconds); `_maxIterations = 64` (`:169`) admits ~6.4× the strongest preset's work from a hostile envelope before tag rejection.
- **AND-8** — `onlyUnlocked` doc claims "store() can still succeed while the screen is locked"; on Android 14+ UDR superencryption makes encrypt-init fail too (recoverably — safe direction). Doc fix: qualify with "on Android 14+ writes also fail recoverably until unlock".
- **AND-9** — Keymaster operation slots opened at `Cipher.init` are never aborted on abandonment (auth cancel, activity gone, timeout); `javax.crypto.Cipher` has no abort API — inherent, recorded for awareness (mildly aggravates the pruning condition `decrypt_interrupted` exists for).
- **AND-10a** — `StrongBoxUnavailableException` caught only as the outer type (`KeystorePlugin.kt:258-259`); an OEM wrapping it yields `generate_key_failed` instead of `strongbox_unavailable` — diagnostic only; a cause-chain walk would fix it.
- **DAR-9** — SE key deleted between item read and decrypt maps to `se_decrypt_failed` rather than `se_key_missing` (both non-recoverable; diagnostic-only; narrow race).
- **DAR-10** — the native `Keychain` facade accepts an empty alias (`KeychainQueries.swift:65-81`); oubliette never sends one — direct facade callers only.
- **DAR-11** — biometric-enrollment invalidation on `authenticatedFatal` is indistinguishable from "never stored" on Darwin (unlike Android's `KeyInvalidatedException`); the post-invalidation OSStatus is OS-version-dependent and has no integration test — recommend an on-device verification note.
- **DAR-12 / DART tests** — coverage gaps: `secureEnclave: true` *without* authentication (the only SE path CI could run) has no test; DAR-1 (nil vs scoped service), DAR-3 (composition), and DART-1 (re-constructing an identical custom profile) are untested anywhere.
- **DART-9 — the example app models the anti-patterns the API is designed to prevent:** copies plaintext out of `useAndForget` into long-lived widget state (`storage_test_page.dart:79-86`); catches raw `PlatformException`/generic `catch (e)` and never demonstrates the typed `recoverable` branching; `debugPrint`s the full profile config including `keyAlias`/`prefix`/`service` (`custom_profile_page.dart:91-112`) — the exact identifiers the library scrubbed from its own init banners; `_platformHint` has no Linux branch. Fine for a storage-tester, but it is the first usage pattern every adopter copies.
- **DART-11** — minor drift: `PassphraseVault.useAndForget` lacks the non-nullable-`T` caveat its `Oubliette` counterpart documents; sentinel pseudo-keys (`<purge>`/`<keys>`/`<init>`) surface in `AuthenticationFailedException.key` on Android/Darwin while Linux passes `null`; `keys()` trusts the native reply shape (`substring` can throw a raw `RangeError` on a misbehaving host); hardcoded English `'Confirm your identity'` default in `keystore.dart:95,140`.
- **REL-5** — `secret_service/CHANGELOG.md` lacks the `# Changelog` title header the other three have (cosmetic, pub.dev Changelog tab).
- **REL-8** — dartdoc gaps are all above pana's bar (no pub-points at risk): ~57/140 public declarations in `oubliette` lack local `///` (mostly `@override` members inheriting docs), keystore 12/18, keychain 6/23, secret_service 0/7.
- **REL-12 — CI is unusually strong** (SHA-pinned actions, least-privilege, format gate, native Kotlin/Swift/C++ compile+test gates, Android emulator + real-macOS-Keychain integration jobs, dead-test guard, Dependabot across all 6 dirs). Gaps: triggers only on `main` (feature branches get CI only via PR); no pana/pub-score job; no publish automation (manual — fine).
- **REL-13** — hygiene: zero TODO/FIXME/HACK markers in shipped source or docs; working tree clean; PLATFORM_DEEP_DIVE.md is deliberately local-only (gitignored, unreferenced by tracked docs — note its verified contents ship nowhere); one cosmetic git-history artifact (commit `2e4777b`'s subject contains an embedded `" -m "`).
- **REL-14 / DART-10** — publish-order: the three leaves must be live before `oubliette 1.0.0` resolves (documented in a pubspec comment; hard-coupled to REL-1). The `default_package:` entries are effectively decorative (they drive pub.dev platform badges); actual selection is runtime `defaultTargetPlatform`, web fails fast via `kIsWeb`, Windows/Fuchsia hit the documented `UnsupportedError`. Leaves may drift ahead of `oubliette` within 1.x under the append-only error-code contract — keep in mind at publish time.

---

## Executed release checks (all actually run, 2026-07-02)

- `flutter pub get` — resolves clean (Flutter 3.44.2 / Dart 3.12.x via fvm).
- `melos run analyze` (flutter analyze × 5 packages incl. example) — no issues in any package.
- `melos run test` — all pass: oubliette 209, keystore 36, secret_service 20, keychain 12, example 1 (native Kotlin/Swift + device integration tests covered in CI).
- `dart format --set-exit-if-changed` across all 4 packages — clean.
- `flutter pub publish --dry-run` in each package — **all 4 pass with 0 warnings** (the `keychain` dry-run's "previous version 0.0.8 isn't opted in to null safety" hint is the REL-1 smoking gun).

---

## Previous-audit verification (evidence that every prior finding landed)

All five reviewers spot-checked the prior AUDIT.md's findings in their domain against the current tree. Consolidated evidence:

| Prior finding | Status | Evidence |
|---|---|---|
| H-1 (COMPARISON.md denied Linux) | Fixed | `COMPARISON.md:18,55` covers Linux + `keys()` |
| M-1 (Android `custom` fail-open combo) | Fixed | `android_secret_access.dart:323-331` throws for `invalidatedByBiometricEnrollment` without `promptTitle` (+ passing test) |
| M-2 (vault purge/store race) | Fixed | `passphrase_vault.dart:265-274` post-`_encrypt` epoch/dispose re-check → `StateError`, envelope zeroed; `Completer`-gated interleaving tests at `passphrase_vault_test.dart:767-855` |
| M-3 (Linux wipe-without-free leak) | Fixed | `secret_service_plugin.cc:69` `secret_password_free` |
| M-4 (SE decrypt CFError discarded) | Fixed | `EnclaveDecryptResult` carries the CFError; `enclaveDecryptFlutterError` (`KeychainPlugin.swift:150-176`) routes NSOSStatus + LAError domains to recoverable codes |
| M-5 (transient keymaster → fatal) | Fixed | `BiometricAuth.kt:61-103` `isTransientKeystoreInterruption` → `decrypt_interrupted` (AEADBadTagException vetoed), mapped recoverable |
| M-6 (Darwin `exists()` on auth profile) | Fixed | `darwin_oubliette.dart:308-340` narrow `interaction_not_allowed` → `true` translation, documented on `Oubliette.exists` |
| M-7 (oversized write strands data) | Fixed | `encrypted_payload.dart:84-99` symmetric write-side cap via shared constant |
| M-10/M-12 (root README drift) | Fixed | root README: four packages, `pointycastle ^4.0.0` disclosed, constructor args correct (but see REL-2 for the *package* README) |
| M-11 (USE_BIOMETRIC) | Fixed | `keystore/android/src/main/AndroidManifest.xml:16` |
| M-13 (CI gaps) | Fixed | format gate + iOS build job; Dependabot covers all dirs |
| M-14 (vault zeroing untested) | Fixed | `passphrase_vault_test.dart:139-167` asserts buffer zeroed when action throws |
| L-1 (unzeroed `_wrap` copies) | Fixed | `darwin_oubliette.dart:139-141`, `linux_oubliette.dart:129-131` finally-zeroed + corrupt-header zero-before-rethrow |
| L-2 (shared custom alias) | Fixed (but see DART-1/AND-2/AND-3 for the gaps the fix's shape left) | `android_secret_access.dart:29,352-361` per-isolate registry |
| L-3/L-4 (unmapped codes, `fetch` on interface) | Fixed | Android trash/exists/keys through `_mapError`; `fetch` moved to unexported `src/fetch.dart` mixin |
| L-5 (facade auth defaults) | Fixed | `keystore.dart:34-41` all flags `required` |
| L-6 (LAContext gating) | Fixed | `KeychainPlugin.swift:335` gates on auth-required or prompt; reuse-duration 0; deterministic invalidate |
| L-8 (unknown version fatal) | Fixed | `KeystorePlugin.kt:346-362` + `BiometricAuth.kt:222-235` emit recoverable `unsupported_version` (but see DART-6 for granularity) |
| L-9 (single cancellation slot) | Fixed | `KeystorePlugin.kt:73-74` `ConcurrentHashMap.newKeySet()` |
| L-10 (null listByPrefix → empty) | Fixed | `secret_service.dart:145-157` fails closed |
| L-11…L-15 & Info items | Fixed | NUL-backstop doc; trailing-separator test double; Podfile.locks; `topics:` in all pubspecs; `kIsWeb` guard; vault `keys()` filters `reservedKekKey`; init `debugPrint` banners removed; SECURITY.md contact email; `android.R.string.cancel`; privacy manifest shipped via both CocoaPods `resource_bundles` and SPM `resources` |

---

## Overall verdict

**Code: ready-with-caveats. Publish: blocked on the `keychain` name.** This remains an unusually well-engineered secret-storage library, and it is materially better than at the previous audit — every prior finding was verified fixed in code, with regression tests. No reviewer found a plaintext-disclosure, auth-bypass, or slot-forgery path. What this pass adds is a set of second-order findings the first audit's angles couldn't see: cross-profile isolation holes reachable through ordinary configuration (nil `service`, prefix overrides, prefix collisions), three fresh instances of the transient-vs-fatal misclassification the library's doctrine forbids, and two headline documentation claims (post-quantum, hardware-at-rest on macOS) that don't survive contact with the actual primitives. All of the recommended gate items are small, localized fixes except the pub.dev rename decision — resolve REL-1 first, land the seven code/doc gate fixes, and this ships.
