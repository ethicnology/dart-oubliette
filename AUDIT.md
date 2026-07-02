# Security & Code Audit — dart-oubliette

**Date:** 2026-07-02
**Scope:** Full repository — `oubliette/` (Dart core, all platform backends, `PassphraseVault`), `keystore/` (Android/Kotlin), `keychain/` (iOS/macOS/Swift), `secret_service/` (Linux/C++), tests, CI, package metadata, and all documentation (`README.md`, `SECURITY.md`, `COMPARISON.md`, `AGENTS.md`, changelogs).
**Method:** Line-by-line review of every source file in the four packages, cross-checked against the documented security claims. Library behavior claims were verified against platform semantics (e.g. libsecret 0.21.7 sources/disassembly for the Linux findings, `BiometricPrompt` permission requirements for Android). Every finding below was verified in the actual code, not inferred.

---

## Executive summary

**This is an unusually well-engineered secret-storage library.** The core security claims hold: slot isolation via the reserved U+001D separator is airtight (including NUL, unpaired-surrogate, and nested-prefix edge cases), the Android AES-256-GCM parameters are exactly right with the scheme version genuinely bound into the AAD, biometric auth is cryptographically load-bearing (`CryptoObject`-bound cipher, not a decorative callback), the Secure Enclave key lifecycle avoids the classic regenerate-on-read data-loss trap, `kSecAttrSynchronizable = false` is on every Keychain query, fail-closed behavior is enforced (not just documented) at every layer, and plaintext zeroing on the Android native side is exhaustive across error/cancel/detach paths. CI is SHA-pinned, least-privilege, and actually gates native Kotlin/Swift/C++ code plus real-hardware integration tests.

**No Critical findings. No plaintext-disclosure, auth-bypass, or slot-forgery path was found.**

The defects cluster in three themes:

1. **Error-taxonomy misclassification** — several *transient* failures land in `recoverable == false` buckets whose documented remedy is the irreversible `purge()`. For a library whose central doctrine is "never steer a caller toward destroying recoverable data," these are the most important code fixes (M-4, M-5, M-6).
2. **Fail-open/fail-silent edge cases at the `custom`-profile and standalone-facade boundaries** — the named profiles are safe, but the escape hatches can silently drop requested protections (M-1, L-5, L-6).
3. **Documentation drift** — `COMPARISON.md` predates Linux support entirely, and the README misstates the package count, the dependency set, and (in examples) the required constructor arguments (H-1, M-10…M-12).

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High     | 1 (documentation) |
| Medium   | 14 |
| Low      | 15 |
| Info     | ~15 (recorded, mostly hardening notes / accepted trade-offs) |

---

## High

### H-1 — COMPARISON.md denies that Linux support exists
`COMPARISON.md:53` claims "Android + iOS/macOS only (no Linux/Windows/web)", contradicting the README, SECURITY.md, and the shipped `secret_service` Linux plugin wired in `oubliette/pubspec.yaml:41-42`. The comparison table has no Linux row and omits `keys()` from the API list. A prospective user evaluating the library from this document is told a shipping platform doesn't exist. Docs-only fix, but it's the first document a comparison shopper reads.

---

## Medium

### Security behavior

**M-1 — Android `custom` silently drops a requested protection.**
`oubliette/lib/android_secret_access.dart:284-293` — `AndroidSecretAccess.custom` derives `userAuthenticationRequired = promptTitle != null` and never cross-checks `invalidatedByBiometricEnrollment`. Passing `invalidatedByBiometricEnrollment: true` with `promptTitle: null` yields a key with **no auth requirement and no enrollment invalidation** — the enrollment trip-wire becomes a silent no-op. This is exactly the "asked for protection, silently got none" failure mode the README's *Fail-Closed Authentication* section rules out, and the Darwin counterpart explicitly guards the analogous combination (`darwin_secret_access.dart:267-274` throws for `biometryCurrentSetOnly && !authenticationRequired`). **Fix:** throw `ArgumentError` in the `custom` constructor when `invalidatedByBiometricEnrollment && promptTitle == null`.

**M-2 — `PassphraseVault` keyring-mode purge/store race is undetected, contradicting its documented fail-closed claim.**
`oubliette/lib/src/passphrase_vault.dart:250-255` (claim at 299-303) — `store()` performs no epoch/dispose re-check between `_encrypt` completing and `_inner.store`. A `purge()` that completes inside that suspension gap goes undetected: the envelope is written under a destroyed KEK, the next KEK mint makes it permanently undecryptable, and it later surfaces as a misleading `DecryptionFailedException`. The doc explicitly promises a `StateError` when the race is detected. **Fix:** re-check `_kekEpoch`/disposal after `_encrypt` and before `_inner.store`.

**M-3 — Linux read path leaks every decrypted secret buffer (wipe-without-free).**
`secret_service/linux/secret_service_plugin.cc:56-64` — the `secret_autofree` cleanup calls `secret_password_wipe()` (zeroes only, **never frees** — verified against libsecret 0.21.7), while the comment claims the reverse semantics. Every `fetch` leaks one allocation from libsecret's **mlocked secure-memory pool**; a long-running app exhausts `RLIMIT_MEMLOCK`, after which libsecret silently falls back to ordinary *pageable* memory for future secret transfers — degrading the non-pageable property process-wide, plus an unbounded RSS leak. **Fix (one line):** call `secret_password_free()` (which both wipes and frees) and correct the comment.

### Error taxonomy (transient failures steered toward `purge()`)

**M-4 — Darwin: transient Secure Enclave decrypt errors are conflated with permanent decryption failure.**
`keychain/.../SecureEnclave.swift:228-237` + `KeychainPlugin.swift:263-266` — `enclaveDecrypt` discards the `CFError` and collapses every `SecKeyCreateDecryptedData` failure to `se_decrypt_failed` → `DecryptionFailedException` (`recoverable: false`, documented remedy "overwrite or `purge()`"). If the device locks between the item read and the SE decrypt (or the SEP returns a transient error), a purely transient condition tells the caller the ciphertext is bad — and a compliant caller destroys an intact wallet seed. **Fix:** inspect the `CFError` and surface interaction-not-allowed/auth-class errors as recoverable codes, mirroring the item-read path.

**M-5 — Android: transient keymaster failures at `doFinal` land in the fatal `decrypt_failed` bucket.**
`keystore/.../V1Scheme.kt:157-187` via `KeystorePlugin.kt:350-363` — on the authenticated path, `Cipher.init` opens a keymaster operation *before* an unbounded biometric prompt; system-wide operation-slot pruning during the prompt makes post-auth `doFinal` throw a bare `KeyStoreException` ("operation expired"), which maps to `decrypt_failed` → `DecryptionFailedException(recoverable: false)`. The code's own comment says misclassifying transient failures as key-loss "is the exact mistake the taxonomy exists to prevent" — but the fallback bucket is the fatal one. **Fix:** a distinct retryable code (or one re-init-and-retry) for `KeyStoreException` at `doFinal` on the authenticated path.

**M-6 — Darwin `exists()` throws a misleading "recoverable" auth error for items that plainly exist.**
`oubliette/lib/darwin_oubliette.dart:287-290` — on an authenticated profile, the UI-suppressed presence probe makes the OS report a present item as `interaction_not_allowed` → `AuthenticationFailedException` (`recoverable: true`). No amount of user authentication makes the probe succeed, so a compliant retry loop spins forever, or the caller treats the throw as "absent" and re-onboards over a live secret. `store()` works around this internally; public `exists()` gets no workaround and the facade contract carries no caveat. **Fix:** apply the same workaround (or document the tri-state) at the facade.

**M-7 — Android: an oversized secret stores successfully, then becomes permanently unreadable.**
`keystore/lib/src/encrypted_payload.dart:96-113` — `fromMap` (read path) rejects any base64 field above 64 Ki chars (~48 KiB decoded), but the write path has no corresponding cap. A ~60 KiB secret stores fine and every subsequent fetch throws `PayloadCorruptException` (`recoverable: false`) — self-inflicted data stranding that violates the SECURITY.md pledge that written data stays readable. **Fix:** enforce the cap symmetrically at `store()` time (fail the write) or document a hard input limit.

**M-8 — Linux: "fail-closed store" is check-then-create over an API that silently replaces.**
`secret_service/linux/secret_service_plugin.cc:337-362` — libsecret's `secret_password_store_sync` always uses `SECRET_ITEM_CREATE_REPLACE` (verified in 0.21.7 sources), so the `already_exists` guarantee rests entirely on a non-atomic search→store window plus the per-isolate Dart lock. Two processes (or two isolates) racing `store()` on one slot both pass the dup-check and the second write **silently overwrites** the first. `linux_oubliette.dart:100-110` documents this honestly, but `README.md:167-170` claims Linux fail-closed store "behaves like the other platforms" — on Darwin the duplicate check is atomic (`errSecDuplicateItem`). There is no put-if-absent in the Secret Service API. **Fix:** carry the cross-process caveat in README/SECURITY.md (the realistic remedy).

**M-9 — Linux: all keyring I/O blocks the GTK platform thread — up to ~60 s of whole-app freeze.**
`secret_service_plugin.cc:79, 581-694` — every handler runs synchronous libsecret calls inline on the GTK main thread; the 20 s watchdog bounds each call but not the thread, and `handle_write` chains up to three bounded calls. With a locked keyring, the entire window freezes (no input, no redraw) precisely while the user is expected to interact with the unlock dialog. **Fix:** run libsecret work on a worker thread (the `FlMethodCall` is refcounted and safely holdable) or use libsecret's async API.

### Process / documentation

**M-10 — README misstates the package set and the dependency policy.**
`README.md:272-279` says "monorepo with three packages" and omits `secret_service` (there are four); `README.md:255-256` claims "runtime deps are kept to official packages only (`shared_preferences`, `meta`)" — but `pointycastle: ^4.0.0` (`oubliette/pubspec.yaml:25`) is a third-party **crypto** dependency used by `PassphraseVault`, exactly what a security-focused reader audits first.

**M-11 — The keystore plugin manifest wrongly claims `USE_BIOMETRIC` isn't needed.**
`keystore/android/src/main/AndroidManifest.xml:1-6` asserts the platform `BiometricPrompt` "needs none", but `android.hardware.biometrics.BiometricPrompt#authenticate` is `@RequiresPermission(USE_BIOMETRIC)`. README:231 is correct; the manifest comment is wrong, and because the plugin deliberately avoids androidx (whose manifest would merge the permission in), omitting it kills the authenticated profiles at runtime with a recoverable-looking `auth_error` no retry will fix. **Fix:** declare `<uses-permission android:name="android.permission.USE_BIOMETRIC" />` in the plugin's own manifest so manifest-merge covers all consumers, and fix the comment.

**M-12 — README quick-start examples don't compile.**
`README.md:26, 53-55` — both examples call `AndroidSecretAccess.onlyUnlocked(strongBox: …)` without the **required** `requireHardwareBacking` parameter. Also `SECURITY.md:226-231` self-contradicts, calling it "a required choice — no default" and two lines later "it defaults off."

**M-13 — CI gaps: no format gate, and iOS is never built or tested.**
`.github/workflows/ci.yml` has no `dart format` check despite `melos run format` existing, and the darwin job builds macOS only — an iOS-only Swift compile break in the `keychain` pod ships green. Additionally `.github/dependabot.yml:6-14` omits `/secret_service` and the workspace root `/` (where the single `pubspec.lock` and `melos` actually resolve), so those get no advisory coverage.

**M-14 — The most security-relevant zeroing path has no test.**
`oubliette/lib/src/passphrase_vault.dart:265-279` zeroes the decrypted secret in a `finally` (including when the caller's `action` throws) — but no test captures that buffer and asserts it was zeroed (`use_and_forget_test.dart` covers only the base-class layer). A regression dropping the vault's `finally` would leave decrypted mnemonics in memory with zero test signal.

---

## Low

**L-1 — Library-owned plaintext copies in `_wrap` are never zeroed.** `darwin_oubliette.dart:45-50`, `linux_oubliette.dart:42-47` — the header-prepended copy of the full plaintext handed to the method channel is modifiable and trivially zeroable in a `finally`, but isn't — contradicting README:194 ("the library only wipes the buffers it owns"). Similarly, a fetch whose `_unwrap` throws `PayloadCorruptException` discards the (non-SE plaintext) buffer unzeroed.

**L-2 — Nothing prevents two `custom` Android profiles from sharing a Keystore alias.** `android_secret_access.dart:295-302` validates the alias only against the four reserved names; two custom profiles with the same alias are accepted, and `purge()` of one deletes the shared key — permanently bricking the other, violating "purge() of one profile never touches another" (SECURITY.md:63-65). Key-material isolation is by unenforced convention.

**L-3 — Android `trash`/`exists` bypass `_mapError`.** `android_oubliette.dart:263-266, 293-296` — `SharedPreferences` failures escape as raw `PlatformException`, while the facade contract promises typed `OublietteException`s (Darwin/Linux `trash` do map). Callers branching on `recoverable` have nothing to branch on.

**L-4 — The "no `read()`" doctrine is lint-only.** `oubliette.dart:109-110` — `fetch()` is public API guarded only by `@protected` (a warning, not an error) in publicly importable files; any caller can obtain an unmanaged, never-zeroed plaintext buffer.

**L-5 — Keystore Dart facade defaults `userAuthenticationRequired = false`.** `keystore/lib/src/keystore.dart:29-30` — the Kotlin side makes every security flag mandatory precisely to avoid fail-open defaults, but the standalone facade (documented as usable directly) defaults the auth flag off while its siblings (`strongBox`, `requireHardwareBacking`…) are `required`.

**L-6 — Darwin LAContext hardening is gated on the wrong condition.** `KeychainPlugin.swift:214-225` — `touchIDAuthenticationAllowableReuseDuration = 0` and deterministic context invalidation apply only when an `authenticationPrompt` string is supplied; an auth-required read without a prompt gets the system-managed context with none of the hardening. Gate on `authenticationRequired` instead. (Oubliette's profiles always pass a prompt; only direct facade users are exposed.)

**L-7 — For authenticated SE profiles, user presence gates the ciphertext item, not the SE key operation.** `SecureEnclave.swift:179-189` (`.privateKeyUsage` only) — deliberate and documented (the SE key is shared across profiles), but SECURITY.md's "Darwin uses a data-bound `SecAccessControl`" overstates it as key-bound; unlike Android's `CryptoObject`, the SEP will decrypt for any in-process caller holding the ciphertext.

**L-8 — Unknown/future scheme versions map to the fatal `decrypt_failed`.** `KeystorePlugin.kt:328-331` — an app downgrade (rollback, sideload) reading v2 blobs gets destructive-recovery guidance instead of a distinct "version newer than this reader" signal.

**L-9 — Only one in-flight biometric prompt is tracked for lifecycle cancellation.** `KeystorePlugin.kt:61-62` — a second concurrent prompt evicts the first from `pendingAuthCancellation`; on activity destroy only the second is cancelled, reopening the OEM `ERROR_CANCELED` gap the mechanism exists to close.

**L-10 — Linux `listByPrefix` treats a null protocol reply as "no keys".** `secret_service/lib/src/secret_service.dart:135-141` — `contains` fails closed on the same protocol violation; `keys()` instead reports an empty profile that actually holds secrets.

**L-11 — Dart docs advertise a native NUL backstop that the native layer explicitly does not implement.** `secret_service.dart:48-51` vs `secret_service_plugin.cc:620-631` — the facade doc/test claim a `bad_args` native re-check; the native comment correctly explains it cannot re-check. Doc fix.

**L-12 — secret_service test double diverges from the native contract.** `secret_service_test.dart:101-109` — `deleteByPrefix` is tested with a prefix the real backend rejects (must end in `0x1D`), and `listByPrefix` is untested; a facade regression would pass CI and fail only at runtime.

**L-13 — Stale committed Podfile.locks.** `oubliette/example/{ios,macos}/Podfile.lock` record `keychain (0.0.1)` vs podspec `1.0.0`, undermining the README's "reproducible CocoaPods" pinning claim. Also: wrapper-jar convention differs between `keystore/android` (committed) and the example (ignored).

**L-14 — README error-table drift from actual Darwin mappings.** `darwin_oubliette.dart:179-229` maps seven codes (`sec_item_copy_failed`, `missing_entitlement`, `se_key_missing`, …) the README table omits or attributes to Android only.

**L-15 — Toolchain-table overstatement + missing pub.dev `topics:`.** README:244 says Dart is "pinned" by every pubspec, but they declare the range `>=3.12.1 <4.0.0`; no publishable pubspec has `topics:` (discoverability).

---

## Info (selected)

- **`PLATFORM_DEEP_DIVE.md` (34 KB) is untracked and unignored** — the only `??` in `git status`; commit it or ignore it before it's lost or accidentally committed.
- **`SECURITY.md:5`** — the vulnerability-reporting section says "Email with details…" but **no email address is given**.
- **Argon2id runs synchronously on the calling isolate** (`passphrase_vault.dart:639-651`) — the `sensitive` preset (256 MiB, t=10) freezes the UI isolate for seconds; consider `Isolate.run`.
- **Envelope-driven Argon2 DoS ceiling** (`passphrase_vault.dart:165-171`) admits ~6× the work of the strongest shipped preset before tag rejection; tighten `_maxIterations` toward the legitimate maximum.
- **`init()` `debugPrint`s the key alias/service/prefix** — identifiers the error taxonomy deliberately redacts from `toString()` leave via the init banner (and `debugPrint` is not stripped in release).
- **Factory dispatch mis-selects on Flutter web** (`oubliette.dart:60-70`) — no `kIsWeb` check, so web gets an opaque `MissingPluginException` instead of the intended `UnsupportedError`.
- **`useAndForget<T?>` cannot distinguish "key absent" from "action returned null".**
- **`PassphraseVault` lacks a `keys()` passthrough** — enumerating via `inner.keys()` exposes the reserved `__oubliette_vault_kek__` slot to accidental `inner.trash()` (mass data loss), bypassing the vault's reserved-key guard.
- **Linux `SECRET_SEARCH_UNLOCK` asymmetry** — `contains`/read/dup-check keep the flag that `deleteByPrefix`/`listByPrefix` deliberately drop (planted-item unlock-prompt storm); looks unintentional.
- **Swift SE tag "length prefix" counts graphemes, not bytes** (`SecureEnclave.swift:72-84`) — injectivity was verified to still hold; a byte-length prefix would be robust by inspection. NFC/NFD-differing service strings mint distinct keys.
- **Darwin post-handoff `wipe()` zeroes a COW copy**, not the surviving bridged buffer — accurately self-documented; don't strengthen the docs without changing the mechanism.
- **Missing Apple privacy manifest** (`PrivacyInfo.xcprivacy` commented out; podspec bundles none) — compliance hygiene.
- **Hardcoded English "Cancel"** on the biometric negative button (`BiometricAuth.kt:280`).
- **Integration tests for biometric/SE paths run in no CI job** (device-only; documented, but permanently ungated).
- **Android hardcoded `device_locked` over-classification** and the **macOS `useDataProtection` tag-domain hazard** are deliberate, correctly argued in code comments, and safe under the shipped profiles — recorded, no action needed.

---

## What was checked and found sound

- **Slot isolation** — U+001D separator, NUL, and unpaired-surrogate rejection on both prefix and key make slots injective; nested-prefix `purge()`/`keys()` ownership is byte-exact on all four platforms (including the Linux trailing-`0x1D` guard: `0x1D` can never be a UTF-8 continuation byte).
- **Android crypto** — `PURPOSE_ENCRYPT|DECRYPT`, GCM, no padding, 256-bit, `setRandomizedEncryptionRequired(true)`, per-operation auth (`setUserAuthenticationParameters(0, …)`), StrongBox fail-closed, keystore-generated IVs (never caller-supplied on encrypt), **version genuinely bound into the AAD** via an injective construction, hardware-backing verification with delete-on-refusal, minSdk 30 enforced.
- **Auth is load-bearing** — the `Cipher` rides in `BiometricPrompt.CryptoObject` and `doFinal` runs on the authenticated cipher; a bypassed UI callback cannot satisfy the keymaster. Prompt authenticators are derived from `KeyInfo`, fail-closed.
- **Android plaintext zeroing** — traced through every path (bad args, init failure, dead looper, auth error/cancel, doFinal failure, success): all wiped.
- **Darwin** — `kSecAttrSynchronizable = false` on every item query; fail-closed `SecAccessControl` (nothing stored on creation failure); `.biometryCurrentSet` vs `.userPresence` wired correctly; ECIES is `eciesEncryptionCofactorVariableIVX963SHA256AESGCM` (no raw ECDH); SE key create-only-on-verified-missing (never a second key under one tag); frozen 1-byte format header fails closed; no `SecItemUpdate` anywhere; correct threading (work off main, results on main).
- **Error mapping** — every README-table code exists in the corresponding `_mapError`; unknown codes rethrow raw rather than guessing toward `purge()`.
- **Repo hygiene** — `local.properties`, `.idea/`, generated files all correctly ignored; no credentials or user paths in tracked content; single-lockfile pub-workspace policy verified in sync (`--enforce-lockfile` passes).
- **CI security posture** — `permissions: contents: read`, `pull_request` (not `pull_request_target`), **all** actions (including third-party) pinned to full commit SHAs, no secrets; native Kotlin/Swift tests genuinely gated (with a dead-test guard), Linux C++ compile-gated, real Keystore emulator + real Keychain macOS integration jobs.
- **Test quality** — ~1.4:1 test-to-source for Dart plus native tests; the crypto core is tested with real Argon2id/AES-GCM/HKDF, golden v1 format vectors on both Dart and Kotlin sides, nonce-uniqueness sweeps, GCM tamper/AAD-relocation cases, and `Completer`-gated race tests. No skipped or tautological tests found.

---

## Priority recommendations

1. **Fix the one-line Linux leak (M-3)** — `secret_password_free` instead of `secret_password_wipe`; it silently degrades libsecret's non-pageable memory guarantee process-wide.
2. **Close the fail-open `custom` combination (M-1)** and the `PassphraseVault` purge/store race (M-2) — both contradict documented fail-closed guarantees.
3. **Fix the transient-vs-fatal misclassifications (M-4, M-5, M-6)** — these actively steer compliant callers toward `purge()`-ing recoverable data, the exact failure the library's taxonomy exists to prevent.
4. **Declare `USE_BIOMETRIC` in the keystore plugin manifest (M-11)** and add the write-side payload cap (M-7).
5. **Sweep the documentation** — rewrite/retire COMPARISON.md (H-1), fix the README package list, dependency claim, non-compiling examples, error-table drift, and add the missing security-contact email; decide the fate of the untracked PLATFORM_DEEP_DIVE.md.
6. **CI:** add a `dart format` gate, an iOS build/test lane, dependabot entries for `/secret_service` and the workspace root, and a regression test asserting the vault zeroes plaintext when the callback throws (M-13, M-14).

---

*Generated by a multi-agent audit (five parallel reviewers: Dart core, Android/Kotlin, Darwin/Swift, Linux/C++, and repo hygiene/CI/docs), with the highest-impact findings independently re-verified against the source.*
