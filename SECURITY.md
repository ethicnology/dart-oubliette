# Security Policy

## Reporting a vulnerability

Email with details and a proof of concept if you
have one. Please do not open a public issue for undisclosed vulnerabilities.
We aim to acknowledge reports within a few business days.

## Threat model

Oubliette stores small secrets (e.g. mnemonic phrases, API tokens) in
hardware-backed platform stores. It is designed for a specific, bounded set of
guarantees — knowing what is *not* covered matters as much as what is.

### What is protected

- **Secrets at rest are hardware-encrypted.** Android: AES-256-GCM with a key
  held in the Keystore (TEE or StrongBox). iOS/macOS: a Keychain item,
  optionally wrapped by a Secure Enclave P-256 key. The cryptographic key never
  enters the app process.
- **Per-profile slot isolation.** Each security profile uses a distinct storage
  prefix and key, so a key stored under one profile cannot be read under
  another. On Darwin this is the only barrier (the read query carries no
  access-control attribute), so it is treated as a security boundary.
- **Tamper-evidence against data-dir writes (Android).** An attacker with write
  access to `SharedPreferences` cannot relocate a payload to a different slot,
  downgrade its decrypting key, or force a weaker scheme: `fetch` recomputes the
  AAD and alias from the live profile and throws `PayloadTamperException` on
  mismatch, and the scheme `version` that selects the decryptor is itself bound
  into the AES-GCM AAD, so a rewritten version fails the GCM tag. GCM
  authentication backs all of this.
- **Fail-closed protection.** Requesting authentication or StrongBox yields the
  protection or a clear error — never a silent downgrade to an unprotected /
  weaker item.
- **No cloud exfiltration.** `kSecAttrSynchronizable = false`; secrets never
  leave the device via iCloud Keychain.
- **Device-bound auth.** The `authenticated`/`authenticatedFatal` profiles gate
  access on biometric/credential auth; `authenticatedFatal` additionally
  invalidates the key on biometric enrollment change.

### Key lifecycle: the library never destroys key material

Destroying a key is an irreversible data-loss event — every secret encrypted
under it becomes permanently unrecoverable. **That decision belongs to the
developer, never to this library.** Concretely:

- We never delete, overwrite, or regenerate an existing key on your behalf —
  not as error recovery, not as cleanup, not silently.
- `trash(key)` removes a single stored *value* (its SharedPreferences blob /
  Keychain item). It never touches the underlying key.
- When a key is permanently invalidated — the OS does this when biometric
  enrollment changes on `authenticatedFatal`, or when the secure lock screen is
  disabled/reset on **any** authenticated profile — `store`/`fetch` surface a
  typed `KeyInvalidatedException` (Android) **unchanged**. The profile is
  intentionally left unwritable until *you* explicitly recover it. The data
  under that key is already gone (that is what invalidation means); the library
  refuses to make the destruction decision for you.
- `purge()` is the **only** API that destroys key material, and only when you
  call it: it wipes a whole profile (every blob plus, on Android, the profile's
  Keystore key) so a wedged/invalidated profile can be re-provisioned with
  `purge()` then `init()`. On Darwin the shared Secure Enclave key is retained
  (its identity excludes the slot prefix, so it may be shared with a sibling
  profile, and it is never invalidated). `purge()` of one profile never touches
  another: a slot is `prefix + U+001D + key`, and the reserved separator makes
ownership exact — a profile whose prefix nests under another's can never match.

### What is NOT protected

- **Rooted / jailbroken devices.** A privileged attacker who can defeat the
  TEE/Secure Enclave or hook the process is out of scope. Hardware key isolation
  raises the bar; it is not an absolute guarantee on a compromised OS.
- **An unlocked device in an attacker's hands** for profiles that don't require
  per-use auth (`evenLocked`, `onlyUnlocked`). Use the `authenticated` profiles
  for per-access gating.
- **Memory disclosure.** Zeroing is best-effort. The library cannot guarantee
  erasure against GC compaction, Flutter method-channel copies, OS swap, or core
  dumps (see README → Memory Hygiene). It also cannot zero the caller-owned
  `value` buffer passed to `store()`.
- **The caller's handling of decrypted bytes.** Once `useAndForget`'s callback
  receives the plaintext, what the callback does with it (logging, copying,
  sending) is the caller's responsibility.
- **An attacker already inside the app's Keychain ACL (Darwin).** Unlike Android,
  where each blob's AES-GCM AAD cryptographically binds it to its slot, Keychain
  items are isolated by account/accessibility but are not crypto-bound to their
  account. An attacker who can already write the app's Keychain (i.e. has
  defeated the platform's app isolation) could plant a chosen item. This is past
  the trust boundary; cross-profile *reads* still fail (distinct
  accessibility/SE keys), and the 1-byte format header catches SE/non-SE
  confusion.
- **Compromised build/supply chain.** Reproducible-build pinning is provided
  (see README → toolchain), but verifying it is the consuming app's job.

### Linux (Secret Service tier)

On Linux, Oubliette stores each secret as a separate item in the desktop Secret
Service (gnome-keyring, KWallet, or another `org.freedesktop.secrets` provider).
This is a **software-encrypted tier**, analogous to the macOS legacy
file-keychain — **not** hardware-backed, and weaker than the Android Keystore
and Apple Secure Enclave tiers.

- **What it protects.** Secrets are encrypted at rest while the keyring is
  locked (e.g. before login, or on a powered-off disk), and Oubliette's per-slot
  envelope binds each value to its slot so a relocated or version-downgraded
  on-disk blob fails closed (`PayloadCorruptException`) rather than decrypting
  under the wrong slot. Per-profile slot isolation and prefix-exact `purge()`
  hold via the reserved `U+001D` separator, identical to the other platforms.
- **What it does NOT protect.** The keyring is unlocked automatically at login
  (PAM) and stays unlocked for the whole session, including across screen-lock;
  while unlocked, **any process running as your user can read every stored
  secret** over the session bus — there is no per-application isolation outside
  a Flatpak/Snap sandbox, and no per-operation authentication gate. The
  encryption key is derived from your login password and lives in a user-space
  daemon, so it lacks the "key never leaves secure hardware" guarantee of the
  mobile tiers; the at-rest cipher also depends on which provider answers the
  bus (gnome-keyring AES vs KWallet Blowfish) and cannot be asserted by
  Oubliette.
- **No silent downgrade.** There is no hardware-backing or per-operation-auth
  option on Linux: `LinuxSecretAccess` offers only `evenLocked` / `onlyUnlocked`
  / `custom`, so an app cannot *believe* it asked for protection that the
  platform cannot provide. A missing/headless backend fails closed with
  `BackendUnavailableException`; a locked keyring with `KeyringLockedException`
  (both recoverable — never `purge()` in response).
- **Backup hygiene.** Exclude `~/.local/share/keyrings` (and
  `~/.local/share/kwalletd`) from cloud sync and home-directory backups: syncing
  them leaks secrets, and restoring them onto another machine/account yields
  ciphertext whose login-keyring master no longer matches — Oubliette surfaces
  that as a typed decrypt/lookup failure, never silent data loss.

## Stability & upgrade contract

The defining guarantee of this library: **upgrading the dependency never loses
or silently strands your data.** This is the explicit reaction to the failure
mode that has bitten other secure-storage plugins, where a version bump (a
silent reset-on-error, an algorithm auto-migration, or a removed cipher) quietly
destroyed user secrets. Oubliette pledges:

- **The on-disk format is versioned and frozen — on both platforms.** On
  Android each blob carries a scheme `version` inside the `EncryptedPayload`
  JSON envelope (format v1). On Darwin, where Keychain items have no format of
  their own, every blob is prefixed with a frozen 1-byte format header serving
  the same role. Readers ignore unknown JSON fields (forward-compatible).
  Committed *golden test vectors* fail CI if any change would make the current
  code unable to read v1 data.
- **The scheme registry is append-only.** A shipped scheme version is never
  removed or mutated — old blobs always decrypt by their on-disk version. New
  crypto is added as a new version and promoted to primary for new writes
  (Tink-style rotation); old data stays readable.
- **The naming schema is frozen.** Storage prefixes, Keystore aliases, and
  Secure-Enclave tag inputs are a stable contract. A storage slot is
  `prefix + U+001D + key`, where the reserved separator (rejected in prefixes
  and keys) makes slot ownership exact: a profile whose prefix nests under
  another's can never collide with or `purge()` the other's data. These names
  are never changed in a way that would relocate data out from under a reader.
- **No automatic migration, reset, or re-keying — and none to forget to run.**
  There is no `resetOnError` and no implicit re-encrypt-on-read. Because the
  format is versioned and the registry append-only (above), data written by any
  1.x release stays readable by every later 1.x with **no migration call**. The
  only API that destroys data is `purge()`, and only when you invoke it — the
  explicit recovery path for a profile wedged by a `KeyInvalidatedException`
  (`purge()` then `init()`, after which the user re-enters the secret).
- **Breaking changes are major-version-gated** and documented in the CHANGELOG
  with the recovery path; data written by an earlier 1.x is always readable by
  a later 1.x.

## Supported versions

`1.x`: the latest 1.x is supported; security fixes land on it. The 1.x on-disk
format is stable per the contract above — data written by any 1.x is readable by
every later 1.x.

## Platform backup & uninstall behaviour (read this)

The library guarantees its *own* format stability, but two platform behaviours
are outside its control and your app must handle them — both are classic
secure-storage data-loss/leak traps:

- **Android backup can strand data.** Android Auto Backup / D2D transfer may copy
  the app's `SharedPreferences` (which hold oubliette's ciphertext) to a new
  device, but Keystore keys are **device-bound and never restored**. The result
  is ciphertext with no key — undecryptable. This surfaces as
  `KeyNotFoundException`/`DecryptionFailedException` (never silent data loss on
  our side), but to avoid it entirely, **exclude oubliette's storage from
  backup**: set `android:allowBackup="false"`, or add a `dataExtractionRules` /
  `fullBackupContent` rule excluding the SharedPreferences file. Treat
  hardware-bound secrets as device-local, re-provisioned on a new device.
- **iOS/macOS Keychain items survive app uninstall.** Keychain entries are not
  deleted when the app is removed; a reinstall can read old secrets. Call
  `purge()` on logout / account deletion, and consider purging on first launch
  after a detected reinstall, so secrets do not outlive their intended lifetime.

## Platform CVEs & minimum OS

Hardware-backed storage depends on the OS and secure hardware, so some risks are
patched by the platform, not this library. Keep devices updated and document a
minimum OS for your app.

- Keep up with vendor patch levels. Recent examples (platform-fixed, not
  app-fixable): a 2026 Keychain authorization issue (CVE-2026-28864, fixed in
  iOS 18.7.7 / iOS·iPadOS 26.4 / macOS 15.7.5 / 14.8.5 / 26.4) and Qualcomm StrongBox
  memory-safety issues (e.g. CVE-2026-25276/25277). `ThisDeviceOnly`
  accessibility, access-group isolation, and per-use auth are the defense-in-depth
  that limits blast radius.
- **Hardware backing.** On a real device the Android Keystore key is
  hardware-backed (TEE/StrongBox) automatically. `strongBox: true` is
  fail-closed (absent StrongBox → error, never a silent TEE downgrade). For the
  general case, set **`requireHardwareBacking: true`** (a required choice — no
  default; pass `false` to allow software keystores like emulators) to make
  key *generation* verify the key landed in secure hardware (`KeyInfo`:
  `getSecurityLevel()` on API 31+, `isInsideSecureHardware` on API 30) and, if
  not, delete it and fail with `hardware_unavailable` rather than keep a
  software-keystore key. It defaults off so the library runs on software-only
  keystores (emulators); **wallet apps holding seeds should set it true.** (For
  a guarantee of *which* hardware, layer key attestation in your app.)
- **Biometric-bypass CVEs are scoped to OS app-lock UIs, not our path.** Issues
  like CVE-2026-28895 (iOS) and the Pixel CVE-2024-53835/53840 class target the
  system's "require Face ID to open app" toggle or the biometric success
  *callback*; Oubliette gates on the key itself — Android binds the operation to
  a `CryptoObject` (work runs on the authenticated cipher) and Darwin uses a
  data-bound `SecAccessControl`, so neither is satisfied by the bypassed UI.
  Keep devices patched regardless.
- **Post-quantum:** for **at-rest** secrets the confidentiality primitive is
  AES-256 (symmetric), which is already quantum-adequate — Grover only halves
  its strength, leaving 128-bit security. Apple's and Google's 2025–2026 PQC work
  (ML-KEM/ML-DSA) targets *transport* (messaging/TLS), and the Secure Enclave has
  no documented PQ-resident key, so the SE P-256 + ECIES wrap stays correct. A
  device-bound blob whose key never leaves the chip is not a harvest-now-decrypt-
  later target.

## Integrator checklist for high-value secrets (e.g. wallet seeds)

A leaked seed is total, irreversible loss, so for that class of secret the
library's controls only pay off if the integrator does its part. In priority
order:

1. **Use an authenticated profile** (`authenticated` / `authenticatedFatal`,
   `secureEnclave: true` on Darwin, `requireHardwareBacking: true` on Android) —
   never `evenLocked`/`onlyUnlocked`. The
   non-auth profiles are readable on any unlocked or in-process-compromised
   device; that is the single most likely real-world failure.
2. **Never make oubliette the only backup.** It is the on-device hot copy.
   Key material is device-bound and not restored across devices, so a restore /
   factory reset / key invalidation leaves ciphertext you cannot read — by
   design (no silent wipe). On `KeyNotFoundException` / `KeyInvalidatedException`,
   guide the user to re-import from their backup; never auto-`purge()` a
   `recoverable` error.
3. **Exclude from device backup and purge on logout** — see *Platform backup &
   uninstall* above (`allowBackup=false` / `dataExtractionRules`; `purge()` on
   logout because iOS Keychain survives uninstall).
4. **Enforce an OS/patch floor** (minSdk 30 already) and, for high-value funds,
   add root/jailbreak detection and gate on **key attestation**.
5. **Lock the plaintext lifecycle:** always read via `useAndForget`, never copy
   the secret to the clipboard, set `FLAG_SECURE` / obscure the app switcher,
   and never log it. The library cannot protect bytes once your callback holds
   them.

For coercion/duress resistance (forced unlock), prefer a multisig or
passphrase-gated design at the protocol level — device auth alone cannot defend
against a user compelled to unlock.
