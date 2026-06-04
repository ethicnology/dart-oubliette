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
  access to `SharedPreferences` cannot relocate a payload to a different slot or
  downgrade its decrypting key: `fetch` recomputes the AAD and alias from the
  live profile and throws `PayloadTamperException` on mismatch. GCM
  authentication backs this up.
- **Fail-closed protection.** Requesting authentication or StrongBox yields the
  protection or a clear error — never a silent downgrade to an unprotected /
  weaker item.
- **No cloud exfiltration.** `kSecAttrSynchronizable = false`; secrets never
  leave the device via iCloud Keychain.
- **Device-bound auth.** The `authenticated`/`authenticatedFatal` profiles gate
  access on biometric/credential auth; `authenticatedFatal` additionally
  invalidates the key on biometric enrollment change.

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
- **Compromised build/supply chain.** Reproducible-build pinning is provided
  (see README → toolchain), but verifying it is the consuming app's job.

## Supported versions

Pre-1.0 (`0.0.x`): only the latest version is supported. Breaking security
fixes may land without a migration path until 1.0.
