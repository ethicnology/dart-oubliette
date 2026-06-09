/// Base class for every typed failure Oubliette raises.
///
/// Callers should branch on [recoverable] rather than string-matching a native
/// `PlatformException.code`. The distinction is safety-critical: calling
/// `purge()` (which is irreversible) in response to a *recoverable* error
/// destroys data that a retry would have returned.
///
/// Being `sealed`, a `switch` over an [OublietteException] is exhaustive — the
/// analyzer flags any unhandled subtype if a future release adds one.
///
/// **Diagnostic hygiene:** `toString()` is deliberately kept free of the
/// profile key alias and the underlying native `cause` (which can carry OEM
/// keymaster / biometric text, and — for a `custom` alias encoding a tenant or
/// user id — caller-sensitive identifiers). Those are retained as fields
/// (`keyAlias`, `cause`, …) for explicit, opt-in debugging, but are not folded
/// into `toString()` so that logging the exception — or a crash reporter
/// capturing it — does not exfiltrate them off-device. Log the fields yourself
/// when you intend to.
sealed class OublietteException implements Exception {
  const OublietteException();

  /// Whether retrying the *same* operation can succeed without destroying data
  /// — typically after the user unlocks the device or re-authenticates.
  ///
  /// - `true`  → transient. Retry; **never** `purge()` in response.
  /// - `false` → the secret behind this operation is unreadable. The only way
  ///   forward is an explicit, data-destroying recovery: `purge()` →`init()` →
  ///   have the user re-enter the secret.
  bool get recoverable;
}

/// Thrown when a stored [EncryptedPayload] does not match the slot it was
/// fetched from.
///
/// On Android the `aad` and `key_alias` fields are recomputed live from the
/// `(profile, key)` pair and compared against the values embedded in the
/// on-disk blob. A mismatch means the blob was relocated between storage slots
/// or its decrypting key was downgraded — an attacker with write access to
/// `SharedPreferences` attempting to make a payload decrypt under a different
/// (weaker, or differently-bound) key. The library refuses to decrypt rather
/// than trust attacker-controlled routing metadata.
///
/// Not recoverable by retry: the on-disk blob will keep failing the check until
/// it is overwritten (`trash` + `store`).
final class PayloadTamperException extends OublietteException {
  /// The logical key the caller asked for.
  final String key;

  /// The AAD the slot should carry (derived from the live profile + key).
  final String expectedAad;

  /// The AAD actually found in the stored blob.
  final String actualAad;

  /// The key alias the live profile mandates.
  final String expectedAlias;

  /// The key alias actually found in the stored blob.
  final String actualAlias;

  const PayloadTamperException({
    required this.key,
    required this.expectedAad,
    required this.actualAad,
    required this.expectedAlias,
    required this.actualAlias,
  });

  @override
  bool get recoverable => false;

  @override
  String toString() =>
      'PayloadTamperException: stored payload for key "$key" does not match '
      'its slot (the recomputed AAD/alias differ from the on-disk blob). '
      'Refusing to decrypt attacker-relocatable data. See the '
      'expected/actual AAD and alias fields for diagnostics.';
}

/// Thrown when a stored blob cannot be parsed into a valid [EncryptedPayload]
/// — a missing/invalid `version`, a nonce of the wrong length, empty
/// ciphertext, or non-base64 fields.
///
/// This signals on-disk corruption or an out-of-contract write, distinct from a
/// cryptographic decrypt failure ([DecryptionFailedException]) and from a
/// relocation attack ([PayloadTamperException]). Not recoverable by retry.
final class PayloadCorruptException extends OublietteException {
  /// Human-readable description of what was malformed.
  final String reason;

  const PayloadCorruptException(this.reason);

  @override
  bool get recoverable => false;

  @override
  String toString() => 'PayloadCorruptException: $reason';
}

/// Thrown when the profile's hardware key has been **permanently invalidated**
/// by the OS, making both the key and every secret stored under it
/// unrecoverable.
///
/// On Android this happens to any `userAuthenticationRequired` key when:
/// - a new biometric is enrolled (only for `authenticatedFatal`, which sets
///   `invalidatedByBiometricEnrollment`), or
/// - the secure lock screen (PIN/pattern/password) is removed or reset — this
///   invalidates **all** authenticated keys, including the non-fatal
///   `authenticated` profile.
///
/// The library never deletes key material implicitly, so a present-but-dead
/// key leaves the profile wedged: `store`/`fetch` keep failing and the alias
/// cannot be regenerated. Recovery is an explicit, irreversible decision the
/// caller must make — delete the profile's key **and** its stored blobs
/// (`purge`), then re-`init()`.
///
/// Darwin cannot raise this: OS invalidation there deletes the keychain item,
/// so `fetch` returns `null` rather than signalling an invalidated key.
final class KeyInvalidatedException extends OublietteException {
  /// The Keystore alias of the dead key (the profile's [keyAlias]).
  final String keyAlias;

  /// The underlying platform error, for diagnostics.
  final Object? cause;

  const KeyInvalidatedException({required this.keyAlias, this.cause});

  @override
  bool get recoverable => false;

  @override
  String toString() =>
      'KeyInvalidatedException: the profile hardware key was permanently '
      'invalidated (biometric enrollment or lock-screen change); the key and '
      'every secret under it are unrecoverable. Recover with purge() + init(). '
      'See the keyAlias/cause fields for diagnostics.';
}

/// Thrown when the profile's key alias does not exist at decrypt time — e.g.
/// the Android Keystore was cleared, or the app was restored from a backup
/// that carried `SharedPreferences` blobs but not the (non-backupable) key
/// material.
///
/// Distinct from [KeyInvalidatedException] (the key existed and the OS killed
/// it) and from [DecryptionFailedException] (the key exists but the ciphertext
/// failed authentication). The orphaned blob is unreadable: the library does
/// **not** silently mint a fresh key, as that would mask the cause behind an
/// opaque decrypt failure. Recovery is an explicit `purge()` + `init()` +
/// re-entry of the secret. Not recoverable by retry.
final class KeyNotFoundException extends OublietteException {
  /// The Keystore alias that was expected but absent.
  final String keyAlias;

  /// The underlying platform error, for diagnostics.
  final Object? cause;

  const KeyNotFoundException({required this.keyAlias, this.cause});

  @override
  bool get recoverable => false;

  @override
  String toString() =>
      'KeyNotFoundException: the profile hardware key does not exist, but a '
      'blob encrypted under it remains; the blob is unreadable. Recover with '
      'purge() + init(). See the keyAlias/cause fields for diagnostics.';
}

/// Thrown when authenticated decryption fails because the ciphertext did not
/// verify under the profile key — corrupted/truncated storage, a key mismatch,
/// or tampering the AEAD tag caught.
///
/// The key itself is intact (use [KeyInvalidatedException] / [KeyNotFoundException]
/// for key-level problems); it is this specific blob that cannot be read. Not
/// recoverable by retry.
final class DecryptionFailedException extends OublietteException {
  /// The logical key whose blob failed to decrypt.
  final String key;

  /// The underlying platform error, for diagnostics.
  final Object? cause;

  const DecryptionFailedException({required this.key, this.cause});

  @override
  bool get recoverable => false;

  @override
  String toString() =>
      'DecryptionFailedException: the stored blob for key "$key" failed '
      'authenticated decryption (corruption, key mismatch, or tampering). '
      'See the cause field for diagnostics.';
}

/// Thrown when a per-operation authentication gate is not satisfied — the user
/// cancelled or failed the biometric/credential prompt, or the device was
/// locked so no prompt could be shown (`interaction_not_allowed`).
///
/// **Recoverable**: the key and data are intact. Prompt again once the user is
/// ready / the device is unlocked. Never `purge()` in response — that would
/// destroy readable data because the user simply hasn't authenticated yet.
final class AuthenticationFailedException extends OublietteException {
  /// The logical key the operation targeted, if applicable.
  final String? key;

  /// `true` when the user explicitly cancelled the prompt (vs a failed match
  /// or a locked device).
  final bool cancelled;

  /// The underlying platform error, for diagnostics.
  final Object? cause;

  const AuthenticationFailedException({
    this.key,
    this.cancelled = false,
    this.cause,
  });

  @override
  bool get recoverable => true;

  @override
  String toString() =>
      'AuthenticationFailedException: authentication was not satisfied'
      '${cancelled ? ' (cancelled by user)' : ''}'
      '${key != null ? ' for key "$key"' : ''}. The data is intact — retry '
      'after the user authenticates. See the cause field for diagnostics.';
}
