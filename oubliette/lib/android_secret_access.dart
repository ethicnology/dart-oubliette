import 'package:meta/meta.dart';

import 'src/slot.dart';

const _evenLockedKeyAlias = 'oubliette_even_locked';
const _onlyUnlockedKeyAlias = 'oubliette_only_unlocked';
const _authenticatedKeyAlias = 'oubliette_authenticated';
const _authenticatedFatalKeyAlias = 'oubliette_authenticated_fatal';

const _evenLockedPrefix = 'oubliette_even_locked_';
const _onlyUnlockedPrefix = 'oubliette_only_unlocked_';
const _authenticatedPrefix = 'oubliette_authenticated_';
const _authenticatedFatalPrefix = 'oubliette_authenticated_fatal_';

const _reservedKeyAliases = [
  _evenLockedKeyAlias,
  _onlyUnlockedKeyAlias,
  _authenticatedKeyAlias,
  _authenticatedFatalKeyAlias,
];

/// Custom aliases already claimed by a `custom` profile in this isolate (L-2).
/// Two custom profiles sharing a Keystore alias would share key material:
/// `purge()` of one deletes the shared key and permanently bricks the other —
/// violating "purge() of one profile never touches another" (SECURITY.md). The
/// set is per-isolate (Dart has no cross-isolate shared state), so cross-
/// isolate / cross-process alias collisions are still the caller's
/// responsibility — documented on the `custom` constructor.
final Set<String> _customKeyAliases = <String>{};

const _reservedPrefixes = [
  _evenLockedPrefix,
  _onlyUnlockedPrefix,
  _authenticatedPrefix,
  _authenticatedFatalPrefix,
];

/// Controls how secrets are protected on Android.
///
/// Use one of the named constructors to select a security profile:
/// - [AndroidSecretAccess.evenLocked] — accessible even when the device is locked (after first unlock).
/// - [AndroidSecretAccess.onlyUnlocked] — accessible only while the device is unlocked.
/// - [AndroidSecretAccess.authenticated] — requires authentication (biometric/PIN/pattern/password); survives enrollment changes.
/// - [AndroidSecretAccess.authenticatedFatal] — requires **biometric-only** authentication (no credential fallback); key is permanently invalidated if biometric enrollment changes.
///
/// Each named profile uses a dedicated, hardcoded Keystore alias **and a
/// dedicated default storage prefix**. The prefix namespaces the
/// SharedPreferences slot (`prefix + separator + key`, see `slot.dart`) so the
/// same logical key stored under two different profiles never collides — slot
/// isolation is a security boundary, not a convenience. The [custom]
/// constructor requires a unique alias and prefix that must not collide with
/// any reserved profile value.
class AndroidSecretAccess {
  /// Prefix prepended to every SharedPreferences key used to store the
  /// encrypted payload. The resulting slot key (`prefix + separator + key`,
  /// built by `slot.dart`'s `buildSlot`) is also used as the AES-GCM AAD
  /// (Additional Authenticated Data).
  ///
  /// On fetch the AAD is **recomputed** from `prefix + separator + key` and
  /// compared against the value embedded in the stored blob; a mismatch throws
  /// [PayloadTamperException]. The AAD is therefore verify-only — it is never
  /// read back from disk to decide how to decrypt.
  ///
  /// Each named profile defaults to a distinct prefix so the same logical key
  /// cannot collide across security domains. Example:
  /// `evenLocked` + `key = 'token'` → `'oubliette_even_locked_token'`.
  final String prefix;

  /// Alias under which the AES-256 key is stored in the Android Keystore.
  /// Maps to the first argument of `KeyGenParameterSpec.Builder(alias, …)`.
  ///
  /// Each named profile (`evenLocked`, `onlyUnlocked`, `authenticated`,
  /// `authenticatedFatal`) uses a dedicated reserved alias. The [custom]
  /// constructor rejects any alias that collides with a reserved one.
  final String keyAlias;

  /// When `true`, requests that the key be generated inside a dedicated
  /// StrongBox Keymaster secure element (a separate, tamper-resistant chip)
  /// via `KeyGenParameterSpec.Builder.setIsStrongBoxBacked(true)`.
  ///
  /// StrongBox provides stronger isolation than a TEE but may not be present
  /// on all devices. This is **fail-closed**: if `strongBox` is `true` and the
  /// device lacks `PackageManager.FEATURE_STRONGBOX_KEYSTORE` (or generation
  /// throws `StrongBoxUnavailableException`), key generation fails with
  /// `strongbox_unavailable` — it never silently falls back to the TEE.
  ///
  /// Callers willing to accept a TEE-backed key must opt in explicitly, e.g.
  /// `strongBox: await Keystore().isStrongBoxAvailable()`.
  final bool strongBox;

  /// When `true`, the key is gated on the device being unlocked, via
  /// `KeyGenParameterSpec.Builder.setUnlockedDeviceRequired(true)`.
  ///
  /// **This gates decryption, not encryption.** Android allows an
  /// `UnlockedDeviceRequired` key to *encrypt* (and verify/wrap) while the
  /// screen is locked — only *decrypt* (and sign/unwrap) is blocked until the
  /// device is unlocked. So on the non-authenticated `onlyUnlocked` profile,
  /// `store()` can still succeed while the screen is locked (the secret is
  /// written, encrypted under the hardware key), but `fetch()` fails with a
  /// recoverable error until the user unlocks. To also gate *writes* on user
  /// presence, use an `authenticated` profile (`userAuthenticationRequired`),
  /// whose per-operation `BiometricPrompt` covers encrypt too.
  ///
  /// When `false`, the key remains usable after the first unlock since boot,
  /// even if the device is subsequently locked.
  ///
  /// **Best-effort on some OEMs.** `KeyInfo` exposes no read-back for
  /// `setUnlockedDeviceRequired`, so a non-conforming API-30 keymaster could
  /// silently no-op it, degrading the gate to "after first unlock since boot".
  /// When the unlocked-device gate must be guaranteed, use an `authenticated`
  /// profile — its per-operation `BiometricPrompt` is enforced by the prompt
  /// itself, not by the keymaster honoring this flag. (See SECURITY.md.)
  ///
  /// Requires API 29 (Android 10).
  final bool unlockedDeviceRequired;

  /// When `true`, every encrypt/decrypt operation requires the user to
  /// authenticate via biometric or device credential (PIN/pattern/password)
  /// immediately before use (timeout = 0).
  ///
  /// Implemented via `KeyGenParameterSpec.Builder.setUserAuthenticationRequired(true)`
  /// combined with `setUserAuthenticationParameters(0, AUTH_DEVICE_CREDENTIAL |
  /// AUTH_BIOMETRIC_STRONG)`. Always enforced — the `minSdk` floor is API 30
  /// (Android 11), so the requirement can never be silently dropped.
  ///
  /// For the [custom] constructor this is derived automatically:
  /// `userAuthenticationRequired = promptTitle != null`.
  final bool userAuthenticationRequired;

  /// When `true`, the key is **permanently and irrecoverably invalidated**
  /// whenever biometric enrollment changes — a new fingerprint is added,
  /// existing biometric data is removed, or Face data is updated.
  ///
  /// Maps to `KeyGenParameterSpec.Builder.setInvalidatedByBiometricEnrollment(true)`
  /// **and makes the key biometric-only** (`AUTH_BIOMETRIC_STRONG`, no
  /// PIN/pattern/password fallback). Keymaster only enforces enrollment
  /// invalidation for keys valid for biometric authentication *only* — a key
  /// that also accepts the device credential stays usable through it after a
  /// new biometric is enrolled, silently voiding the guarantee. Consequences:
  ///
  /// - generating the key **requires at least one enrolled biometric** (and
  ///   biometric hardware) — keygen fails otherwise;
  /// - the authentication prompt offers **no device-credential fallback**.
  ///
  /// After invalidation, any attempt to use the key throws
  /// `KeyPermanentlyInvalidatedException`, which is surfaced as
  /// `KeyInvalidatedException`. The encrypted payload cannot be recovered;
  /// the secret must be re-entered by the user.
  ///
  /// Only meaningful when [userAuthenticationRequired] is `true`.
  final bool invalidatedByBiometricEnrollment;

  /// Title displayed at the top of the authentication prompt dialog shown
  /// before each encrypt/decrypt operation. Maps to
  /// `BiometricPrompt.Builder.setTitle(promptTitle)`.
  ///
  /// When `null`, the authentication prompt is skipped entirely and
  /// [userAuthenticationRequired] is `false`. A non-null value enables
  /// per-operation authentication.
  ///
  /// Keep this short — it is the primary user-facing text explaining why
  /// authentication is needed (e.g. `"Unlock your vault"`).
  final String? promptTitle;

  /// Subtitle displayed below [promptTitle] in the authentication prompt
  /// dialog. Maps to `BiometricPrompt.Builder.setSubtitle(promptSubtitle)`.
  ///
  /// Provides secondary context or instructions (e.g. `"Use your fingerprint
  /// or PIN"`). Shown only when [promptTitle] is non-null. If `null`, the
  /// plugin substitutes the default `"Confirm your identity"`.
  final String? promptSubtitle;

  /// When `true`, key generation **refuses** a key that is not backed by secure
  /// hardware (TEE/StrongBox) — it deletes the key and fails with
  /// `hardware_unavailable` rather than keep a software-keystore key.
  ///
  /// **Required — no default** (an explicit security choice, like [strongBox]).
  /// On a real device the Android Keystore key is hardware-backed automatically
  /// regardless of this flag, so it only changes behaviour on a **software-only**
  /// keystore (emulators, some rooted/old devices): `false` → use it; `true` →
  /// refuse. Pass `true` for wallet-grade secrets that must never reside in
  /// software; pass `false` to allow software keystores (e.g. emulator/testing).
  /// (StrongBox remains independently fail-closed via [strongBox].)
  final bool requireHardwareBacking;

  const AndroidSecretAccess._({
    required this.prefix,
    required this.keyAlias,
    required this.strongBox,
    required this.unlockedDeviceRequired,
    required this.userAuthenticationRequired,
    required this.invalidatedByBiometricEnrollment,
    required this.promptTitle,
    required this.promptSubtitle,
    required this.requireHardwareBacking,
  });

  /// Accessible even when the device is locked, as long as it has been
  /// unlocked at least once. Maps to `setUnlockedDeviceRequired(false)`
  /// on the `KeyGenParameterSpec`.
  const AndroidSecretAccess.evenLocked({
    String prefix = _evenLockedPrefix,
    required bool strongBox,
    required bool requireHardwareBacking,
  }) : this._(
         prefix: prefix,
         keyAlias: _evenLockedKeyAlias,
         strongBox: strongBox,
         unlockedDeviceRequired: false,
         userAuthenticationRequired: false,
         invalidatedByBiometricEnrollment: false,
         promptTitle: null,
         promptSubtitle: null,
         requireHardwareBacking: requireHardwareBacking,
       );

  /// Accessible only while the device is unlocked. Maps to
  /// `setUnlockedDeviceRequired(true)` on the `KeyGenParameterSpec`.
  const AndroidSecretAccess.onlyUnlocked({
    String prefix = _onlyUnlockedPrefix,
    required bool strongBox,
    required bool requireHardwareBacking,
  }) : this._(
         prefix: prefix,
         keyAlias: _onlyUnlockedKeyAlias,
         strongBox: strongBox,
         unlockedDeviceRequired: true,
         userAuthenticationRequired: false,
         invalidatedByBiometricEnrollment: false,
         promptTitle: null,
         promptSubtitle: null,
         requireHardwareBacking: requireHardwareBacking,
       );

  /// Requires user authentication (biometric, PIN, pattern, or password)
  /// for every encrypt/decrypt operation. The key survives biometric
  /// enrollment changes (e.g. new fingerprint added).
  ///
  /// Requires `<uses-permission android:name="android.permission.USE_BIOMETRIC" />`
  /// in your app's `AndroidManifest.xml`.
  const AndroidSecretAccess.authenticated({
    String prefix = _authenticatedPrefix,
    required bool strongBox,
    required String promptTitle,
    required String promptSubtitle,
    required bool requireHardwareBacking,
  }) : this._(
         prefix: prefix,
         keyAlias: _authenticatedKeyAlias,
         strongBox: strongBox,
         unlockedDeviceRequired: true,
         userAuthenticationRequired: true,
         invalidatedByBiometricEnrollment: false,
         promptTitle: promptTitle,
         promptSubtitle: promptSubtitle,
         requireHardwareBacking: requireHardwareBacking,
       );

  /// Requires **biometric** authentication (no PIN/pattern/password fallback)
  /// for every encrypt/decrypt operation. The key is **permanently
  /// invalidated** if biometric enrollment changes — the secret becomes
  /// irrecoverable.
  ///
  /// Biometric-only is what makes the invalidation real: keymaster only
  /// invalidates keys that are valid for biometric auth *only*, so a
  /// credential fallback would let anyone who knows the PIN bypass the
  /// enrollment trip-wire (see [invalidatedByBiometricEnrollment]). This
  /// profile therefore requires biometric hardware **and at least one
  /// enrolled biometric at key-generation time**; if biometrics may be
  /// unavailable, use [AndroidSecretAccess.authenticated] instead.
  ///
  /// Requires `<uses-permission android:name="android.permission.USE_BIOMETRIC" />`
  /// in your app's `AndroidManifest.xml`.
  const AndroidSecretAccess.authenticatedFatal({
    String prefix = _authenticatedFatalPrefix,
    required bool strongBox,
    required String promptTitle,
    required String promptSubtitle,
    required bool requireHardwareBacking,
  }) : this._(
         prefix: prefix,
         keyAlias: _authenticatedFatalKeyAlias,
         strongBox: strongBox,
         unlockedDeviceRequired: true,
         userAuthenticationRequired: true,
         invalidatedByBiometricEnrollment: true,
         promptTitle: promptTitle,
         promptSubtitle: promptSubtitle,
         requireHardwareBacking: requireHardwareBacking,
       );

  /// Full manual control. [keyAlias] and [prefix] must not collide with the
  /// values reserved by the named profiles — distinct security domains require
  /// distinct slots and key material.
  AndroidSecretAccess.custom({
    required this.prefix,
    required this.keyAlias,
    required this.strongBox,
    required this.unlockedDeviceRequired,
    required this.invalidatedByBiometricEnrollment,
    required this.promptTitle,
    required this.promptSubtitle,
    required this.requireHardwareBacking,
  }) : userAuthenticationRequired = promptTitle != null {
    validateSlotPrefix(prefix);
    if (keyAlias.isEmpty) {
      throw ArgumentError.value(keyAlias, 'keyAlias', 'must not be empty');
    }
    if (_reservedKeyAliases.contains(keyAlias)) {
      throw ArgumentError(
        'keyAlias "$keyAlias" is reserved for a named profile. Use a unique alias.',
      );
    }
    // Fail-closed: `invalidatedByBiometricEnrollment` only has any effect on a
    // key whose authenticator set is biometric-only, and that set is selected
    // by `userAuthenticationRequired` — which is `true` only when `promptTitle`
    // is non-null. Passing `invalidatedByBiometricEnrollment: true` with
    // `promptTitle: null` would silently mint a no-auth key whose enrollment
    // trip-wire is a no-op: the caller asked for a protection and got none,
    // exactly the fail-open failure mode the README's *Fail-Closed
    // Authentication* section rules out (and the Darwin counterpart guards as
    // `biometryCurrentSetOnly && !authenticationRequired`).
    if (invalidatedByBiometricEnrollment && promptTitle == null) {
      throw ArgumentError.value(
        invalidatedByBiometricEnrollment,
        'invalidatedByBiometricEnrollment',
        'requires a non-null promptTitle (otherwise the key has no '
            'authentication requirement and the enrollment-invalidation '
            'flag is a silent no-op)',
      );
    }
    // Storage slots are `prefix + slotSeparator + key`. The separator's
    // position encodes the prefix length, so two *distinct* prefixes can never
    // produce colliding slots — even when one nests under the other. The only
    // genuine collision is an identical prefix (same slot namespace, different
    // key material), so reject exact equality with a reserved prefix. (Nested
    // reserved prefixes are also rejected as a conservative, no-cost guard.)
    for (final reserved in _reservedPrefixes) {
      if (prefix.startsWith(reserved) || reserved.startsWith(prefix)) {
        throw ArgumentError(
          'prefix "$prefix" collides with reserved profile prefix "$reserved" '
          '(one is a prefix of the other). Use a clearly distinct prefix.',
        );
      }
    }
    // L-2: reject a keyAlias already claimed by another custom profile in this
    // isolate. Two custom profiles sharing a Keystore alias share key material:
    // purge() of one deletes the key and bricks the other. The check is last so
    // that validation errors above throw BEFORE the alias is claimed (a
    // rejected constructor must not pollute the registry). Per-isolate only —
    // cross-isolate / cross-process collisions remain the caller's responsibility.
    if (!_customKeyAliases.add(keyAlias)) {
      throw ArgumentError.value(
        keyAlias,
        'keyAlias',
        'is already in use by another custom AndroidSecretAccess in this '
            'isolate. Two custom profiles must not share a Keystore alias — '
            'purge() of one would delete the shared key and brick the other. '
            'Use a unique alias per security domain.',
      );
    }
  }

  /// Clears the per-isolate custom-alias registry. For testing only: production
  /// code never needs to reset the registry (a custom profile's alias is
  /// claimed for the isolate's lifetime, which is the correct invariant —
  /// re-claiming it with a different security domain is exactly the collision
  /// this guard prevents).
  @visibleForTesting
  static void resetCustomAliasRegistry() => _customKeyAliases.clear();
}
