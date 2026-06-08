import 'src/slot.dart';

/// Controls how secrets are protected on Android.
///
/// Use one of the named constructors to select a security profile:
/// - [AndroidSecretAccess.evenLocked] — accessible even when the device is locked (after first unlock).
/// - [AndroidSecretAccess.onlyUnlocked] — accessible only while the device is unlocked.
/// - [AndroidSecretAccess.authenticated] — requires authentication (biometric/PIN/pattern/password); survives enrollment changes.
/// - [AndroidSecretAccess.authenticatedFatal] — requires authentication; key is permanently invalidated if biometric enrollment changes.
///
/// Each named profile uses a dedicated, hardcoded Keystore alias **and a
/// dedicated default storage prefix**. The prefix namespaces the
/// SharedPreferences slot (`prefix + separator + key`, see `slot.dart`) so the
/// same logical key stored under two different profiles never collides — slot
/// isolation is a security
/// boundary, not a convenience. The [custom] constructor requires a unique
/// alias and prefix that must not collide with any reserved profile value.
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

const _reservedPrefixes = [
  _evenLockedPrefix,
  _onlyUnlockedPrefix,
  _authenticatedPrefix,
  _authenticatedFatalPrefix,
];

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

  /// When `true`, the key is only usable while the device is unlocked,
  /// via `KeyGenParameterSpec.Builder.setUnlockedDeviceRequired(true)`.
  /// Once the screen locks, any in-progress cipher operation will fail
  /// until the user unlocks again.
  ///
  /// When `false`, the key remains accessible after the first unlock since
  /// boot, even if the device is subsequently locked.
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
  /// Maps to `KeyGenParameterSpec.Builder.setInvalidatedByBiometricEnrollment(true)`.
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

  const AndroidSecretAccess._({
    required this.prefix,
    required this.keyAlias,
    required this.strongBox,
    required this.unlockedDeviceRequired,
    required this.userAuthenticationRequired,
    required this.invalidatedByBiometricEnrollment,
    required this.promptTitle,
    required this.promptSubtitle,
  });

  /// Accessible even when the device is locked, as long as it has been
  /// unlocked at least once. Maps to `setUnlockedDeviceRequired(false)`
  /// on the `KeyGenParameterSpec`.
  const AndroidSecretAccess.evenLocked({
    String prefix = _evenLockedPrefix,
    required bool strongBox,
  }) : this._(
         prefix: prefix,
         keyAlias: _evenLockedKeyAlias,
         strongBox: strongBox,
         unlockedDeviceRequired: false,
         userAuthenticationRequired: false,
         invalidatedByBiometricEnrollment: false,
         promptTitle: null,
         promptSubtitle: null,
       );

  /// Accessible only while the device is unlocked. Maps to
  /// `setUnlockedDeviceRequired(true)` on the `KeyGenParameterSpec`.
  const AndroidSecretAccess.onlyUnlocked({
    String prefix = _onlyUnlockedPrefix,
    required bool strongBox,
  }) : this._(
         prefix: prefix,
         keyAlias: _onlyUnlockedKeyAlias,
         strongBox: strongBox,
         unlockedDeviceRequired: true,
         userAuthenticationRequired: false,
         invalidatedByBiometricEnrollment: false,
         promptTitle: null,
         promptSubtitle: null,
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
  }) : this._(
         prefix: prefix,
         keyAlias: _authenticatedKeyAlias,
         strongBox: strongBox,
         unlockedDeviceRequired: true,
         userAuthenticationRequired: true,
         invalidatedByBiometricEnrollment: false,
         promptTitle: promptTitle,
         promptSubtitle: promptSubtitle,
       );

  /// Requires user authentication (biometric, PIN, pattern, or password)
  /// for every encrypt/decrypt operation. The key is **permanently
  /// invalidated** if biometric enrollment changes — the secret becomes
  /// irrecoverable.
  ///
  /// Requires `<uses-permission android:name="android.permission.USE_BIOMETRIC" />`
  /// in your app's `AndroidManifest.xml`.
  const AndroidSecretAccess.authenticatedFatal({
    String prefix = _authenticatedFatalPrefix,
    required bool strongBox,
    required String promptTitle,
    required String promptSubtitle,
  }) : this._(
         prefix: prefix,
         keyAlias: _authenticatedFatalKeyAlias,
         strongBox: strongBox,
         unlockedDeviceRequired: true,
         userAuthenticationRequired: true,
         invalidatedByBiometricEnrollment: true,
         promptTitle: promptTitle,
         promptSubtitle: promptSubtitle,
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
  }
}
