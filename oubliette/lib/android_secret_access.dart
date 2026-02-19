/// Controls how secrets are protected on Android.
///
/// Use one of the named constructors to select a security profile:
/// - [AndroidSecretAccess.evenLocked] — accessible even when the device is locked (after first unlock).
/// - [AndroidSecretAccess.onlyUnlocked] — accessible only while the device is unlocked.
/// - [AndroidSecretAccess.authenticated] — requires authentication (biometric/PIN/pattern/password); survives enrollment changes.
/// - [AndroidSecretAccess.authenticatedFatal] — requires authentication; key is permanently invalidated if biometric enrollment changes.
///
/// Each named profile uses a dedicated, hardcoded Keystore alias.
/// The [custom] constructor requires a unique alias that must not collide
/// with any reserved profile alias.
const _defaultPrefix = 'oubliette_';
const _evenLockedKeyAlias = 'oubliette_even_locked';
const _onlyUnlockedKeyAlias = 'oubliette_only_unlocked';
const _authenticatedKeyAlias = 'oubliette_authenticated';
const _authenticatedFatalKeyAlias = 'oubliette_authenticated_fatal';

const _reservedKeyAliases = [
  _evenLockedKeyAlias,
  _onlyUnlockedKeyAlias,
  _authenticatedKeyAlias,
  _authenticatedFatalKeyAlias,
];

class AndroidSecretAccess {
  /// Prefix prepended to every SharedPreferences key used to store the
  /// encrypted payload. Also used as AAD (Additional Authenticated Data)
  /// in the AES-GCM cipher, binding the ciphertext to its storage slot.
  ///
  /// Example: `prefix = 'oubliette_'` + `key = 'token'` → stored under
  /// `'oubliette_token'`.
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
  /// on all devices. Availability is checked at runtime via
  /// `PackageManager.FEATURE_STRONGBOX_KEYSTORE`; if the feature is absent
  /// the plugin silently falls back to the TEE-backed Keystore.
  ///
  /// Use `Keystore().isStrongBoxAvailable()` to decide whether to advertise
  /// the stronger guarantee in your UI.
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
  /// AUTH_BIOMETRIC_STRONG)`. Only enforced on API 30+ (Android 11); on
  /// earlier API levels the key is accessible without authentication.
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
  /// Requires API 24 (Android 7.0); enforced by this library on API 30+.
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
    String prefix = _defaultPrefix,
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
    String prefix = _defaultPrefix,
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
  /// in your app's `AndroidManifest.xml`. Only effective on API 30+ (Android 11).
  const AndroidSecretAccess.authenticated({
    String prefix = _defaultPrefix,
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
  /// in your app's `AndroidManifest.xml`. Only effective on API 30+ (Android 11).
  const AndroidSecretAccess.authenticatedFatal({
    String prefix = _defaultPrefix,
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

  /// Full manual control. [keyAlias] must not collide with reserved aliases.
  AndroidSecretAccess.custom({
    required this.prefix,
    required this.keyAlias,
    required this.strongBox,
    required this.unlockedDeviceRequired,
    required this.invalidatedByBiometricEnrollment,
    required this.promptTitle,
    required this.promptSubtitle,
  }) : userAuthenticationRequired = promptTitle != null {
    if (_reservedKeyAliases.contains(keyAlias)) {
      throw ArgumentError(
        'keyAlias "$keyAlias" is reserved for a named profile. Use a unique alias.',
      );
    }
  }
}
