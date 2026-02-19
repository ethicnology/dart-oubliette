/// Controls how secrets are protected on Android.
///
/// Use one of the factory constructors to select a security profile:
/// - [AndroidSecretAccess.evenLocked] — accessible even when the device is locked (after first unlock).
/// - [AndroidSecretAccess.onlyUnlocked] — accessible only while the device is unlocked.
/// - [AndroidSecretAccess.biometric] — requires biometric/credential auth; survives biometric enrollment changes.
/// - [AndroidSecretAccess.biometricFatal] — requires biometric/credential auth; key is permanently invalidated if biometric enrollment changes.
///
/// Each named profile uses a dedicated, hardcoded Keystore alias.
/// The [custom] constructor requires a unique alias that must not collide
/// with any reserved profile alias.
sealed class AndroidSecretAccess {
  const AndroidSecretAccess._({
    required this.prefix,
    required this.keyAlias,
    required this.strongBox,
  });

  static const _evenLockedKeyAlias = 'oubliette_even_locked';
  static const _onlyUnlockedKeyAlias = 'oubliette_only_unlocked';
  static const _biometricKeyAlias = 'oubliette_biometric';
  static const _biometricFatalKeyAlias = 'oubliette_biometric_fatal';

  static const _reservedKeyAliases = [
    _evenLockedKeyAlias,
    _onlyUnlockedKeyAlias,
    _biometricKeyAlias,
    _biometricFatalKeyAlias,
  ];

  /// Accessible even when the device is locked, as long as it has been
  /// unlocked at least once. Maps to `setUnlockedDeviceRequired(false)`
  /// on the `KeyGenParameterSpec`.
  const factory AndroidSecretAccess.evenLocked({
    String prefix,
    required bool strongBox,
  }) = _EvenLocked;

  /// Accessible only while the device is unlocked. Maps to
  /// `setUnlockedDeviceRequired(true)` on the `KeyGenParameterSpec`.
  const factory AndroidSecretAccess.onlyUnlocked({
    String prefix,
    required bool strongBox,
  }) = _OnlyUnlocked;

  /// Requires biometric or device credential authentication for every
  /// encrypt/decrypt operation. The key survives biometric enrollment
  /// changes (e.g. new fingerprint added).
  ///
  /// Requires `<uses-permission android:name="android.permission.USE_BIOMETRIC" />`
  /// in your app's `AndroidManifest.xml`. Only effective on API 30+ (Android 11).
  const factory AndroidSecretAccess.biometric({
    String prefix,
    required bool strongBox,
    required String promptTitle,
    required String promptSubtitle,
  }) = _Biometric;

  /// Requires biometric or device credential authentication for every
  /// encrypt/decrypt operation. The key is **permanently invalidated**
  /// if biometric enrollment changes — the secret becomes irrecoverable.
  ///
  /// Requires `<uses-permission android:name="android.permission.USE_BIOMETRIC" />`
  /// in your app's `AndroidManifest.xml`. Only effective on API 30+ (Android 11).
  const factory AndroidSecretAccess.biometricFatal({
    String prefix,
    required bool strongBox,
    required String promptTitle,
    required String promptSubtitle,
  }) = _BiometricFatal;

  /// Full manual control. [keyAlias] must not collide with reserved aliases.
  factory AndroidSecretAccess.custom({
    required String prefix,
    required String keyAlias,
    required bool strongBox,
    required bool unlockedDeviceRequired,
    required bool invalidatedByBiometricEnrollment,
    required String? promptTitle,
    required String? promptSubtitle,
  }) = _Custom;

  final String prefix;
  final String keyAlias;
  final bool strongBox;

  bool get unlockedDeviceRequired;
  bool get userAuthenticationRequired;
  bool get invalidatedByBiometricEnrollment;
  String? get promptTitle;
  String? get promptSubtitle;
}

class _EvenLocked extends AndroidSecretAccess {
  const _EvenLocked({
    super.prefix = 'oubliette_',
    required super.strongBox,
  }) : super._(keyAlias: AndroidSecretAccess._evenLockedKeyAlias);

  @override
  bool get unlockedDeviceRequired => false;
  @override
  bool get userAuthenticationRequired => false;
  @override
  bool get invalidatedByBiometricEnrollment => false;
  @override
  String? get promptTitle => null;
  @override
  String? get promptSubtitle => null;
}

class _OnlyUnlocked extends AndroidSecretAccess {
  const _OnlyUnlocked({
    super.prefix = 'oubliette_',
    required super.strongBox,
  }) : super._(keyAlias: AndroidSecretAccess._onlyUnlockedKeyAlias);

  @override
  bool get unlockedDeviceRequired => true;
  @override
  bool get userAuthenticationRequired => false;
  @override
  bool get invalidatedByBiometricEnrollment => false;
  @override
  String? get promptTitle => null;
  @override
  String? get promptSubtitle => null;
}

class _Biometric extends AndroidSecretAccess {
  const _Biometric({
    super.prefix = 'oubliette_',
    required super.strongBox,
    required this.promptTitle,
    required this.promptSubtitle,
  }) : super._(keyAlias: AndroidSecretAccess._biometricKeyAlias);

  @override
  bool get unlockedDeviceRequired => true;
  @override
  bool get userAuthenticationRequired => true;
  @override
  bool get invalidatedByBiometricEnrollment => false;
  @override
  final String promptTitle;
  @override
  final String promptSubtitle;
}

class _BiometricFatal extends AndroidSecretAccess {
  const _BiometricFatal({
    super.prefix = 'oubliette_',
    required super.strongBox,
    required this.promptTitle,
    required this.promptSubtitle,
  }) : super._(keyAlias: AndroidSecretAccess._biometricFatalKeyAlias);

  @override
  bool get unlockedDeviceRequired => true;
  @override
  bool get userAuthenticationRequired => true;
  @override
  bool get invalidatedByBiometricEnrollment => true;
  @override
  final String promptTitle;
  @override
  final String promptSubtitle;
}

class _Custom extends AndroidSecretAccess {
  _Custom({
    required super.prefix,
    required super.keyAlias,
    required super.strongBox,
    required this.unlockedDeviceRequired,
    required this.invalidatedByBiometricEnrollment,
    required this.promptTitle,
    required this.promptSubtitle,
  }) : super._() {
    if (AndroidSecretAccess._reservedKeyAliases.contains(keyAlias)) {
      throw ArgumentError(
        'keyAlias "$keyAlias" is reserved for a named profile. Use a unique alias.',
      );
    }
  }

  @override
  bool get userAuthenticationRequired => promptTitle != null;
  @override
  final bool unlockedDeviceRequired;
  @override
  final bool invalidatedByBiometricEnrollment;
  @override
  final String? promptTitle;
  @override
  final String? promptSubtitle;
}
