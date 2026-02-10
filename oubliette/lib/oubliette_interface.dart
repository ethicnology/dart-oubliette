import 'dart:typed_data';

const String defaultPrefix = 'oubliette';
const String defaultKeyAlias = 'default_key';

/// When provided to [AndroidOptions], every encrypt/decrypt operation
/// requires biometric or device credential authentication via
/// `BiometricPrompt`. The key is generated with
/// `setUserAuthenticationRequired(true)` and
/// `setInvalidatedByBiometricEnrollment(true)`.
///
/// Requires `<uses-permission android:name="android.permission.USE_BIOMETRIC" />`
/// in your app's `AndroidManifest.xml`. Only effective on API 30+ (Android 11);
/// on API 29 authentication is silently ignored.
class AndroidAuthentication {
  const AndroidAuthentication({
    required this.promptTitle,
    required this.promptSubtitle,
  });

  /// Title displayed on the biometric prompt dialog.
  final String promptTitle;

  /// Subtitle displayed on the biometric prompt dialog.
  final String promptSubtitle;
}

class AndroidOptions {
  const AndroidOptions({
    this.prefix = defaultPrefix,
    this.keyAlias = defaultKeyAlias,
    this.unlockedDeviceRequired = true,
    this.strongBox = false,
    this.authentication,
  });

  /// Prefix prepended to every storage key.
  final String prefix;

  /// Android Keystore alias used for the AES-256-GCM encryption key.
  final String keyAlias;

  /// When `true`, the hardware-backed key can only be used while the
  /// device is unlocked. Maps to `setUnlockedDeviceRequired` on the
  /// `KeyGenParameterSpec`.
  final bool unlockedDeviceRequired;

  /// When `true`, prefers StrongBox-backed key storage if the device
  /// supports it (`PackageManager.FEATURE_STRONGBOX_KEYSTORE`).
  /// Falls back silently to TEE if StrongBox is unavailable.
  final bool strongBox;

  /// When non-null, enables biometric/device credential authentication
  /// for every encrypt and decrypt operation.
  final AndroidAuthentication? authentication;

}

/// Common keychain options shared by iOS and macOS.
sealed class KeychainOptions {
  const KeychainOptions({
    this.prefix = defaultPrefix,
    this.service,
    this.unlockedDeviceRequired = true,
  });

  /// Prefix prepended to every storage key.
  final String prefix;

  /// `kSecAttrService` — namespaces keychain items so the same key in
  /// different services won't collide.
  final String? service;

  /// When `true`, keychain items use `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
  /// (class key is wiped from memory on lock). When `false`, items use
  /// `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` (class key persists
  /// in memory until reboot).
  final bool unlockedDeviceRequired;

  /// macOS only — opts into the data protection keychain.
  /// Override in [MacosOptions] to enable. Always `false` on iOS.
  bool get useDataProtection => false;
}

class IosOptions extends KeychainOptions {
  const IosOptions({
    super.prefix,
    super.service,
    super.unlockedDeviceRequired,
  });

}

class MacosOptions extends KeychainOptions {
  /// [useDataProtection] enables `kSecUseDataProtectionKeychain` on macOS
  /// 10.15+, which uses the iOS-style data protection keychain instead of
  /// the legacy file-based keychain. Requires the `keychain-access-groups`
  /// entitlement and a valid code-signing identity.
  const MacosOptions({
    super.prefix,
    super.service,
    super.unlockedDeviceRequired,
    this.useDataProtection = false,
  });

  @override
  final bool useDataProtection;

}

abstract class Oubliette {
  Oubliette.internal();

  Future<void> store(String key, Uint8List value);
  Future<Uint8List?> fetch(String key);
  Future<void> trash(String key);
  Future<bool> exists(String key);
}
