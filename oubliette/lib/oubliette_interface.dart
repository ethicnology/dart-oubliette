import 'dart:typed_data';

const String defaultPrefix = 'oubliette';
const String defaultKeyAlias = 'default_key';

class AndroidOptions {
  const AndroidOptions({
    this.prefix = defaultPrefix,
    this.keyAlias = defaultKeyAlias,
    this.unlockedDeviceRequired = true,
  });

  /// Prefix prepended to every storage key.
  final String prefix;

  /// Android Keystore alias used for the AES-256-GCM encryption key.
  final String keyAlias;

  /// When `true`, the hardware-backed key can only be used while the
  /// device is unlocked. Maps to `setUnlockedDeviceRequired` on the
  /// `KeyGenParameterSpec`.
  final bool unlockedDeviceRequired;
}

class IosOptions {
  const IosOptions({
    this.prefix = defaultPrefix,
    this.service,
    this.unlockedDeviceRequired = true,
    this.useDataProtection = false,
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

  /// macOS only — opts into the data protection keychain
  /// (`kSecUseDataProtectionKeychain`). Requires the `keychain-access-groups`
  /// entitlement and a valid code-signing identity.
  final bool useDataProtection;
}

abstract class Oubliette {
  Oubliette.internal();

  Future<void> store(String key, Uint8List value);
  Future<Uint8List?> fetch(String key);
  Future<void> trash(String key);
  Future<bool> exists(String key);
}
