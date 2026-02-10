import 'package:flutter/services.dart';

enum KeychainAccessibility {
  whenUnlocked('whenUnlocked'),
  whenUnlockedThisDeviceOnly('whenUnlockedThisDeviceOnly'),
  afterFirstUnlock('afterFirstUnlock'),
  afterFirstUnlockThisDeviceOnly('afterFirstUnlockThisDeviceOnly'),
  whenPasscodeSetThisDeviceOnly('whenPasscodeSetThisDeviceOnly');

  final String _value;
  const KeychainAccessibility(this._value);
  String get value => _value;
}

class KeychainConfig {
  /// Configuration passed to every keychain operation.
  ///
  /// [service] maps to `kSecAttrService` and namespaces items so that
  /// the same alias in different services won't collide. When omitted,
  /// queries match any service.
  ///
  /// [accessibility] controls when keychain items are accessible relative
  /// to the device lock state. Defaults to [KeychainAccessibility.whenUnlockedThisDeviceOnly].
  ///
  /// [useDataProtection] enables `kSecUseDataProtectionKeychain` on macOS
  /// 10.15+, which uses the iOS-style data protection keychain instead of
  /// the legacy file-based keychain. Requires the `keychain-access-groups`
  /// entitlement and a valid code-signing identity. No effect on iOS.
  const KeychainConfig({
    this.service,
    this.accessibility = KeychainAccessibility.whenUnlockedThisDeviceOnly,
    this.useDataProtection = false,
  });

  /// `kSecAttrService` — namespaces keychain items by service identifier.
  final String? service;

  /// `kSecAttrAccessible` — when the keychain item is accessible.
  final KeychainAccessibility accessibility;

  /// macOS only — opts into the data protection keychain.
  final bool useDataProtection;

  Map<String, dynamic> toMap() => {
        if (service != null) 'service': service,
        'accessibility': accessibility.value,
        if (useDataProtection) 'useDataProtection': true,
      };
}

class Keychain {
  Keychain({KeychainConfig? config})
      : config = config ?? const KeychainConfig();

  final KeychainConfig config;
  final MethodChannel _channel = const MethodChannel('keychain');

  Map<String, dynamic> _args(String alias) => {
        'alias': alias,
        ...config.toMap(),
      };

  Future<bool> contains(String alias) async {
    final result = await _channel.invokeMethod<bool>(
      'keychainContains',
      _args(alias),
    );
    if (result != null) return result;

    throw PlatformException(
      code: 'keychain_contains_failed',
      message: 'Native keychain contains returned null.',
    );
  }

  Future<void> secItemAdd(String alias, Uint8List data) async {
    await _channel.invokeMethod<void>('secItemAdd', {
      ..._args(alias),
      'data': data,
    });
  }

  Future<Uint8List?> secItemCopyMatching(String alias) async {
    final result = await _channel.invokeMethod<Uint8List?>(
      'secItemCopyMatching',
      _args(alias),
    );
    return result;
  }

  Future<void> secItemDelete(String alias) async {
    await _channel.invokeMethod<void>('secItemDelete', _args(alias));
  }
}
