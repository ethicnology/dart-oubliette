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

class Keychain {
  /// Creates a [Keychain] instance.
  ///
  /// [service] maps to `kSecAttrService` and namespaces items so that
  /// the same alias in different services won't collide. When omitted,
  /// queries match any service.
  ///
  /// [useDataProtection] enables `kSecUseDataProtectionKeychain` on macOS
  /// 10.15+, which uses the iOS-style data protection keychain instead of
  /// the legacy file-based keychain. Requires the `keychain-access-groups`
  /// entitlement and a valid code-signing identity. No effect on iOS.
  Keychain({this.service, this.useDataProtection = false});

  /// `kSecAttrService` — namespaces keychain items by service identifier.
  final String? service;

  /// macOS only — opts into the data protection keychain (`kSecUseDataProtectionKeychain`).
  final bool useDataProtection;
  final MethodChannel _channel = const MethodChannel('keychain');

  Map<String, dynamic> _baseArgs(String alias) => {
        'alias': alias,
        if (service != null) 'service': service,
        if (useDataProtection) 'useDataProtection': true,
      };

  Future<bool> contains(String alias) async {
    final result = await _channel.invokeMethod<bool>(
      'keychainContains',
      _baseArgs(alias),
    );
    if (result != null) return result;

    throw PlatformException(
      code: 'keychain_contains_failed',
      message: 'Native keychain contains returned null.',
    );
  }

  Future<void> secItemAdd(
    String alias,
    Uint8List data, {
    KeychainAccessibility accessibility =
        KeychainAccessibility.whenUnlockedThisDeviceOnly,
  }) async {
    await _channel.invokeMethod<void>('secItemAdd', {
      ..._baseArgs(alias),
      'data': data,
      'accessibility': accessibility.value,
    });
  }

  Future<Uint8List?> secItemCopyMatching(String alias) async {
    final result = await _channel.invokeMethod<Uint8List?>(
      'secItemCopyMatching',
      _baseArgs(alias),
    );
    return result;
  }

  Future<void> secItemDelete(String alias) async {
    await _channel.invokeMethod<void>('secItemDelete', _baseArgs(alias));
  }
}
