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
  final MethodChannel _channel = const MethodChannel('keychain');

  Future<bool> contains(String alias) async {
    final result = await _channel.invokeMethod<bool>('keychainContains', {
      'alias': alias,
    });
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
      'alias': alias,
      'data': data,
      'accessibility': accessibility.value,
    });
  }

  Future<Uint8List?> secItemCopyMatching(String alias) async {
    final result = await _channel.invokeMethod<Uint8List?>(
      'secItemCopyMatching',
      {'alias': alias},
    );
    return result;
  }

  Future<void> secItemDelete(String alias) async {
    await _channel.invokeMethod<void>('secItemDelete', {'alias': alias});
  }
}
