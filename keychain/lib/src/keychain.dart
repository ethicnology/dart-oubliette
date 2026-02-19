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
  ///
  /// [authenticationRequired] when `true`, the item is stored with a
  /// `SecAccessControl` that requires user presence (biometry or passcode).
  ///
  /// [biometryCurrentSetOnly] when `true` (and [authenticationRequired] is
  /// `true`), uses `.biometryCurrentSet` flag which invalidates items when
  /// biometric enrollment changes.
  ///
  /// [authenticationPrompt] reason string shown in the system authentication
  /// dialog when reading an authentication-protected item.
  const KeychainConfig({
    required this.service,
    required this.accessibility,
    required this.useDataProtection,
    required this.authenticationRequired,
    required this.biometryCurrentSetOnly,
    required this.authenticationPrompt,
    required this.secureEnclave,
    required this.accessGroup,
  });

  /// `kSecAttrService` — namespaces keychain items by service identifier.
  final String? service;

  /// `kSecAttrAccessible` — when the keychain item is accessible.
  final KeychainAccessibility accessibility;

  /// macOS only — opts into the data protection keychain.
  final bool useDataProtection;

  /// When `true`, items are protected by `SecAccessControl` with user
  /// presence (biometry / passcode).
  final bool authenticationRequired;

  /// When `true` and [authenticationRequired] is `true`, uses
  /// `.biometryCurrentSet` instead of `.userPresence`.
  final bool biometryCurrentSetOnly;

  /// Reason displayed in the system authentication dialog on read.
  final String? authenticationPrompt;

  /// When `true`, data is encrypted/decrypted using a Secure Enclave
  /// P-256 key via `eciesEncryptionCofactorX963SHA256AESGCM`. The
  /// ciphertext blob is stored in the Keychain; the private key never
  /// leaves the SE chip.
  final bool secureEnclave;

  /// `kSecAttrAccessGroup` — restricts which apps can access the item.
  final String? accessGroup;

  Map<String, dynamic> toMap() => {
        if (service != null) 'service': service,
        'accessibility': accessibility.value,
        if (useDataProtection) 'useDataProtection': true,
        if (authenticationRequired) 'authenticationRequired': true,
        if (biometryCurrentSetOnly) 'biometryCurrentSetOnly': true,
        if (authenticationPrompt != null)
          'authenticationPrompt': authenticationPrompt,
        if (secureEnclave) 'secureEnclave': true,
        if (accessGroup != null) 'accessGroup': accessGroup,
      };
}

/// There is no `secItemUpdate` — items are immutable once stored.
/// `SecAccessControl` is set at `secItemAdd` time and cannot be changed.
/// To replace a value, call [secItemDelete] then [secItemAdd].
final class Keychain {
  Keychain({required this.config});

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
    final result = await _channel.invokeMethod<Uint8List>(
      'secItemCopyMatching',
      _args(alias),
    );
    return result;
  }

  Future<void> secItemDelete(String alias) async {
    await _channel.invokeMethod<void>('secItemDelete', _args(alias));
  }
}
