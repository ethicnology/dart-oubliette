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
  /// [biometryCurrentSetOnly] when `true`, uses the `.biometryCurrentSet` flag
  /// which invalidates items when biometric enrollment changes. It is only
  /// meaningful together with [authenticationRequired]; setting it with
  /// [authenticationRequired] `false` is **rejected** by `secItemAdd`
  /// (`biometry_requires_authentication`) rather than silently stored as an
  /// un-gated item — the strictest-sounding flag must never yield the weakest
  /// item.
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
  /// P-256 key via `eciesEncryptionCofactorVariableIVX963SHA256AESGCM`. The
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

  /// Tri-state existence probe: `true`/`false` only on a definite answer;
  /// anything else throws (never silently "false", which would misreport a
  /// stored secret as absent and typically trigger an overwrite flow).
  ///
  /// The probe never raises an auth prompt, and for [KeychainConfig.secureEnclave]
  /// profiles it checks the ciphertext *item* only — after a device migration
  /// the item can exist while the non-migratable SE key is gone, so `true`
  /// does not guarantee the value is decryptable (that surfaces on
  /// [secItemCopyMatching] as `se_key_missing`).
  ///
  /// LIMITATION on an `authenticationRequired` profile: the probe suppresses
  /// auth UI (`kSecUseAuthenticationUIFail`), and the OS answers a presence-gated
  /// item's existence query with `errSecInteractionNotAllowed` rather than a
  /// clean hit/miss — so `contains` on such a profile cannot return a definite
  /// `true`/`false` and instead throws `interaction_not_allowed`, *even when the
  /// device is unlocked and the item plainly exists*. Do not use `contains` as a
  /// silent existence precheck for authenticated profiles; rely on the
  /// fail-closed duplicate handling of the write path (`already_exists`) instead.
  ///
  /// Throws [PlatformException]: `interaction_not_allowed` (device locked, or an
  /// authenticated profile as above — retry when unlocked / authenticate to
  /// read), `missing_entitlement`, `sec_item_copy_failed`, `bad_args`.
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

  /// Ensures the Secure Enclave key pair for this config exists, generating it
  /// if needed.
  ///
  /// The SE key identity is scoped by service, accessibility, and access group
  /// — all three are sent so the native tag matches the one used on
  /// store/fetch, and so a profile change regenerates the key rather than
  /// silently reusing an old policy.
  ///
  /// Returns `true` if the key already existed, `false` if it was just
  /// created. `false` is the restore-detection signal — a fresh key cannot
  /// decrypt any pre-existing ciphertext — so an indeterminate outcome throws
  /// rather than masquerading as "just created".
  ///
  /// Throws [PlatformException]: `se_key_fetch_failed` (lookup errored — the
  /// key may be intact; retry, do not purge), `se_key_gen_failed`,
  /// `se_requires_device_only_accessibility`, `bad_args`.
  Future<bool> ensureEnclaveKeyPair() async {
    final result = await _channel.invokeMethod<bool>('ensureEnclaveKeyPair', {
      if (config.service != null) 'service': config.service,
      'accessibility': config.accessibility.value,
      if (config.accessGroup != null) 'accessGroup': config.accessGroup,
      // macOS: keep the SE key in the same keychain domain as the item.
      if (config.useDataProtection) 'useDataProtection': true,
    });
    if (result != null) return result;

    throw PlatformException(
      code: 'se_ensure_key_failed',
      message: 'Native ensureEnclaveKeyPair returned null.',
    );
  }

  /// Stores [data] under [alias]. Items are immutable — a second add for the
  /// same alias throws `already_exists` (call [secItemDelete] first).
  ///
  /// Throws [PlatformException]: `already_exists`, `se_key_gen_failed`,
  /// `se_encrypt_failed`, `access_control_failed`,
  /// `se_requires_device_only_accessibility`,
  /// `biometry_requires_authentication` (biometryCurrentSetOnly set without
  /// authenticationRequired), `macos_auth_requires_data_protection` (macOS),
  /// `interaction_not_allowed` (device locked), `missing_entitlement`,
  /// `sec_item_add_failed`, `bad_args`. On every `se_*` /
  /// `access_control_failed` / `biometry_requires_authentication` outcome
  /// nothing was stored (fail-closed).
  Future<void> secItemAdd(String alias, Uint8List data) async {
    await _channel.invokeMethod<void>('secItemAdd', {
      ..._args(alias),
      'data': data,
    });
  }

  /// Reads the value for [alias]; `null` means definitively not found.
  ///
  /// Throws [PlatformException]: `se_key_missing` (item present but the SE
  /// key is gone — e.g. after device migration; the ciphertext is permanently
  /// unreadable), `se_key_fetch_failed` (lookup errored — key may be intact,
  /// retry), `se_decrypt_failed`, `auth_cancelled`, `auth_failed`,
  /// `interaction_not_allowed` (device locked), `missing_entitlement`,
  /// `sec_item_copy_failed`, `bad_args`.
  Future<Uint8List?> secItemCopyMatching(String alias) async {
    final result = await _channel.invokeMethod<Uint8List>(
      'secItemCopyMatching',
      _args(alias),
    );
    return result;
  }

  /// Deletes the item for [alias]; deleting a missing item is a clean no-op.
  ///
  /// Throws [PlatformException]: `interaction_not_allowed` (device locked),
  /// `missing_entitlement`, `sec_item_delete_failed`, `bad_args`.
  Future<void> secItemDelete(String alias) async {
    await _channel.invokeMethod<void>('secItemDelete', _args(alias));
  }

  /// Deletes every keychain item in this config's scope whose account starts
  /// with [prefix] but does **not** start with any of [excludePrefixes].
  ///
  /// Callers that pass a separator-terminated [prefix] (the Oubliette layer
  /// passes `profilePrefix + U+001D`) get exact ownership for free: the
  /// separator can only sit at the prefix/key boundary, so wiping one profile
  /// can never match a nested sibling's accounts. [excludePrefixes] is an
  /// optional belt-and-suspenders list for callers that don't use a separator;
  /// it defaults to empty and is a no-op if nothing matches.
  ///
  /// Matching nothing is a clean no-op. Throws [PlatformException]:
  /// `interaction_not_allowed` (device locked), `missing_entitlement`,
  /// `sec_item_delete_failed`, `bad_args`.
  Future<void> deleteByPrefix(
    String prefix, {
    List<String> excludePrefixes = const [],
  }) async {
    // Reject an empty prefix: `hasPrefix("")` matches every account, so an empty
    // prefix would wipe every item in this config's scope (for a service-less,
    // group-less config, that is the app's entire generic-password class). The
    // Oubliette layer always passes a separator-terminated, non-empty prefix;
    // this is a defensive backstop for direct callers of the facade, mirroring
    // the native empty-prefix guard on the Linux backend.
    if (prefix.isEmpty) {
      throw ArgumentError.value(prefix, 'prefix', 'must not be empty');
    }
    await _channel.invokeMethod<void>('secItemDeleteByPrefix', {
      'prefix': prefix,
      'excludePrefixes': excludePrefixes,
      ...config.toMap(),
    });
  }

  /// Lists the `kSecAttrAccount` of every keychain item in this config's scope
  /// whose account starts with [prefix] but with **none** of [excludePrefixes].
  ///
  /// The non-destructive twin of [deleteByPrefix]: same enumeration query
  /// (`kSecMatchLimitAll` + `kSecReturnAttributes`), but it returns the matching
  /// account names instead of deleting them. Account names are not secret
  /// (they are the storage keys); item *values* are never read, returned, or
  /// decrypted — so this is not the forbidden plain `read()` (see AGENTS.md).
  ///
  /// Matching nothing returns an empty list. Throws [PlatformException]:
  /// `interaction_not_allowed` (device locked), `missing_entitlement`,
  /// `sec_item_copy_failed`, `bad_args`.
  Future<List<String>> listByPrefix(
    String prefix, {
    List<String> excludePrefixes = const [],
  }) async {
    // Same defensive empty-prefix guard as [deleteByPrefix]: an empty prefix
    // would match every account in scope. The Oubliette layer always passes a
    // separator-terminated, non-empty prefix.
    if (prefix.isEmpty) {
      throw ArgumentError.value(prefix, 'prefix', 'must not be empty');
    }
    final result = await _channel.invokeListMethod<String>(
      'secItemListByPrefix',
      {'prefix': prefix, 'excludePrefixes': excludePrefixes, ...config.toMap()},
    );
    return result ?? const [];
  }
}
