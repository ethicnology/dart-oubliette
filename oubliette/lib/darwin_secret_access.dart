import 'package:keychain/keychain.dart';

export 'package:keychain/keychain.dart' show KeychainAccessibility;

/// Controls how secrets are protected on iOS and macOS (Darwin).
///
/// Use one of the named constructors to select a security profile:
/// - [DarwinSecretAccess.evenLocked] — accessible even when the device is locked (after first unlock since boot).
/// - [DarwinSecretAccess.onlyUnlocked] — accessible only while the device is unlocked.
/// - [DarwinSecretAccess.authenticated] — requires authentication (biometric/passcode); survives enrollment changes.
/// - [DarwinSecretAccess.authenticatedFatal] — requires authentication; invalidated if biometric enrollment changes. Item destroyed if passcode removed.
///
/// ### macOS keychain backends
///
/// On macOS there are two keychain backends:
///
/// - **Legacy file-based keychain** (default when [useDataProtection] is `false`):
///   Works without code signing or entitlements. When [authenticationRequired]
///   is `true`, the system prompts for the user's macOS login password on
///   every read via `SecAccessControl` with `.userPresence`. No Touch ID
///   support on this backend.
///
/// - **Data Protection keychain** (when [useDataProtection] is `true`):
///   iOS-style keychain on macOS 10.15+. Supports Touch ID and biometric
///   policies via `SecAccessControl`. **Requires** the app to be code-signed
///   with a Development Certificate and the `keychain-access-groups`
///   entitlement — without this you get `errSecMissingEntitlement` (-34018).
///
/// The [authenticated] and [authenticatedFatal] profiles set
/// [useDataProtection] to `true` because they rely on Touch ID / Face ID
/// which is only available through the Data Protection keychain. If you only
/// need a macOS password prompt (no biometric), use
/// [DarwinSecretAccess.custom] with `authenticationRequired: true` and
/// `useDataProtection: false`.
const _defaultPrefix = 'oubliette_';

class DarwinSecretAccess {
  /// Prefix prepended to every storage key in the Keychain.
  final String prefix;

  /// `kSecAttrService` — namespaces keychain items so the same key in
  /// different services won't collide.
  final String? service;

  /// `kSecAttrAccessible` value controlling when the item is readable.
  final KeychainAccessibility accessibility;

  /// On macOS, switches to the iOS-style Data Protection keychain
  /// (`kSecUseDataProtectionKeychain`). Requires code signing and the
  /// `keychain-access-groups` entitlement. Ignored on iOS (always active).
  final bool useDataProtection;

  /// When `true`, a `SecAccessControl` is attached to the item requiring
  /// user authentication (biometric or password) on every read.
  final bool authenticationRequired;

  /// When `true`, uses `.biometryCurrentSet` instead of `.userPresence`.
  /// The item is invalidated if biometric enrollment changes (e.g. a new
  /// fingerprint is added). No passcode fallback.
  final bool biometryCurrentSetOnly;

  /// Reason displayed in the system authentication dialog when reading.
  final String? authenticationPrompt;

  /// When `true`, data is encrypted/decrypted using a Secure Enclave
  /// P-256 key via `eciesEncryptionCofactorX963SHA256AESGCM`. The
  /// private key never leaves the SE chip.
  final bool secureEnclave;

  /// `kSecAttrAccessGroup` — restricts which apps can access the item.
  final String? accessGroup;

  const DarwinSecretAccess._({
    required this.prefix,
    required this.service,
    required this.accessibility,
    required this.useDataProtection,
    required this.authenticationRequired,
    required this.biometryCurrentSetOnly,
    required this.authenticationPrompt,
    required this.secureEnclave,
    required this.accessGroup,
  });

  /// Accessible after the first unlock since boot, even when the device
  /// is locked. Maps to `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`.
  const DarwinSecretAccess.evenLocked({
    String prefix = _defaultPrefix,
    String? service,
    required bool secureEnclave,
  }) : this._(
         prefix: prefix,
         service: service,
         accessibility: KeychainAccessibility.afterFirstUnlockThisDeviceOnly,
         useDataProtection: false,
         authenticationRequired: false,
         biometryCurrentSetOnly: false,
         authenticationPrompt: null,
         secureEnclave: secureEnclave,
         accessGroup: null,
       );

  /// Accessible only while the device is unlocked. The class key is
  /// wiped from memory on lock. Maps to
  /// `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.
  const DarwinSecretAccess.onlyUnlocked({
    String prefix = _defaultPrefix,
    String? service,
    required bool secureEnclave,
  }) : this._(
         prefix: prefix,
         service: service,
         accessibility: KeychainAccessibility.whenUnlockedThisDeviceOnly,
         useDataProtection: false,
         authenticationRequired: false,
         biometryCurrentSetOnly: false,
         authenticationPrompt: null,
         secureEnclave: secureEnclave,
         accessGroup: null,
       );

  /// Requires user authentication (biometric or passcode) on every read.
  /// Survives biometric enrollment changes (e.g. new fingerprint).
  ///
  /// Sets [useDataProtection] to `true`. On macOS this uses the Data
  /// Protection keychain which requires code signing and entitlements.
  /// For a password-only prompt on unsigned macOS apps, use
  /// [DarwinSecretAccess.custom] with `useDataProtection: false`.
  const DarwinSecretAccess.authenticated({
    String prefix = _defaultPrefix,
    String? service,
    required String promptReason,
    required bool secureEnclave,
  }) : this._(
         prefix: prefix,
         service: service,
         accessibility: KeychainAccessibility.whenUnlockedThisDeviceOnly,
         useDataProtection: true,
         authenticationRequired: true,
         biometryCurrentSetOnly: false,
         authenticationPrompt: promptReason,
         secureEnclave: secureEnclave,
         accessGroup: null,
       );

  /// Requires user authentication on every read. The item is
  /// **invalidated** if biometric enrollment changes — the secret
  /// becomes irrecoverable. No passcode fallback.
  ///
  /// Uses `whenPasscodeSetThisDeviceOnly` — the item is destroyed by
  /// the OS if the user removes their passcode, providing the
  /// strictest protection level.
  ///
  /// Sets [useDataProtection] to `true`. On macOS this uses the Data
  /// Protection keychain which requires code signing and entitlements.
  const DarwinSecretAccess.authenticatedFatal({
    String prefix = _defaultPrefix,
    String? service,
    required String promptReason,
    required bool secureEnclave,
  }) : this._(
         prefix: prefix,
         service: service,
         accessibility: KeychainAccessibility.whenPasscodeSetThisDeviceOnly,
         useDataProtection: true,
         authenticationRequired: true,
         biometryCurrentSetOnly: true,
         authenticationPrompt: promptReason,
         secureEnclave: secureEnclave,
         accessGroup: null,
       );

  /// Full control over every keychain parameter.
  ///
  /// Useful for advanced combinations such as password-only prompts on
  /// unsigned macOS apps (`authenticationRequired: true`,
  /// `useDataProtection: false`).
  const DarwinSecretAccess.custom({
    required this.prefix,
    required this.service,
    required this.accessibility,
    required this.useDataProtection,
    required this.authenticationRequired,
    required this.biometryCurrentSetOnly,
    required this.authenticationPrompt,
    required this.secureEnclave,
    required this.accessGroup,
  });

  KeychainConfig toConfig() => KeychainConfig(
    service: service,
    accessibility: accessibility,
    useDataProtection: useDataProtection,
    authenticationRequired: authenticationRequired,
    biometryCurrentSetOnly: biometryCurrentSetOnly,
    authenticationPrompt: authenticationPrompt,
    secureEnclave: secureEnclave,
    accessGroup: accessGroup,
  );
}
