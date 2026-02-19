import 'package:keychain/keychain.dart';

export 'package:keychain/keychain.dart' show KeychainAccessibility;

/// Controls how secrets are protected on iOS and macOS (Darwin).
///
/// Use one of the factory constructors to select a security profile:
/// - [DarwinSecretAccess.evenLocked] — accessible even when the device is locked (after first unlock since boot).
/// - [DarwinSecretAccess.onlyUnlocked] — accessible only while the device is unlocked.
/// - [DarwinSecretAccess.biometric] — requires biometric/passcode auth; survives biometric enrollment changes.
/// - [DarwinSecretAccess.biometricFatal] — requires biometric auth; invalidated if biometric enrollment changes. Item destroyed if passcode removed. No passcode fallback.
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
/// The [biometric] and [biometricFatal] profiles set [useDataProtection]
/// to `true` because they rely on Touch ID / Face ID which is only available
/// through the Data Protection keychain. If you only need a macOS password
/// prompt (no biometric), use [DarwinSecretAccess.custom] with
/// `authenticationRequired: true` and `useDataProtection: false`.
sealed class DarwinSecretAccess {
  const DarwinSecretAccess._({
    required this.prefix,
    required this.secureEnclave,
  });

  /// Accessible after the first unlock since boot, even when the device
  /// is locked. Maps to `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`.
  const factory DarwinSecretAccess.evenLocked({
    String prefix,
    String? service,
    required bool secureEnclave,
  }) = _EvenLocked;

  /// Accessible only while the device is unlocked. The class key is
  /// wiped from memory on lock. Maps to
  /// `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.
  const factory DarwinSecretAccess.onlyUnlocked({
    String prefix,
    String? service,
    required bool secureEnclave,
  }) = _OnlyUnlocked;

  /// Requires biometric or passcode authentication on every read.
  /// Survives biometric enrollment changes (e.g. new fingerprint).
  ///
  /// When [secureEnclave] is `true`, data is encrypted/decrypted
  /// using a Secure Enclave P-256 key.
  ///
  /// Sets [useDataProtection] to `true`. On macOS this uses the Data
  /// Protection keychain which requires code signing and entitlements.
  /// For a password-only prompt on unsigned macOS apps, use
  /// [DarwinSecretAccess.custom] with `useDataProtection: false`.
  const factory DarwinSecretAccess.biometric({
    String prefix,
    String? service,
    required String promptReason,
    required bool secureEnclave,
  }) = _Biometric;

  /// Requires biometric authentication on every read. The item is
  /// **invalidated** if biometric enrollment changes — the secret
  /// becomes irrecoverable. No passcode fallback.
  ///
  /// Uses `whenPasscodeSetThisDeviceOnly` — the item is destroyed by
  /// the OS if the user removes their passcode, providing the
  /// strictest protection level.
  ///
  /// When [secureEnclave] is `true`, data is encrypted/decrypted
  /// using a Secure Enclave P-256 key.
  ///
  /// Sets [useDataProtection] to `true`. On macOS this uses the Data
  /// Protection keychain which requires code signing and entitlements.
  const factory DarwinSecretAccess.biometricFatal({
    String prefix,
    String? service,
    required String promptReason,
    required bool secureEnclave,
  }) = _BiometricFatal;

  /// Full control over every keychain parameter.
  ///
  /// Useful for advanced combinations such as password-only prompts on
  /// unsigned macOS apps (`authenticationRequired: true`,
  /// `useDataProtection: false`).
  const factory DarwinSecretAccess.custom({
    required String prefix,
    required String? service,
    required KeychainAccessibility accessibility,
    required bool useDataProtection,
    required bool authenticationRequired,
    required bool biometryCurrentSetOnly,
    required String? authenticationPrompt,
    required bool secureEnclave,
    required String? accessGroup,
  }) = _Custom;

  /// Prefix prepended to every storage key in the Keychain.
  final String prefix;

  /// When `true`, data is encrypted/decrypted using a Secure Enclave
  /// P-256 key via `eciesEncryptionCofactorX963SHA256AESGCM`. The
  /// private key never leaves the SE chip.
  final bool secureEnclave;

  /// `kSecAttrService` — namespaces keychain items so the same key in
  /// different services won't collide.
  String? get service;

  /// `kSecAttrAccessible` value controlling when the item is readable.
  KeychainAccessibility get accessibility;

  /// On macOS, switches to the iOS-style Data Protection keychain
  /// (`kSecUseDataProtectionKeychain`). Requires code signing and the
  /// `keychain-access-groups` entitlement. Ignored on iOS (always active).
  bool get useDataProtection;

  /// When `true`, a `SecAccessControl` is attached to the item requiring
  /// user authentication (biometric or password) on every read.
  bool get authenticationRequired;

  /// When `true`, uses `.biometryCurrentSet` instead of `.userPresence`.
  /// The item is invalidated if biometric enrollment changes (e.g. a new
  /// fingerprint is added). No passcode fallback.
  bool get biometryCurrentSetOnly;

  /// Reason displayed in the system authentication dialog when reading.
  String? get authenticationPrompt;

  /// `kSecAttrAccessGroup` — restricts which apps can access the item.
  String? get accessGroup;

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

class _EvenLocked extends DarwinSecretAccess {
  const _EvenLocked({
    super.prefix = 'oubliette_',
    this.service,
    required super.secureEnclave,
  }) : super._();

  @override
  final String? service;
  @override
  KeychainAccessibility get accessibility => KeychainAccessibility.afterFirstUnlockThisDeviceOnly;
  @override
  bool get useDataProtection => false;
  @override
  bool get authenticationRequired => false;
  @override
  bool get biometryCurrentSetOnly => false;
  @override
  String? get authenticationPrompt => null;
  @override
  String? get accessGroup => null;
}

class _OnlyUnlocked extends DarwinSecretAccess {
  const _OnlyUnlocked({
    super.prefix = 'oubliette_',
    this.service,
    required super.secureEnclave,
  }) : super._();

  @override
  final String? service;
  @override
  KeychainAccessibility get accessibility => KeychainAccessibility.whenUnlockedThisDeviceOnly;
  @override
  bool get useDataProtection => false;
  @override
  bool get authenticationRequired => false;
  @override
  bool get biometryCurrentSetOnly => false;
  @override
  String? get authenticationPrompt => null;
  @override
  String? get accessGroup => null;
}

class _Biometric extends DarwinSecretAccess {
  const _Biometric({
    super.prefix = 'oubliette_',
    this.service,
    required String promptReason,
    required super.secureEnclave,
  }) : authenticationPrompt = promptReason,
       super._();

  @override
  final String? service;
  @override
  KeychainAccessibility get accessibility => KeychainAccessibility.whenUnlockedThisDeviceOnly;
  @override
  bool get useDataProtection => true;
  @override
  bool get authenticationRequired => true;
  @override
  bool get biometryCurrentSetOnly => false;
  @override
  final String authenticationPrompt;
  @override
  String? get accessGroup => null;
}

class _BiometricFatal extends DarwinSecretAccess {
  const _BiometricFatal({
    super.prefix = 'oubliette_',
    this.service,
    required String promptReason,
    required super.secureEnclave,
  }) : authenticationPrompt = promptReason,
       super._();

  @override
  final String? service;
  @override
  KeychainAccessibility get accessibility => KeychainAccessibility.whenPasscodeSetThisDeviceOnly;
  @override
  bool get useDataProtection => true;
  @override
  bool get authenticationRequired => true;
  @override
  bool get biometryCurrentSetOnly => true;
  @override
  final String authenticationPrompt;
  @override
  String? get accessGroup => null;
}

class _Custom extends DarwinSecretAccess {
  const _Custom({
    required super.prefix,
    required this.service,
    required this.accessibility,
    required this.useDataProtection,
    required this.authenticationRequired,
    required this.biometryCurrentSetOnly,
    required this.authenticationPrompt,
    required super.secureEnclave,
    required this.accessGroup,
  }) : super._();

  @override
  final String? service;
  @override
  final KeychainAccessibility accessibility;
  @override
  final bool useDataProtection;
  @override
  final bool authenticationRequired;
  @override
  final bool biometryCurrentSetOnly;
  @override
  final String? authenticationPrompt;
  @override
  final String? accessGroup;
}
