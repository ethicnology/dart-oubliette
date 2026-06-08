import 'package:keychain/keychain.dart';

import 'src/slot.dart';

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
///   Works without code signing or entitlements, but does **not** support
///   access control. The file-based keychain rejects `kSecAttrAccessControl`,
///   so an authenticated write fails closed with `errSecParam` (-50).
///   Authentication is unavailable here — use this backend only for the
///   non-authenticated profiles (`evenLocked`, `onlyUnlocked`).
///
/// - **Data Protection keychain** (when [useDataProtection] is `true`):
///   iOS-style keychain on macOS 10.15+. The **only** macOS backend that
///   supports authentication (`SecAccessControl` — Touch ID / Face ID /
///   password). **Requires** the app to be code-signed with a Development
///   Certificate and the `keychain-access-groups` entitlement — without this
///   you get `errSecMissingEntitlement` (-34018).
///
/// The [authenticated] and [authenticatedFatal] profiles set
/// [useDataProtection] to `true` accordingly. On macOS, **any** authenticated
/// profile (including [custom] with `authenticationRequired: true`) requires
/// `useDataProtection: true` plus signing + entitlements; pairing
/// `authenticationRequired: true` with `useDataProtection: false` cannot work
/// and fails closed with `errSecParam`. (iOS always uses the data-protection
/// keychain, so the [useDataProtection] flag is ignored there.)
/// Per-profile default keychain account prefixes. Distinct prefixes keep the
/// same logical key in different security profiles from sharing a keychain
/// slot — critical on Darwin, where the read query carries no access-control
/// attribute, so the protection bound at write time is authoritative and a
/// shared slot would let a weaker profile read a stronger profile's item with
/// no prompt. Slot isolation is a security boundary here.
const _evenLockedPrefix = 'oubliette_even_locked_';
const _onlyUnlockedPrefix = 'oubliette_only_unlocked_';
const _authenticatedPrefix = 'oubliette_authenticated_';
const _authenticatedFatalPrefix = 'oubliette_authenticated_fatal_';

const _reservedPrefixes = [
  _evenLockedPrefix,
  _onlyUnlockedPrefix,
  _authenticatedPrefix,
  _authenticatedFatalPrefix,
];

/// The only accessibility classes Oubliette permits: every one keeps the item
/// strictly on **this device** — never synced to iCloud Keychain, never
/// restored to another device through an encrypted backup. A hardware-bound
/// secret must not outlive the device it was minted on (its key cannot leave
/// that device anyway, so a restored ciphertext would be undecryptable — and a
/// synced/backed-up secret is an exfiltration path). The four named profiles
/// already use one of these; the `custom` constructor rejects anything else.
const _deviceLocalAccessibility = {
  KeychainAccessibility.whenUnlockedThisDeviceOnly,
  KeychainAccessibility.afterFirstUnlockThisDeviceOnly,
  KeychainAccessibility.whenPasscodeSetThisDeviceOnly,
};

class DarwinSecretAccess {
  /// Prefix prepended to every storage key (`kSecAttrAccount`) in the
  /// Keychain. Each named profile defaults to a distinct prefix so the same
  /// logical key cannot collide across security domains.
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
    String prefix = _evenLockedPrefix,
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
    String prefix = _onlyUnlockedPrefix,
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
    String prefix = _authenticatedPrefix,
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
    String prefix = _authenticatedFatalPrefix,
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
  /// Useful for advanced combinations such as a custom [accessGroup] for
  /// app-group sharing or a non-default [accessibility]. [accessibility] **must**
  /// be a `*ThisDeviceOnly` class — `custom` rejects the syncable /
  /// backup-restorable variants (`whenUnlocked`, `afterFirstUnlock`) so a
  /// hardware-bound secret can never leave the device. Note: on macOS,
  /// `authenticationRequired: true` requires `useDataProtection: true` (plus
  /// code signing + entitlements) — the legacy file-based keychain cannot
  /// enforce authentication and will fail closed with `errSecParam`.
  DarwinSecretAccess.custom({
    required this.prefix,
    required this.service,
    required this.accessibility,
    required this.useDataProtection,
    required this.authenticationRequired,
    required this.biometryCurrentSetOnly,
    required this.authenticationPrompt,
    required this.secureEnclave,
    required this.accessGroup,
  }) {
    validateSlotPrefix(prefix);
    // Device-local only — for EVERY profile. A non-`ThisDeviceOnly` class
    // (`whenUnlocked`/`afterFirstUnlock`) would let the item ride an encrypted
    // backup to another device (where its hardware key cannot follow), so it is
    // both an exfiltration path and a guaranteed undecryptable-on-restore blob.
    if (!_deviceLocalAccessibility.contains(accessibility)) {
      throw ArgumentError.value(
        accessibility,
        'accessibility',
        'must be a *ThisDeviceOnly class (whenUnlockedThisDeviceOnly, '
        'afterFirstUnlockThisDeviceOnly, or whenPasscodeSetThisDeviceOnly) — '
        'Oubliette never stores a hardware-bound secret with a '
        'backup-restorable or syncable accessibility',
      );
    }
    // Keychain accounts are `prefix + slotSeparator + key`. The separator's
    // position encodes the prefix length, so two *distinct* prefixes can never
    // produce colliding accounts — even when one nests under the other. The
    // only genuine collision is an identical prefix (same slot, different
    // protection), so reject exact equality with a reserved prefix. On Darwin
    // slot isolation is the security boundary, so nested reserved prefixes are
    // also rejected as a conservative, no-cost guard.
    for (final reserved in _reservedPrefixes) {
      if (prefix.startsWith(reserved) || reserved.startsWith(prefix)) {
        throw ArgumentError(
          'prefix "$prefix" collides with reserved profile prefix "$reserved" '
          '(one is a prefix of the other). Use a clearly distinct prefix.',
        );
      }
    }
  }

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
