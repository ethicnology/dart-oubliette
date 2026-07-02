import 'src/slot.dart';

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

/// Controls how secrets are stored on Linux via the freedesktop Secret Service
/// (libsecret: gnome-keyring, KWallet, …).
///
/// ### Software tier — read this
///
/// Unlike Android (Keystore TEE/StrongBox) and iOS/macOS (Secure Enclave), the
/// Linux Secret Service is a **software-encrypted** keyring protected by your
/// login password — **not hardware-backed**. It is the Linux analog of the
/// macOS legacy file-based keychain. Once the keyring is unlocked (the normal
/// state after login), any process running as the same user can read every
/// stored secret over the session bus; there is no per-application isolation
/// and no per-operation authentication gate. See `SECURITY.md`.
///
/// Because there is only **one** real posture on Linux, this type deliberately
/// exposes a smaller surface than [DarwinSecretAccess]/`AndroidSecretAccess`:
///
/// - [evenLocked] / [onlyUnlocked] differ **only** in their storage prefix
///   (slot namespace). Secret Service has no lock-state accessibility class, so
///   their at-rest behavior is identical — both are readable whenever the
///   keyring is unlocked. The two names exist so the same cross-platform key
///   stays in its own namespace, matching the Darwin/Android profiles.
/// - There is **no** `authenticated`/`authenticatedFatal` profile: the Secret
///   Service has no per-operation biometric/credential gate bound to a key
///   (the `SecAccessControl` / `CryptoObject` analog). Rather than silently
///   degrade such a request to an unauthenticated store, the profile simply is
///   not offered — gate authentication in your app if you need it on Linux.
/// - There is **no** hardware-backing knob: Linux has no host-session
///   hardware-backed secret store, so requesting one is not expressible (it
///   would only ever fail closed).
///
/// Each named profile owns the same frozen prefix as its Darwin/Android
/// counterpart. The storage slot is `prefix + U+001D + key` (see `slot.dart`),
/// so `purge()` ownership stays exact even when one profile's prefix nests
/// under another's.
class LinuxSecretAccess {
  /// Prefix prepended to every storage slot (the Secret Service item's `slot`
  /// attribute). Each named profile defaults to a distinct prefix so the same
  /// logical key cannot collide across security domains.
  final String prefix;

  const LinuxSecretAccess._({required this.prefix});

  /// Stored in the default login keyring. On Linux this behaves identically to
  /// [onlyUnlocked] at rest (Secret Service has no lock-state class); it differs
  /// only in its slot namespace, matching the Darwin/Android `evenLocked`.
  const LinuxSecretAccess.evenLocked({String prefix = _evenLockedPrefix})
    : this._(prefix: prefix);

  /// Stored in the default login keyring. The default profile on Linux.
  const LinuxSecretAccess.onlyUnlocked({String prefix = _onlyUnlockedPrefix})
    : this._(prefix: prefix);

  /// Full manual control over the storage prefix. [prefix] must not collide
  /// with a reserved profile prefix (one being a prefix of the other) and must
  /// not contain the reserved slot separator.
  LinuxSecretAccess.custom({required this.prefix}) {
    validateSlotPrefix(prefix);
    // Storage slots are `prefix + slotSeparator + key`; the separator's
    // position encodes the prefix length, so two *distinct* prefixes can never
    // collide. Reject only an exact match with (or nesting of) a reserved
    // prefix — a conservative, no-cost guard mirroring the Darwin/Android side.
    for (final reserved in _reservedPrefixes) {
      if (prefix.startsWith(reserved) || reserved.startsWith(prefix)) {
        throw ArgumentError(
          'prefix "$prefix" collides with reserved profile prefix "$reserved" '
          '(one is a prefix of the other). Use a clearly distinct prefix.',
        );
      }
    }
  }
}
