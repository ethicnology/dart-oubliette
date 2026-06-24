import 'package:flutter/foundation.dart';
import 'package:oubliette/android_oubliette.dart' show AndroidOubliette;
import 'package:oubliette/android_secret_access.dart';
import 'package:oubliette/darwin_oubliette.dart' show DarwinOubliette;
import 'package:oubliette/darwin_secret_access.dart';
import 'package:oubliette/linux_oubliette.dart' show LinuxOubliette;
import 'package:oubliette/linux_secret_access.dart';

export 'android_secret_access.dart';
export 'darwin_secret_access.dart';
export 'linux_secret_access.dart';
export 'src/passphrase_vault.dart' show PassphraseVault, Argon2idParams;
export 'src/errors.dart'
    show
        OublietteException,
        PayloadTamperException,
        PayloadCorruptException,
        KeyInvalidatedException,
        KeyNotFoundException,
        DecryptionFailedException,
        AuthenticationFailedException,
        BackendUnavailableException,
        KeyringLockedException;

/// Hardware-backed, device-local secret storage with a single, deliberately
/// small surface: [store] (write-once), [useAndForget] (read + auto-zero),
/// [trash] (delete one), [exists], and [purge] (destroy the whole profile).
///
/// Construct the [Oubliette] factory with a per-platform access profile; it
/// dispatches to the Keychain/Secure Enclave (Darwin), Android Keystore, or the
/// Secret Service (Linux) backend. Keys are minted lazily, so [init] is optional
/// (call it to surface backend errors eagerly).
///
/// **Design doctrine (load-bearing — see AGENTS.md):**
/// - **No `read()`** — plaintext is only ever exposed through [useAndForget],
///   which zeroes the buffer after your callback.
/// - **No `update()`/upsert** — [store] throws if the key exists; [trash] then
///   [store] to overwrite deliberately (avoids silently changing protection
///   attributes).
/// - **No silent fallback** — the library never makes a key/data decision for
///   you (hardware backing, per-op auth) and never silently downgrades.
/// - **Typed, fail-closed errors** — backend failures surface as sealed
///   [OublietteException]s; branch on [OublietteException.recoverable], never
///   answer a recoverable failure with the irreversible [purge].
///
/// For an at-rest passphrase/KEK layer on top of any backend, see
/// [PassphraseVault].
abstract class Oubliette {
  factory Oubliette({
    required AndroidSecretAccess android,
    required DarwinSecretAccess darwin,
    // Optional, with a default, unlike [android]/[darwin]. Those are required
    // because they carry security-relevant choices (hardware backing, per-op
    // auth) the library refuses to make for you. Linux has no such choice — the
    // Secret Service is a single software tier with no stronger alternative —
    // so the default only selects a storage-prefix namespace, not a posture.
    LinuxSecretAccess linux = const LinuxSecretAccess.onlyUnlocked(),
  }) {
    switch (defaultTargetPlatform) {
      case TargetPlatform.iOS:
      case TargetPlatform.macOS:
        return DarwinOubliette(access: darwin);
      case TargetPlatform.android:
        return AndroidOubliette(access: android);
      case TargetPlatform.linux:
        return LinuxOubliette(access: linux);
      default:
        throw UnsupportedError('Unsupported platform: $defaultTargetPlatform');
    }
  }

  Oubliette.internal();

  /// Ensures the platform encryption key exists, generating it if needed.
  ///
  /// Must be awaited once after construction and before any [store]/[fetch]
  /// call. Subsequent calls are no-ops (idempotent).
  Future<void> init();

  /// Encrypts [value] and writes it under [key].
  ///
  /// **Fail-closed, never overwrite:** if a value already exists for [key] this
  /// throws a [StateError] rather than silently replacing it — call [trash]
  /// first to deliberately overwrite. This prevents an accidental second
  /// `store()` from destroying a secret the caller still believes is present.
  ///
  /// Within a single isolate, concurrent `store()` calls for the *same* slot are
  /// serialized so exactly one first-write can win; see [purge] for the
  /// cross-isolate / cross-process caveat. The first-write check is a read
  /// ([exists]) followed by a write, which is **not atomic across processes**:
  /// on Darwin/Linux the native add itself fails closed on a duplicate
  /// (`errSecDuplicateItem` / `already_exists`), so a cross-process race that
  /// slips past the [exists] precheck surfaces that native `already_exists`
  /// rather than the in-isolate [StateError] — both mean "a value already
  /// exists; `trash()` first". (Android's `SharedPreferences` has no atomic
  /// put-if-absent, so a cross-process race there can silently overwrite — the
  /// in-isolate lock is the only guard.)
  ///
  /// Throws a typed [OublietteException] for backend failures (e.g.
  /// [KeyInvalidatedException], [AuthenticationFailedException]); branch on
  /// [OublietteException.recoverable] rather than string-matching.
  Future<void> store(String key, Uint8List value);

  /// Fetches and decrypts the raw bytes for [key], or `null` if absent.
  ///
  /// `@protected` because the bytes are an unmanaged plaintext buffer: read
  /// through [useAndForget] instead, which zeroes the buffer after use.
  @protected
  Future<Uint8List?> fetch(String key);

  /// Removes the single secret stored under [key]. A no-op if absent. Does not
  /// touch the profile's key material (use [purge] to destroy the whole
  /// profile). Backend failures surface as a typed [OublietteException].
  Future<void> trash(String key);

  /// Whether a secret is currently stored under [key].
  Future<bool> exists(String key);

  /// Destroys the **entire profile**: every secret stored under it *and* its
  /// key material. Irreversible — there is no recovery of the wiped secrets.
  ///
  /// Where [trash] removes one secret's blob, [purge] removes all of the
  /// profile's blobs (every slot sharing this profile's prefix).
  ///
  /// - **Android**: also deletes the profile's Keystore key (aliases are
  ///   per-profile, so this is safe). The profile is left empty and keyless.
  /// - **Darwin**: deletes only the blobs and **retains** the Secure Enclave
  ///   key. SE key identity is `(service, accessibility, accessGroup)` — it
  ///   excludes the prefix — so profiles differing only by prefix share one
  ///   key; deleting it could brick a sibling profile. The key is inert once
  ///   its blobs are gone and is never invalidated, so retaining it is safe.
  ///
  /// The primary use is recovering a profile wedged by a
  /// [KeyInvalidatedException] (the dead key blocks re-provisioning) and
  /// implementing a "forget everything" / logout flow. To resume using the
  /// profile afterwards, call [init] again to mint a fresh key:
  ///
  /// ```dart
  /// await vault.purge();
  /// await vault.init();
  /// ```
  ///
  /// Within a single isolate, [purge] serializes against in-flight [store]
  /// writes for the same profile — it drains them before destroying the
  /// profile, and writes started afterwards wait for it. This is **best-effort
  /// and isolate-scoped**: across isolates or processes there is no shared lock
  /// (SharedPreferences/Secret Service offer no cross-process transaction), so
  /// do not run [purge] concurrently with [store]/[fetch] on the same profile
  /// from another isolate or process.
  Future<void> purge();

  /// Lists the keys of every secret currently stored under this profile.
  ///
  /// Each entry is the key exactly as passed to [store] — the profile prefix and
  /// the reserved slot separator are stripped. Order is unspecified; an empty
  /// profile returns an empty list.
  ///
  /// This is the non-destructive counterpart to [purge]'s prefix scan: it reads
  /// only the storage *keys* (the SharedPreferences key / `kSecAttrAccount` /
  /// Secret Service `slot` attribute, all stored unencrypted for lookup), and
  /// never reads, decrypts, or returns any secret *value*. It exists so a caller
  /// can reconcile what it stored against an external index without a `read` API
  /// — distinct from the forbidden plain `read()` (see AGENTS.md), which would
  /// expose plaintext.
  ///
  /// Backend failures surface as a typed [OublietteException] (e.g. a locked
  /// keychain / keyring), never a raw platform exception.
  Future<List<String>> keys();

  /// Fetches the secret for [key], passes it to [action], then attempts to
  /// zero the buffer before returning — regardless of whether [action]
  /// succeeds or throws.
  ///
  /// Returns `null` if the key does not exist, otherwise returns the value
  /// produced by [action].
  ///
  /// ### What this covers
  /// - If the buffer is modifiable, it is zeroed (`fillRange(0)`) as soon as
  ///   [action] completes, so the plaintext bytes no longer sit in the Dart
  ///   heap at that address.
  /// - The caller cannot forget to clean up — zeroing happens in a `finally`
  ///   block even if [action] throws.
  ///
  /// ### What this does NOT cover
  /// - **Unmodifiable method channel buffers**: Flutter's
  ///   `FlutterStandardTypedData` may return an unmodifiable `Uint8List`.
  ///   When that happens the buffer cannot be zeroed. We do not create a
  ///   redundant copy just to zero it — that would leave *two* unzeroed
  ///   buffers instead of one.
  /// - **GC copies**: the Dart VM may relocate objects during garbage
  ///   collection (compaction). Previous memory locations keep stale bytes
  ///   until overwritten by something else.
  /// - **OS-level leaks**: swap, memory-mapped files, and core dumps may
  ///   persist the plaintext on disk.
  /// - **Compiler dead-store elimination**: in theory the JIT/AOT could
  ///   optimise away the `fillRange` call, though this is unlikely in
  ///   practice for `Uint8List`.
  Future<T?> useAndForget<T>(
    String key,
    Future<T> Function(Uint8List bytes) action,
  ) async {
    final bytes = await fetch(key);
    if (bytes == null) return null;
    try {
      return await action(bytes);
    } finally {
      try {
        bytes.fillRange(0, bytes.length, 0);
      } on UnsupportedError {
        // Method channel returned an unmodifiable buffer — cannot zero it.
      }
    }
  }
}
