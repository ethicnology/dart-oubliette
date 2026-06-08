import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:keychain/keychain.dart';
import 'package:oubliette/oubliette.dart';

import 'src/slot.dart';

class DarwinOubliette extends Oubliette {
  DarwinOubliette({required this.access})
      : _keychain = Keychain(config: access.toConfig()),
        super.internal();

  final DarwinSecretAccess access;
  final Keychain _keychain;

  /// Per-slot serialization, mirroring the Android side. On Darwin `secItemAdd`
  /// already fails closed (`errSecDuplicateItem` → `already_exists`), so this
  /// is defense-in-depth / symmetry rather than the primary guard. Static and
  /// keyed by the full slot so it spans separate instances like Android's.
  static final Map<String, Future<void>> _locks = {};

  String _storedKey(String key) => buildSlot(access.prefix, key);

  /// FROZEN: the current Darwin blob format version. Every value written to the
  /// Keychain is prefixed with this 1-byte header. It mirrors the Android
  /// [EncryptedPayload] `version`: native Keychain items carry no format of
  /// their own, so without this header a future change to how Darwin lays out
  /// its bytes could not be told apart from old data — exactly the upgrade
  /// data-loss this library exists to prevent. Bump only by *adding* a reader
  /// for the new value; never reinterpret an existing one (append-only).
  static const int _darwinFormatV1 = 1;

  /// Prepends the [_darwinFormatV1] header to [value].
  Uint8List _wrap(Uint8List value) {
    final out = Uint8List(value.length + 1);
    out[0] = _darwinFormatV1;
    out.setRange(1, out.length, value);
    return out;
  }

  /// Strips and validates the format header. An unknown version means the blob
  /// was written by a newer release than this one can read — surfaced as a
  /// clear [PayloadCorruptException] rather than returning shifted bytes.
  Uint8List _unwrap(String key, Uint8List stored) {
    if (stored.isEmpty) {
      throw PayloadCorruptException('stored blob for key "$key" is empty');
    }
    final version = stored[0];
    if (version != _darwinFormatV1) {
      throw PayloadCorruptException(
        'stored blob for key "$key" has unknown Darwin format version '
        '$version (this build reads v$_darwinFormatV1)',
      );
    }
    return Uint8List.sublistView(stored, 1);
  }

  /// Ensures the Secure Enclave key pair exists when this profile uses it.
  /// No-op when [DarwinSecretAccess.secureEnclave] is false. Idempotent.
  Future<void> _ensureKey() async {
    if (!access.secureEnclave) return;
    await _keychain.ensureEnclaveKeyPair();
  }

  @override
  Future<void> init() async {
    if (!access.secureEnclave) return;
    final existed = await _keychain.ensureEnclaveKeyPair();
    debugPrint(
      existed
          ? '[Oubliette] Darwin SE key already exists (service: ${access.service})'
          : '[Oubliette] Darwin SE key generated (service: ${access.service})',
    );
  }

  @override
  Future<void> store(String key, Uint8List value) {
    return _withKeyLock(key, () async {
      if (await exists(key)) {
        throw StateError('A value already exists for key "$key". Call trash() first.');
      }
      await _ensureKey();
      await _mapError(
          key, () => _keychain.secItemAdd(_storedKey(key), _wrap(value)));
    });
  }

  @override
  Future<Uint8List?> fetch(String key) async {
    final stored =
        await _mapError(key, () => _keychain.secItemCopyMatching(_storedKey(key)));
    if (stored == null) return null;
    return _unwrap(key, stored);
  }

  /// Translates known native keychain error codes into typed
  /// [OublietteException]s so callers can branch on `recoverable`. Darwin does
  /// not raise [KeyInvalidatedException]/[KeyNotFoundException]: OS invalidation
  /// of a keychain item deletes it, surfacing as a `null` fetch. (One nuance:
  /// for Secure-Enclave profiles the native read path regenerates a missing SE
  /// key, so a lost SE key makes decryption fail as `se_decrypt_failed` →
  /// [DecryptionFailedException] rather than `null` — still fail-closed, never
  /// wrong data.) Unknown codes pass through.
  Future<T> _mapError<T>(String key, Future<T> Function() op) async {
    try {
      return await op();
    } on PlatformException catch (e) {
      switch (e.code) {
        case 'se_decrypt_failed':
          throw DecryptionFailedException(key: key, cause: e);
        case 'auth_failed':
        case 'interaction_not_allowed': // device locked — retry when unlocked
          throw AuthenticationFailedException(key: key, cause: e);
        case 'auth_cancelled':
          throw AuthenticationFailedException(
              key: key, cancelled: true, cause: e);
      }
      rethrow;
    }
  }

  @override
  Future<void> trash(String key) async {
    await _keychain.secItemDelete(_storedKey(key));
  }

  @override
  Future<void> purge() async {
    // Keychain has no "delete by account-prefix" query, so the native side
    // enumerates this profile's items (scoped by service/accessGroup) and
    // deletes those whose account begins with `prefix + slotSeparator`.
    // Ownership is exact: the separator's position encodes the prefix length,
    // so a sibling profile whose prefix nests under ours is never matched
    // (e.g. purging `authenticated` never wipes `authenticated_fatal`, nor a
    // custom `app_` ever wipe `app_admin_`). No exclude list is needed.
    await _keychain.deleteByPrefix(access.prefix + slotSeparator);
    // The Secure Enclave key is deliberately NOT deleted. Its identity is
    // (service, accessibility, accessGroup) — it does not include the prefix —
    // so two profiles that differ only by prefix share one key (e.g. the
    // default `onlyUnlocked` and `authenticated` both use
    // `whenUnlockedThisDeviceOnly`). Deleting it here could silently brick a
    // sibling profile. The key is also inert once its blobs are gone, and SE
    // keys are not subject to the `KeyInvalidatedException` wedge (they carry
    // only `.privateKeyUsage`), so there is no recovery reason to remove it.
  }

  @override
  Future<bool> exists(String key) {
    return _keychain.contains(_storedKey(key));
  }

  Future<T> _withKeyLock<T>(String key, Future<T> Function() body) async {
    final lockKey = _storedKey(key);
    final prior = _locks[lockKey] ?? Future<void>.value();
    final release = Completer<void>();
    _locks[lockKey] = release.future;
    await prior;
    try {
      return await body();
    } finally {
      release.complete();
      if (identical(_locks[lockKey], release.future)) _locks.remove(lockKey);
    }
  }
}
