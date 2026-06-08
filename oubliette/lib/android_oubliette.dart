import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:keystore/keystore.dart';
import 'package:oubliette/oubliette.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'src/slot.dart';

class AndroidOubliette extends Oubliette {
  AndroidOubliette({required this.access}) : super.internal();

  final Keystore _keystore = Keystore();
  final AndroidSecretAccess access;

  /// Serializes `exists → encrypt → write` per storage slot so two concurrent
  /// `store()` calls for the same absent key cannot both pass the existence
  /// check and both write (`SharedPreferences.setString` overwrites silently —
  /// unlike Darwin's `secItemAdd`, there is no native fail-closed guard).
  ///
  /// Static and keyed by the full slot (`prefix + separator + key`) so the guarantee holds
  /// across *separate* `AndroidOubliette` instances in the same isolate, not
  /// just within one instance. (Cross-process writes remain unguarded — there
  /// is no atomic put-if-absent in SharedPreferences.)
  static final Map<String, Future<void>> _locks = {};

  String _storedKey(String key) => buildSlot(access.prefix, key);

  /// Generates the profile's Keystore key if it does not already exist.
  /// Idempotent and safe under concurrency: a lost race surfaces as
  /// `already_exists`, which is treated as success.
  Future<void> _ensureKey() async {
    if (await _keystore.containsAlias(access.keyAlias)) return;
    try {
      await _keystore.generateKey(
        alias: access.keyAlias,
        unlockedDeviceRequired: access.unlockedDeviceRequired,
        strongBox: access.strongBox,
        userAuthenticationRequired: access.userAuthenticationRequired,
        invalidatedByBiometricEnrollment: access.invalidatedByBiometricEnrollment,
      );
    } on PlatformException catch (e) {
      // A concurrent init/store already created the key — that is success,
      // matching the documented idempotent contract.
      if (e.code == 'already_exists') return;
      rethrow;
    }
  }

  @override
  Future<void> init() async {
    final existed = await _keystore.containsAlias(access.keyAlias);
    await _ensureKey();
    debugPrint(
      existed
          ? '[Oubliette] Android key already exists: ${access.keyAlias}'
          : '[Oubliette] Android key generated: ${access.keyAlias}',
    );
  }

  @override
  Future<void> store(String key, Uint8List value) {
    return _withKeyLock(key, () async {
      if (await exists(key)) {
        throw StateError('A value already exists for key "$key". Call trash() first.');
      }
      await _ensureKey();
      final storedKey = _storedKey(key);
      // If the profile key was permanently invalidated (biometric enrollment
      // changed on `authenticatedFatal`, or the secure lock screen was
      // disabled/reset), `encrypt` throws `key_invalidated`. We surface it as a
      // typed [KeyInvalidatedException] but never act on it: the library never
      // deletes key material on the developer's behalf — destroying a key is an
      // irreversible data-loss decision the caller must make explicitly.
      final ep = await _mapError(
        key,
        () => _keystore.encrypt(
          alias: access.keyAlias,
          plaintext: value,
          aad: storedKey,
          promptTitle: access.promptTitle,
          promptSubtitle: access.promptSubtitle,
        ),
      );
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(storedKey, ep.toJson());
    });
  }

  @override
  Future<Uint8List?> fetch(String key) async {
    final storedKey = _storedKey(key);
    final prefs = await SharedPreferences.getInstance();
    final payload = prefs.getString(storedKey);
    if (payload == null) return null;

    final EncryptedPayload ep;
    try {
      ep = EncryptedPayload.fromJson(payload);
    } on FormatException catch (e) {
      throw PayloadCorruptException(
        'stored blob for key "$key" is malformed: ${e.message}',
      );
    }

    // The stored blob lives in attacker-writable SharedPreferences, so its
    // routing metadata is never trusted to choose how it is decrypted. The
    // AAD and key alias are derived live from (profile, key); the payload's
    // copies are verify-only. A mismatch means the blob was relocated or its
    // decrypting key downgraded — refuse rather than authenticate it.
    if (ep.aad != storedKey || ep.keyAlias != access.keyAlias) {
      throw PayloadTamperException(
        key: key,
        expectedAad: storedKey,
        actualAad: ep.aad,
        expectedAlias: access.keyAlias,
        actualAlias: ep.keyAlias,
      );
    }

    // No _ensureKey() here: a present blob implies the key was created at
    // store() time. If the alias is genuinely gone (keystore cleared, restored
    // backup), regenerating would mint a fresh key and turn a clear
    // `key_not_found` into an opaque GCM `decrypt_failed` — so let decrypt
    // surface the real error instead.
    return _mapError(
      key,
      () => _keystore.decrypt(
        version: ep.version, // from disk: legitimately selects the scheme
        alias: access.keyAlias, // trusted, not ep.keyAlias
        ciphertext: ep.ciphertext,
        nonce: ep.nonce,
        aad: storedKey, // trusted, not ep.aad
        promptTitle: access.promptTitle,
        promptSubtitle: access.promptSubtitle,
      ),
    );
  }

  /// Runs [op] for logical [key] and translates known native error codes into
  /// typed [OublietteException]s so callers can branch on `recoverable` instead
  /// of string-matching `PlatformException.code`. Unknown codes pass through.
  Future<T> _mapError<T>(String key, Future<T> Function() op) async {
    try {
      return await op();
    } on PlatformException catch (e) {
      switch (e.code) {
        case 'key_invalidated':
          throw KeyInvalidatedException(keyAlias: access.keyAlias, cause: e);
        case 'key_not_found':
          throw KeyNotFoundException(keyAlias: access.keyAlias, cause: e);
        case 'decrypt_failed':
          throw DecryptionFailedException(key: key, cause: e);
        case 'auth_failed':
        case 'auth_error':
          throw AuthenticationFailedException(key: key, cause: e);
        case 'auth_cancelled': // forward-compat; not currently emitted here
          throw AuthenticationFailedException(
              key: key, cancelled: true, cause: e);
      }
      rethrow;
    }
  }

  @override
  Future<void> trash(String key) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_storedKey(key));
  }

  @override
  Future<void> purge() async {
    // Remove every blob in this profile's slot namespace, then the shared key.
    // Order matters only for cleanliness: even if key deletion fails, no
    // readable ciphertext is left behind.
    final prefs = await SharedPreferences.getInstance();
    // Slot ownership is exact: a slot belongs to this profile iff it begins
    // with `prefix + slotSeparator`. The separator's position encodes the
    // prefix length, so a sibling whose prefix nests under ours (e.g.
    // `authenticated_fatal_` vs `authenticated_`, or a custom `app_admin_`
    // under `app_`) never matches — its slots carry the separator at a
    // different offset. No exclude list is needed.
    final owned = access.prefix + slotSeparator;
    final slots = prefs.getKeys().where((k) => k.startsWith(owned)).toList();
    for (final slot in slots) {
      await prefs.remove(slot);
    }
    // Idempotent on the native side: deleting an absent alias is a no-op, so a
    // partially-wiped profile (e.g. dead key, blobs already gone) still clears.
    await _keystore.deleteEntry(access.keyAlias);
  }

  @override
  Future<bool> exists(String key) async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.containsKey(_storedKey(key));
  }

  /// Runs [body] after any in-flight operation for [key] completes, so same-key
  /// writes are serialized. Different keys run concurrently. The lock entry is
  /// removed once this call is the tail of the chain, bounding map growth.
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
