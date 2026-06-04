import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:keystore/keystore.dart';
import 'package:oubliette/oubliette.dart';
import 'package:shared_preferences/shared_preferences.dart';

class AndroidOubliette extends Oubliette {
  AndroidOubliette({required this.access}) : super.internal();

  final Keystore _keystore = Keystore();
  final AndroidSecretAccess access;

  /// Serializes `exists → encrypt → write` per logical key so two concurrent
  /// `store()` futures for the same absent key cannot both pass the existence
  /// check and both write (SharedPreferences.setString overwrites silently).
  final Map<String, Future<void>> _locks = {};

  String _storedKey(String key) => access.prefix + key;

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
      final ep = await _keystore.encrypt(
        alias: access.keyAlias,
        plaintext: value,
        aad: storedKey,
        promptTitle: access.promptTitle,
        promptSubtitle: access.promptSubtitle,
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

    final ep = EncryptedPayload.fromJson(payload);

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

    await _ensureKey();
    return _keystore.decrypt(
      version: ep.version, // from disk: legitimately selects the scheme
      alias: access.keyAlias, // trusted, not ep.keyAlias
      ciphertext: ep.ciphertext,
      nonce: ep.nonce,
      aad: storedKey, // trusted, not ep.aad
      promptTitle: access.promptTitle,
      promptSubtitle: access.promptSubtitle,
    );
  }

  @override
  Future<void> trash(String key) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_storedKey(key));
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
    final prior = _locks[key] ?? Future<void>.value();
    final release = Completer<void>();
    _locks[key] = release.future;
    await prior;
    try {
      return await body();
    } finally {
      release.complete();
      if (identical(_locks[key], release.future)) _locks.remove(key);
    }
  }
}
