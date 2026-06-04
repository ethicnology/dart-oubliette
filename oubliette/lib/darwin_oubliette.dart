import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:keychain/keychain.dart';
import 'package:oubliette/oubliette.dart';

class DarwinOubliette extends Oubliette {
  DarwinOubliette({required this.access})
      : _keychain = Keychain(config: access.toConfig()),
        super.internal();

  final DarwinSecretAccess access;
  final Keychain _keychain;

  /// Per-key serialization, mirroring the Android side. On Darwin `secItemAdd`
  /// already fails closed (`errSecDuplicateItem` → `already_exists`), so this
  /// is defense-in-depth / symmetry rather than the primary guard.
  final Map<String, Future<void>> _locks = {};

  String _storedKey(String key) => access.prefix + key;

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
      await _keychain.secItemAdd(_storedKey(key), value);
    });
  }

  @override
  Future<Uint8List?> fetch(String key) {
    return _keychain.secItemCopyMatching(_storedKey(key));
  }

  @override
  Future<void> trash(String key) async {
    await _keychain.secItemDelete(_storedKey(key));
  }

  @override
  Future<bool> exists(String key) {
    return _keychain.contains(_storedKey(key));
  }

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
