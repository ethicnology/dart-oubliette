import 'dart:typed_data';

import 'package:keystore/keystore.dart';
import 'package:oubliette/oubliette_interface.dart';
import 'package:shared_preferences/shared_preferences.dart';

class AndroidOubliette extends Oubliette {
  AndroidOubliette({required this.options}) : super.internal();

  final Keystore _keystore = Keystore();
  final AndroidOptions options;

  String _storedKey(String key) => options.prefix + key;

  @override
  Future<void> store(String key, Uint8List value) async {
    final storedKey = _storedKey(key);
    final exists = await _keystore.containsAlias(options.keyAlias);
    if (!exists) {
      await _keystore.generateKey(
        alias: options.keyAlias,
        unlockedDeviceRequired: false,
      );
    }
    final ep = await _keystore.encrypt(
      alias: options.keyAlias,
      plaintext: value,
      aad: storedKey,
    );
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(storedKey, ep.toJson());
  }

  @override
  Future<Uint8List?> fetch(String key) async {
    final storedKey = _storedKey(key);
    final prefs = await SharedPreferences.getInstance();
    final payload = prefs.getString(storedKey);
    if (payload == null) return null;
    final ep = EncryptedPayloadMapper.fromJson(payload);
    return _keystore.decrypt(
      version: ep.version,
      alias: ep.alias,
      ciphertext: ep.ciphertext,
      nonce: ep.nonce,
      aad: ep.aad,
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
}
