import 'dart:typed_data';

import 'package:secure_storage/android_keystore/encrypted_payload.dart';
import 'package:secure_storage/android_keystore/keystore_facade.dart';
import 'package:secure_storage/secure_storage_interface.dart';
import 'package:shared_preferences/shared_preferences.dart';

class AndroidSecureStorage extends SecureStorage {
  AndroidSecureStorage({required this.options}) : super.internal();

  final KeystoreFacade _keystore = KeystoreFacade();
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
      alias: options.keyAlias,
      ciphertext: ep.ciphertext,
      nonce: ep.nonce,
      aad: storedKey,
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
