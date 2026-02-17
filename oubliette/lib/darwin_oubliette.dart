import 'dart:typed_data';

import 'package:keychain/keychain.dart';
import 'package:oubliette/oubliette.dart';

class DarwinOubliette extends Oubliette {
  DarwinOubliette({required this.access})
      : _keychain = Keychain(config: access.toConfig()),
        super.internal();

  final DarwinSecretAccess access;
  final Keychain _keychain;

  String _storedKey(String key) => access.prefix + key;

  @override
  Future<void> store(String key, Uint8List value) async {
    await _keychain.secItemAdd(_storedKey(key), value);
  }

  @override
  Future<Uint8List?> fetch(String key) async {
    final data = await _keychain.secItemCopyMatching(_storedKey(key));
    if (data == null) return null;
    return Uint8List.fromList(data);
  }

  @override
  Future<void> trash(String key) async {
    await _keychain.secItemDelete(_storedKey(key));
  }

  @override
  Future<bool> exists(String key) async {
    return _keychain.contains(_storedKey(key));
  }
}
