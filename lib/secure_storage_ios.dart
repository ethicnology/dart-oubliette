import 'dart:typed_data';

import 'package:secure_storage/ios_keychain/keychain_facade.dart';
import 'package:secure_storage/secure_storage_interface.dart';

class IosSecureStorage extends SecureStorage {
  IosSecureStorage({IosOptions? options})
      : options = options ?? const IosOptions(),
        super.internal();

  final IosOptions options;
  final KeychainFacade _keychain = KeychainFacade();

  String _storedKey(String key) => options.prefix + key;

  @override
  Future<void> store(String key, Uint8List value) async {
    await _keychain.secItemAdd(_storedKey(key), value);
  }

  @override
  Future<Uint8List?> fetch(String key) async {
    return _keychain.secItemCopyMatching(_storedKey(key));
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
