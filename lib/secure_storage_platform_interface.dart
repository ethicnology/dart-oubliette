import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'secure_storage_method_channel.dart';

abstract class SecureStoragePlatform extends PlatformInterface {
  /// Constructs a SecureStoragePlatform.
  SecureStoragePlatform() : super(token: _token);

  static final Object _token = Object();

  static SecureStoragePlatform _instance = MethodChannelSecureStorage();

  /// The default instance of [SecureStoragePlatform] to use.
  ///
  /// Defaults to [MethodChannelSecureStorage].
  static SecureStoragePlatform get instance => _instance;

  /// Platform-specific implementations should set this with their own
  /// platform-specific class that extends [SecureStoragePlatform] when
  /// they register themselves.
  static set instance(SecureStoragePlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  Future<String?> getPlatformVersion() {
    throw UnimplementedError('platformVersion() has not been implemented.');
  }
}
