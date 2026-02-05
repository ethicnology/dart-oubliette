import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'secure_storage_platform_interface.dart';

/// An implementation of [SecureStoragePlatform] that uses method channels.
class MethodChannelSecureStorage extends SecureStoragePlatform {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('secure_storage');

  @override
  Future<String?> getPlatformVersion() async {
    final version = await methodChannel.invokeMethod<String>('getPlatformVersion');
    return version;
  }
}
