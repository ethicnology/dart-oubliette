import 'dart:io';

import 'package:secure_storage/secure_storage_android.dart'
    show AndroidSecureStorage;
import 'package:secure_storage/secure_storage_interface.dart';
import 'package:secure_storage/secure_storage_ios.dart' show IosSecureStorage;

export 'secure_storage_interface.dart';
export 'secure_storage_string_extension.dart';

enum SecureStoragePlatform { ios, macos, android }

SecureStoragePlatform get _currentPlatform {
  switch (Platform.operatingSystem) {
    case 'ios':
      return SecureStoragePlatform.ios;
    case 'macos':
      return SecureStoragePlatform.macos;
    case 'android':
      return SecureStoragePlatform.android;
    default:
      throw UnsupportedError('Unsupported platform');
  }
}

SecureStorage createSecureStorage({
  AndroidOptions? androidOptions,
  IosOptions? iosOptions,
}) {
  switch (_currentPlatform) {
    case SecureStoragePlatform.ios:
    case SecureStoragePlatform.macos:
      return IosSecureStorage(options: iosOptions ?? const IosOptions());
    case SecureStoragePlatform.android:
      return AndroidSecureStorage(
        options: androidOptions ?? const AndroidOptions(),
      );
  }
}
