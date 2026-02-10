import 'dart:io';

import 'package:oubliette/oubliette_android.dart'
    show AndroidOubliette;
import 'package:oubliette/oubliette_interface.dart';
import 'package:oubliette/oubliette_ios.dart' show IosOubliette;

export 'oubliette_interface.dart';
export 'oubliette_string_extension.dart';

enum OubliettePlatform { ios, macos, android }

OubliettePlatform get _currentPlatform {
  switch (Platform.operatingSystem) {
    case 'ios':
      return OubliettePlatform.ios;
    case 'macos':
      return OubliettePlatform.macos;
    case 'android':
      return OubliettePlatform.android;
    default:
      throw UnsupportedError('Unsupported platform');
  }
}

Oubliette createOubliette({
  AndroidOptions? androidOptions,
  IosOptions? iosOptions,
  MacosOptions? macosOptions,
}) {
  switch (_currentPlatform) {
    case OubliettePlatform.ios:
      return IosOubliette(options: iosOptions ?? const IosOptions());
    case OubliettePlatform.macos:
      return IosOubliette(options: macosOptions ?? const MacosOptions());
    case OubliettePlatform.android:
      return AndroidOubliette(
        options: androidOptions ?? const AndroidOptions(),
      );
  }
}
