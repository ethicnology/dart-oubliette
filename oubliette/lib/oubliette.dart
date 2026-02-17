import 'dart:io';
import 'dart:typed_data';

import 'package:meta/meta.dart';
import 'package:oubliette/android_oubliette.dart' show AndroidOubliette;
import 'package:oubliette/android_secret_access.dart';
import 'package:oubliette/darwin_oubliette.dart' show DarwinOubliette;
import 'package:oubliette/darwin_secret_access.dart';

export 'android_secret_access.dart';
export 'darwin_secret_access.dart';
export 'oubliette_string_extension.dart';

abstract class Oubliette {
  factory Oubliette({
    required AndroidSecretAccess android,
    required DarwinSecretAccess darwin,
  }) {
    switch (Platform.operatingSystem) {
      case 'ios':
      case 'macos':
        return DarwinOubliette(access: darwin);
      case 'android':
        return AndroidOubliette(access: android);
      default:
        throw UnsupportedError('Unsupported platform');
    }
  }

  Oubliette.internal();

  Future<void> store(String key, Uint8List value);

  @protected
  Future<Uint8List?> fetch(String key);

  Future<void> trash(String key);
  Future<bool> exists(String key);

  /// Fetches the secret for [key], passes it to [action], then zeroes the
  /// buffer before returning — regardless of whether [action] succeeds or
  /// throws.
  ///
  /// Returns `null` if the key does not exist, otherwise returns the value
  /// produced by [action].
  ///
  /// ### What this covers
  /// - The original `Uint8List` buffer is zeroed (`fillRange(0)`) as soon as
  ///   [action] completes, so the plaintext bytes no longer sit in the Dart
  ///   heap at that address.
  /// - The caller cannot forget to clean up — zeroing happens in a `finally`
  ///   block even if [action] throws.
  ///
  /// ### What this does NOT cover
  /// - **GC copies**: the Dart VM may relocate objects during garbage
  ///   collection (compaction). Previous memory locations keep stale bytes
  ///   until overwritten by something else.
  /// - **Method Channel buffers**: `FlutterStandardTypedData` creates
  ///   intermediate copies during native → Dart serialisation that are not
  ///   zeroed.
  /// - **OS-level leaks**: swap, memory-mapped files, and core dumps may
  ///   persist the plaintext on disk.
  /// - **Compiler dead-store elimination**: in theory the JIT/AOT could
  ///   optimise away the `fillRange` call, though this is unlikely in
  ///   practice for `Uint8List`.
  Future<T?> useAndForget<T>(String key, Future<T> Function(Uint8List bytes) action) async {
    final bytes = await fetch(key);
    if (bytes == null) return null;
    try {
      return await action(bytes);
    } finally {
      bytes.fillRange(0, bytes.length, 0);
    }
  }
}
