import 'package:flutter/foundation.dart';
import 'package:oubliette/android_oubliette.dart' show AndroidOubliette;
import 'package:oubliette/android_secret_access.dart';
import 'package:oubliette/darwin_oubliette.dart' show DarwinOubliette;
import 'package:oubliette/darwin_secret_access.dart';

export 'android_secret_access.dart';
export 'darwin_secret_access.dart';

abstract class Oubliette {
  factory Oubliette({
    required AndroidSecretAccess android,
    required DarwinSecretAccess darwin,
  }) {
    switch (defaultTargetPlatform) {
      case TargetPlatform.iOS:
      case TargetPlatform.macOS:
        return DarwinOubliette(access: darwin);
      case TargetPlatform.android:
        return AndroidOubliette(access: android);
      default:
        throw UnsupportedError('Unsupported platform: $defaultTargetPlatform');
    }
  }

  Oubliette.internal();

  /// Ensures the platform encryption key exists, generating it if needed.
  ///
  /// Must be awaited once after construction and before any [store]/[fetch]
  /// call. Subsequent calls are no-ops (idempotent).
  Future<void> init();

  Future<void> store(String key, Uint8List value);

  @protected
  Future<Uint8List?> fetch(String key);

  Future<void> trash(String key);
  Future<bool> exists(String key);

  /// Fetches the secret for [key], passes it to [action], then attempts to
  /// zero the buffer before returning — regardless of whether [action]
  /// succeeds or throws.
  ///
  /// Returns `null` if the key does not exist, otherwise returns the value
  /// produced by [action].
  ///
  /// ### What this covers
  /// - If the buffer is modifiable, it is zeroed (`fillRange(0)`) as soon as
  ///   [action] completes, so the plaintext bytes no longer sit in the Dart
  ///   heap at that address.
  /// - The caller cannot forget to clean up — zeroing happens in a `finally`
  ///   block even if [action] throws.
  ///
  /// ### What this does NOT cover
  /// - **Unmodifiable method channel buffers**: Flutter's
  ///   `FlutterStandardTypedData` may return an unmodifiable `Uint8List`.
  ///   When that happens the buffer cannot be zeroed. We do not create a
  ///   redundant copy just to zero it — that would leave *two* unzeroed
  ///   buffers instead of one.
  /// - **GC copies**: the Dart VM may relocate objects during garbage
  ///   collection (compaction). Previous memory locations keep stale bytes
  ///   until overwritten by something else.
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
      try {
        bytes.fillRange(0, bytes.length, 0);
      } on UnsupportedError {
        // Method channel returned an unmodifiable buffer — cannot zero it.
      }
    }
  }
}
