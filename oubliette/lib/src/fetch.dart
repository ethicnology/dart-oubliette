import 'dart:typed_data';

import 'package:meta/meta.dart';

import '../oubliette.dart';

/// Internal plaintext plumbing shared by the platform backends: declares the
/// raw [fetch] primitive and implements [Oubliette.useAndForget] on top of it.
///
/// **Why this lives under `lib/src/` and not on [Oubliette] itself:** the
/// public interface deliberately carries no plaintext-returning method — that
/// is the "no `read()`" doctrine (see AGENTS.md), and it must be structural,
/// not advisory. An abstract `fetch` on the public class would be guarded only
/// by `@protected` (a lint warning, not an error), so any caller could obtain
/// an unmanaged, never-zeroed plaintext buffer. Keeping the primitive in an
/// unexported mixin means the *interface* a caller holds simply has no such
/// member: the only way to read a secret through [Oubliette] is
/// [Oubliette.useAndForget], which zeroes the buffer after the callback.
///
/// The concrete platform classes still expose [fetch] as a member (Dart has no
/// package-private inheritance), so it stays `@protected` + `@internal` as
/// defense-in-depth for anyone holding a concrete backend type directly.
@internal
mixin OublietteFetch on Oubliette {
  /// Fetches and decrypts the raw bytes for [key], or `null` if absent.
  ///
  /// Internal primitive: the returned bytes are an unmanaged plaintext buffer
  /// that nothing will ever zero. All reads must go through
  /// [Oubliette.useAndForget] instead.
  @internal
  @protected
  Future<Uint8List?> fetch(String key);

  @override
  Future<T?> useAndForget<T>(
    String key,
    Future<T> Function(Uint8List bytes) action,
  ) async {
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
