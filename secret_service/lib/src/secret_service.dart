import 'dart:convert';

import 'package:flutter/services.dart';

/// Typed Dart facade over the native Linux Secret Service plugin (libsecret).
///
/// Each secret is stored as a **distinct Secret Service item** keyed by its
/// `slot` attribute — never bundled into one shared blob (the design
/// `flutter_secure_storage` uses, which loses concurrent writes and has no
/// per-slot isolation). Item *values* are encrypted at rest by the keyring
/// provider (gnome-keyring, KWallet, …); item *attributes* (the slot string)
/// are stored unencrypted for lookup, so slot names are not secret.
///
/// This is a **software-encrypted tier** — the Linux analog of the macOS legacy
/// file-based keychain. It is not hardware-backed (see oubliette `SECURITY.md`).
///
/// ## Wire format
///
/// Values cross the method channel base64-encoded: the native Secret Service
/// simple API stores NUL-terminated strings, so arbitrary bytes (the oubliette
/// envelope) are base64-encoded here and decoded back on read. The native layer
/// only ever sees an ASCII string.
///
/// ## Errors
///
/// Native handlers raise [PlatformException] with stable codes:
/// - `backend_unavailable` — no session D-Bus / no `org.freedesktop.secrets`
///   provider (headless, minimal WM, no keyring daemon).
/// - `keyring_locked` — the default collection is locked and could not be
///   unlocked (no prompter, or the user dismissed the prompt).
/// - `auth_cancelled` — the user dismissed the unlock prompt.
/// - `already_exists` — [add] was called for a slot that already has an item.
/// - `bad_args` / `secret_service_error` — argument or libsecret failure.
final class SecretService {
  final MethodChannel _channel = const MethodChannel('secret_service');

  /// Whether an item exists for [slot].
  Future<bool> contains(String slot) async {
    final result = await _channel.invokeMethod<bool>('contains', {
      'slot': slot,
    });
    return result ?? false;
  }

  /// Stores [data] as the item for [slot]. Fails closed with a
  /// [PlatformException] of code `already_exists` if the slot is already
  /// present — there is no implicit overwrite (mirrors Darwin's
  /// `errSecDuplicateItem`).
  Future<void> add(String slot, Uint8List data) async {
    await _channel.invokeMethod<void>('write', {
      'slot': slot,
      'value': base64Encode(data),
    });
  }

  /// Returns the bytes stored for [slot], or `null` if absent.
  Future<Uint8List?> get(String slot) async {
    final value = await _channel.invokeMethod<String>('read', {'slot': slot});
    if (value == null) return null;
    return base64Decode(value);
  }

  /// Deletes the item for [slot]. A no-op if absent, but a locked/unavailable
  /// keyring **throws** rather than silently succeeding.
  Future<void> delete(String slot) async {
    await _channel.invokeMethod<void>('delete', {'slot': slot});
  }

  /// Deletes every item whose `slot` attribute begins with [prefix].
  ///
  /// The oubliette layer passes `profilePrefix + U+001D`, so ownership is
  /// exact: the reserved separator can only sit at the prefix/key boundary, and
  /// a sibling profile whose prefix nests under another's is never matched.
  Future<void> deleteByPrefix(String prefix) async {
    await _channel.invokeMethod<void>('deleteByPrefix', {'prefix': prefix});
  }
}
