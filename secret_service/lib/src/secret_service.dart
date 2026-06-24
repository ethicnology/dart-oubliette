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
/// - `keyring_timeout` — a call was cancelled by the per-op watchdog (the
///   keyring did not respond within the bounded window). Recoverable; retry.
/// - `auth_cancelled` — the user dismissed the unlock prompt.
/// - `already_exists` — [add] was called for a slot that already has an item.
/// - `bad_args` / `secret_service_error` — argument or libsecret failure.
/// - `payload_corrupt` — raised by this facade (not native) when a stored
///   value is not valid base64 (external tampering/corruption). The raw
///   [FormatException] is deliberately suppressed: its message embeds a
///   snippet of the source string, which would leak stored secret material
///   into error logs.
final class SecretService {
  final MethodChannel _channel = const MethodChannel('secret_service');

  /// Rejects an embedded NUL (U+0000) in a slot/prefix before it crosses the
  /// channel. The native libsecret attribute / D-Bus string is a C string, so a
  /// NUL silently truncates the value there — breaking the byte-exact slot
  /// scoping (a truncated prefix could match foreign items; two distinct keys
  /// sharing a NUL-truncation prefix would collide into one item). The native
  /// plugin also rejects this as a defense-in-depth backstop (`bad_args`); this
  /// surfaces it early as a clear developer-facing [ArgumentError]. Mirrors the
  /// empty-prefix guard in [deleteByPrefix].
  static void _rejectNul(String value, String name) {
    if (value.codeUnits.contains(0)) {
      throw ArgumentError.value(value, name, 'must not contain a NUL (U+0000)');
    }
  }

  /// Whether an item exists for [slot].
  Future<bool> contains(String slot) async {
    _rejectNul(slot, 'slot');
    final result = await _channel.invokeMethod<bool>('contains', {
      'slot': slot,
    });
    if (result == null) {
      // The native handler always returns a bool; a null reply is a protocol
      // violation (malformed reply / misbehaving host). Fail closed rather
      // than reading it as "absent".
      throw PlatformException(
        code: 'secret_service_error',
        message: 'contains returned no result for slot "$slot"',
      );
    }
    return result;
  }

  /// Stores [data] as the item for [slot]. Fails closed with a
  /// [PlatformException] of code `already_exists` if the slot is already
  /// present — there is no implicit overwrite (mirrors Darwin's
  /// `errSecDuplicateItem`).
  Future<void> add(String slot, Uint8List data) async {
    _rejectNul(slot, 'slot');
    await _channel.invokeMethod<void>('write', {
      'slot': slot,
      'value': base64Encode(data),
    });
  }

  /// Returns the bytes stored for [slot], or `null` if absent.
  ///
  /// Throws a [PlatformException] of code `payload_corrupt` if the stored
  /// value is not valid base64 (an externally tampered/corrupted item).
  Future<Uint8List?> get(String slot) async {
    _rejectNul(slot, 'slot');
    final value = await _channel.invokeMethod<String>('read', {'slot': slot});
    if (value == null) return null;
    try {
      return base64Decode(value);
    } on FormatException {
      // Never rethrow the FormatException: its toString() embeds a snippet of
      // the source around the offending offset — i.e. the stored value, which
      // may be one flipped byte away from intact secret material. The slot
      // name is not secret (attributes are stored in the clear); the value
      // must never reach an error message or log.
      throw PlatformException(
        code: 'payload_corrupt',
        message: 'stored value for slot "$slot" is not valid base64',
      );
    }
  }

  /// Deletes the item for [slot]. A no-op if absent, but a locked/unavailable
  /// keyring **throws** rather than silently succeeding.
  Future<void> delete(String slot) async {
    _rejectNul(slot, 'slot');
    await _channel.invokeMethod<void>('delete', {'slot': slot});
  }

  /// Deletes every item whose `slot` attribute begins with [prefix].
  ///
  /// The oubliette layer passes `profilePrefix + U+001D`, so ownership is
  /// exact: the reserved separator can only sit at the prefix/key boundary, and
  /// a sibling profile whose prefix nests under another's is never matched.
  Future<void> deleteByPrefix(String prefix) async {
    _rejectNul(prefix, 'prefix');
    await _channel.invokeMethod<void>('deleteByPrefix', {'prefix': prefix});
  }

  /// Lists the `slot` attribute of every item whose slot begins with [prefix].
  ///
  /// The non-destructive twin of [deleteByPrefix] — same enumeration, but it
  /// returns the matching slot strings instead of deleting them. Slot
  /// attributes are stored unencrypted for lookup (they are not secret); item
  /// *values* are never loaded, decoded, or returned. The oubliette layer
  /// passes `profilePrefix + U+001D`, so ownership is exact.
  Future<List<String>> listByPrefix(String prefix) async {
    _rejectNul(prefix, 'prefix');
    final result = await _channel.invokeListMethod<String>('listByPrefix', {
      'prefix': prefix,
    });
    return result ?? const [];
  }
}
