import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:oubliette/oubliette.dart';
import 'package:secret_service/secret_service.dart';

import 'src/slot.dart';

class LinuxOubliette extends Oubliette {
  LinuxOubliette({required this.access}) : super.internal();

  final LinuxSecretAccess access;
  final SecretService _service = SecretService();

  /// Per-slot serialization, mirroring the Android/Darwin sides. The native
  /// `add` already fails closed on a duplicate slot (`already_exists`), so this
  /// is defense-in-depth / symmetry. Static and keyed by the full slot so it
  /// spans separate instances within an isolate. (Cross-isolate / cross-process
  /// writes are unguarded — the Secret Service has no atomic put-if-absent.)
  static final Map<String, Future<void>> _locks = {};

  /// Profile-wide purge gate, keyed by `access.prefix`. `purge()` holds it while
  /// it drains in-flight per-slot writes and deletes the profile's items;
  /// `store()` waits on it first so a write cannot land an item a concurrent
  /// purge already enumerated past. Store-vs-store concurrency is preserved.
  /// Best-effort within an isolate; cross-isolate / cross-process is unguarded.
  static final Map<String, Future<void>> _purges = {};

  String _storedKey(String key) => buildSlot(access.prefix, key);

  /// FROZEN: the current Linux blob format version. Every value written to the
  /// Secret Service is prefixed with this 1-byte header — the same role as the
  /// Darwin format header and the Android `EncryptedPayload.version`. Secret
  /// Service items carry no envelope of their own, so without this header a
  /// future change to how Linux lays out its bytes could not be told apart from
  /// old data. Bump only by *adding* a reader; never reinterpret an existing
  /// value (append-only).
  static const int _linuxFormatV1 = 1;

  /// Prepends the [_linuxFormatV1] header to [value].
  Uint8List _wrap(Uint8List value) {
    final out = Uint8List(value.length + 1);
    out[0] = _linuxFormatV1;
    out.setRange(1, out.length, value);
    return out;
  }

  /// Strips and validates the format header. An unknown version means the blob
  /// was written by a newer release than this one can read — surfaced as a
  /// clear [PayloadCorruptException] rather than returning shifted bytes.
  Uint8List _unwrap(String key, Uint8List stored) {
    if (stored.isEmpty) {
      throw PayloadCorruptException('stored blob for key "$key" is empty');
    }
    final version = stored[0];
    if (version != _linuxFormatV1) {
      throw PayloadCorruptException(
        'stored blob for key "$key" has unknown Linux format version '
        '$version (this build reads v$_linuxFormatV1)',
      );
    }
    return Uint8List.sublistView(stored, 1);
  }

  @override
  Future<void> init() async {
    // No key material to provision on Linux (the Secret Service holds no
    // per-profile key we generate). Probe the backend so a misconfigured /
    // headless / locked environment fails fast here with a typed error rather
    // than on the first store/fetch. `contains` runs the native warmup
    // (open session + unlock default collection) and is otherwise a no-op.
    //
    // The probe key is a fixed, NUL-free reserved sentinel: `contains` is a
    // read-only existence check (it never writes), so any valid slot works; an
    // earlier revision used an embedded NUL here, which truncated at the C
    // string boundary (now rejected by buildSlot) and made this file register
    // as binary. The sentinel keeps the probe ASCII and self-describing.
    await _mapError(
      null,
      () => _service.contains(_storedKey('__oubliette_init_probe__')),
    );
    debugPrint(
      '[Oubliette] Linux Secret Service reachable (prefix: '
      '${access.prefix})',
    );
  }

  @override
  Future<void> store(String key, Uint8List value) {
    return _withKeyLock(key, () async {
      if (await exists(key)) {
        throw StateError(
          'A value already exists for key "$key". Call trash() first.',
        );
      }
      // The native `add` re-checks existence (search → store) and fails closed
      // with `already_exists` when it finds an item — unify that with the
      // precheck so store() throws ONE error type for the "already present"
      // condition, never a raw PlatformException.
      //
      // Scope caveat (matches the Android backend's SharedPreferences caveat and
      // the [_locks] comment above): the native search→store is NOT atomic and
      // libsecret has no atomic put-if-absent primitive — `secret_password_store`
      // upserts. The in-isolate [_locks] gate serializes same-slot writes, so
      // within an isolate exactly one creator wins and the rest see
      // `already_exists`. A *cross-process* writer that commits inside the native
      // search→store window is unguarded and last-writer-wins (the racing create
      // overwrites). This is the same documented cross-process limitation as
      // Android; do not assume cross-process create atomicity here.
      try {
        await _mapError(key, () => _service.add(_storedKey(key), _wrap(value)));
      } on PlatformException catch (e) {
        if (e.code == 'already_exists') {
          throw StateError(
            'A value already exists for key "$key". Call trash() first.',
          );
        }
        rethrow;
      }
    });
  }

  @override
  Future<Uint8List?> fetch(String key) async {
    final stored = await _mapError(key, () => _service.get(_storedKey(key)));
    if (stored == null) return null;
    return _unwrap(key, stored);
  }

  /// Translates native Secret Service error codes into typed
  /// [OublietteException]s so callers branch on `recoverable`.
  ///
  /// Deliberately-unmapped codes pass through as the raw [PlatformException] by
  /// design (never a data-recovery outcome):
  /// - `already_exists` — the native `add`'s fail-closed put-if-absent signal.
  ///   It is translated by [store] itself into the same `StateError` the
  ///   precheck throws, so it does not escape `store()` as a PlatformException;
  ///   it stays unmapped here because no other call path produces it.
  /// - `bad_args` — a contract/programming error in the channel call.
  /// Any genuinely-unknown code likewise rethrows untouched (never guess a typed
  /// meaning that could steer a caller toward purge()).
  Future<T> _mapError<T>(String? key, Future<T> Function() op) async {
    try {
      return await op();
    } on PlatformException catch (e) {
      switch (e.code) {
        case 'backend_unavailable':
          throw BackendUnavailableException(cause: e);
        // Generic libsecret/D-Bus failure (store/lookup/delete/search). The
        // data on disk is not known to be damaged — environmental, so it maps
        // recoverable and must never steer a caller toward purge().
        case 'secret_service_error':
          throw BackendUnavailableException(cause: e);
        // The per-op watchdog cancelled the call (the keyring did not respond
        // within the bounded window — typically a pending unlock prompt with no
        // agent). Transient and environmental like any other backend stall:
        // recoverable, fix the environment / retry, never purge.
        case 'keyring_timeout':
          throw BackendUnavailableException(cause: e);
        // The facade found the stored value tampered/non-base64 and refused
        // to decode it (it throws BEFORE any bytes reach _unwrap, so the
        // version-envelope check below never sees them).
        case 'payload_corrupt':
          throw PayloadCorruptException(
            'stored blob for key "$key" is not valid base64 (tampered?)',
          );
        case 'keyring_locked':
          throw KeyringLockedException(key: key, cause: e);
        case 'auth_cancelled':
          throw AuthenticationFailedException(
            key: key,
            cancelled: true,
            cause: e,
          );
      }
      rethrow;
    }
  }

  @override
  Future<void> trash(String key) async {
    // Never a silent no-op on a locked/unavailable keyring: the native side
    // runs warmup first and surfaces backend_unavailable / keyring_locked.
    await _mapError(key, () => _service.delete(_storedKey(key)));
  }

  @override
  Future<void> purge() => _withProfilePurge(() async {
    // Delete every item in this profile's slot namespace. Ownership is exact:
    // a slot belongs to this profile iff it begins with `prefix + slotSeparator`
    // — the separator's position encodes the prefix length, so a sibling whose
    // prefix nests under ours (e.g. `authenticated_` vs `authenticated_fatal_`)
    // is never matched. There is no per-profile key material to remove.
    await _mapError(
      null,
      () => _service.deleteByPrefix(access.prefix + slotSeparator),
    );
  });

  @override
  Future<bool> exists(String key) {
    return _mapError(key, () => _service.contains(_storedKey(key)));
  }

  @override
  Future<List<String>> keys() async {
    // The non-destructive twin of purge(): purge() calls deleteByPrefix on the
    // same owned prefix; keys() lists the matching slots instead. Routed through
    // _mapError so a locked/unavailable keyring surfaces as a typed exception.
    // Strip the owned prefix so the caller gets logical keys, not raw slots.
    final owned = access.prefix + slotSeparator;
    final slots = await _mapError(null, () => _service.listByPrefix(owned));
    return slots.map((s) => s.substring(owned.length)).toList(growable: false);
  }

  Future<T> _withKeyLock<T>(String key, Future<T> Function() body) async {
    final pendingPurge = _purges[access.prefix];
    if (pendingPurge != null) {
      try {
        await pendingPurge;
      } catch (_) {
        // A failed purge must not block subsequent writes.
      }
    }
    final lockKey = _storedKey(key);
    final prior = _locks[lockKey] ?? Future<void>.value();
    final release = Completer<void>();
    _locks[lockKey] = release.future;
    await prior;
    try {
      return await body();
    } finally {
      release.complete();
      if (identical(_locks[lockKey], release.future)) _locks.remove(lockKey);
    }
  }

  /// Runs a profile-destroying [body] under the profile-wide purge gate:
  /// serializes against other purges and drains in-flight per-slot writes for
  /// this profile first. New writes wait for it (see [_withKeyLock]).
  Future<void> _withProfilePurge(Future<void> Function() body) async {
    final gateKey = access.prefix;
    final prior = _purges[gateKey] ?? Future<void>.value();
    final release = Completer<void>();
    _purges[gateKey] = release.future;
    try {
      try {
        await prior;
      } catch (_) {
        // Prior purge failure must not block this one.
      }
      final owned = access.prefix + slotSeparator;
      final inflight = _locks.entries
          .where((e) => e.key.startsWith(owned))
          .map((e) => e.value)
          .toList();
      for (final f in inflight) {
        try {
          await f;
        } catch (_) {
          // A failed in-flight write must not block the purge.
        }
      }
      await body();
    } finally {
      release.complete();
      if (identical(_purges[gateKey], release.future)) _purges.remove(gateKey);
    }
  }
}
