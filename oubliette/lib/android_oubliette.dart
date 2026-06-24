import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:keystore/keystore.dart';
import 'package:oubliette/oubliette.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'src/slot.dart';

class AndroidOubliette extends Oubliette {
  AndroidOubliette({required this.access}) : super.internal();

  final Keystore _keystore = Keystore();
  final AndroidSecretAccess access;

  /// Serializes `exists → encrypt → write` per storage slot so two concurrent
  /// `store()` calls for the same absent key cannot both pass the existence
  /// check and both write (`SharedPreferences.setString` overwrites silently —
  /// unlike Darwin's `secItemAdd`, there is no native fail-closed guard).
  ///
  /// Static and keyed by the full slot (`prefix + separator + key`) so the guarantee holds
  /// across *separate* `AndroidOubliette` instances in the same isolate, not
  /// just within one instance. (Cross-process writes remain unguarded — there
  /// is no atomic put-if-absent in SharedPreferences.)
  static final Map<String, Future<void>> _locks = {};

  /// Profile-wide purge gate, keyed by `access.prefix`. `purge()` holds it
  /// while it drains in-flight per-slot writes and then destroys the profile;
  /// `store()` (via [_withKeyLock]) waits on it first, so a write cannot land a
  /// blob a concurrent purge already enumerated past (which would orphan it
  /// under the just-deleted key). Store-vs-store concurrency for different keys
  /// is preserved — stores only *wait on* the gate, they do not hold it.
  ///
  /// Best-effort WITHIN an isolate (like [_locks]): cross-isolate /
  /// cross-process purge-vs-store is unguarded — SharedPreferences has no
  /// cross-process transaction. The documented contract (see [Oubliette.purge])
  /// still stands; this only tightens the common single-isolate case.
  static final Map<String, Future<void>> _purges = {};

  String _storedKey(String key) => buildSlot(access.prefix, key);

  /// Generates the profile's Keystore key if it does not already exist.
  /// Idempotent and safe under concurrency: a lost race surfaces as
  /// `already_exists`, which is treated as success.
  Future<void> _ensureKey() async {
    if (await _keystore.containsAlias(access.keyAlias)) return;
    try {
      await _keystore.generateKey(
        alias: access.keyAlias,
        unlockedDeviceRequired: access.unlockedDeviceRequired,
        strongBox: access.strongBox,
        userAuthenticationRequired: access.userAuthenticationRequired,
        invalidatedByBiometricEnrollment:
            access.invalidatedByBiometricEnrollment,
        requireHardwareBacking: access.requireHardwareBacking,
      );
    } on PlatformException catch (e) {
      // A concurrent init/store already created the key — that is success,
      // matching the documented idempotent contract.
      if (e.code == 'already_exists') return;
      rethrow;
    }
  }

  @override
  Future<void> init() async {
    final existed = await _keystore.containsAlias(access.keyAlias);
    await _ensureKey();
    debugPrint(
      existed
          ? '[Oubliette] Android key already exists: ${access.keyAlias}'
          : '[Oubliette] Android key generated: ${access.keyAlias}',
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
      await _ensureKey();
      final storedKey = _storedKey(key);
      // If the profile key was permanently invalidated (biometric enrollment
      // changed on `authenticatedFatal`, or the secure lock screen was
      // disabled/reset), `encrypt` throws `key_invalidated`. We surface it as a
      // typed [KeyInvalidatedException] but never act on it: the library never
      // deletes key material on the developer's behalf — destroying a key is an
      // irreversible data-loss decision the caller must make explicitly.
      final ep = await _mapError(
        key,
        () => _keystore.encrypt(
          alias: access.keyAlias,
          plaintext: value,
          aad: storedKey,
          promptTitle: access.promptTitle,
          promptSubtitle: access.promptSubtitle,
          // The prompt's authenticator set is not chosen here: the native layer
          // derives it from the key's own KeyInfo (getUserAuthenticationType),
          // so the prompt and the key can never disagree. An
          // enrollment-invalidated key is biometric-only by construction and
          // already yields a BIOMETRIC_STRONG-only prompt.
        ),
      );
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(storedKey, ep.toJson());
    });
  }

  @override
  Future<Uint8List?> fetch(String key) async {
    final storedKey = _storedKey(key);
    final prefs = await SharedPreferences.getInstance();
    final payload = prefs.getString(storedKey);
    if (payload == null) return null;

    final EncryptedPayload ep;
    try {
      ep = EncryptedPayload.fromJson(payload);
    } on FormatException catch (e) {
      throw PayloadCorruptException(
        'stored blob for key "$key" is malformed: ${e.message}',
      );
    }

    // The stored blob lives in attacker-writable SharedPreferences, so its
    // routing metadata is never trusted to choose how it is decrypted. The
    // AAD and key alias are derived live from (profile, key); the payload's
    // copies are verify-only. A mismatch means the blob was relocated or its
    // decrypting key downgraded — refuse rather than authenticate it.
    if (ep.aad != storedKey || ep.keyAlias != access.keyAlias) {
      throw PayloadTamperException(
        key: key,
        expectedAad: storedKey,
        actualAad: ep.aad,
        expectedAlias: access.keyAlias,
        actualAlias: ep.keyAlias,
      );
    }

    // No _ensureKey() here: a present blob implies the key was created at
    // store() time. If the alias is genuinely gone (keystore cleared, restored
    // backup), regenerating would mint a fresh key and turn a clear
    // `key_not_found` into an opaque GCM `decrypt_failed` — so let decrypt
    // surface the real error instead.
    return _mapError(
      key,
      () => _keystore.decrypt(
        version: ep.version, // from disk: legitimately selects the scheme
        alias: access.keyAlias, // trusted, not ep.keyAlias
        ciphertext: ep.ciphertext,
        nonce: ep.nonce,
        aad: storedKey, // trusted, not ep.aad
        promptTitle: access.promptTitle,
        promptSubtitle: access.promptSubtitle,
        // The prompt's authenticator set comes from the key's KeyInfo, not from
        // here — see the store() path above.
      ),
    );
  }

  /// Runs [op] for logical [key] and translates known native error codes into
  /// typed [OublietteException]s so callers can branch on `recoverable` instead
  /// of string-matching `PlatformException.code`.
  ///
  /// Deliberately-unmapped codes pass through as the raw [PlatformException] by
  /// design — they are NOT operational/data-recovery outcomes and must never be
  /// reasoned about with `recoverable`/`purge()`:
  /// - `strongbox_unavailable`, `hardware_unavailable` — generation-time
  ///   fail-closed config errors (caller requested hardware the device cannot
  ///   provide). Deterministic; surfaced raw so the caller fixes the request.
  /// - `bad_args` — a contract/programming error in the channel call.
  /// - `already_exists` — only reachable from [_ensureKey]'s key-generation
  ///   race, where it is caught and treated as success; never escapes here.
  /// Any genuinely-unknown code likewise rethrows untouched (fail-closed: never
  /// guess a typed meaning that could steer a caller toward purge()).
  Future<T> _mapError<T>(String key, Future<T> Function() op) async {
    try {
      return await op();
    } on PlatformException catch (e) {
      switch (e.code) {
        case 'key_invalidated':
          throw KeyInvalidatedException(keyAlias: access.keyAlias, cause: e);
        case 'key_not_found':
          throw KeyNotFoundException(keyAlias: access.keyAlias, cause: e);
        case 'decrypt_failed':
          throw DecryptionFailedException(key: key, cause: e);
        // The encrypt path's catch-all (KeystorePlugin.handleEncrypt /
        // BiometricAuth): a generic Keystore/crypto failure that is NOT a known
        // key-loss (`key_invalidated`/`key_not_found` are caught before it) and
        // is NOT an auth-gate failure. The native layer documents it as
        // *apparently transient* (V1Scheme), and on the encrypt path nothing was
        // written, so the stored data is intact. Map it to the recoverable
        // BackendUnavailableException — never a raw PlatformException a caller
        // might answer with the data-destroying purge() path. (Decrypt's
        // `decrypt_failed` stays DecryptionFailedException: there the specific
        // on-disk blob failed to authenticate.)
        case 'encrypt_failed':
          throw BackendUnavailableException(cause: e);
        // The plugin was detached from the engine mid-operation (the crypto
        // looper was torn down before the work ran — KeystorePlugin.postCrypto).
        // Nothing was encrypted/decrypted and no data was touched, so it is a
        // transient, recoverable condition (retry on the next attach), exactly
        // like `encrypt_failed`. Map it to the recoverable
        // BackendUnavailableException rather than leaking a raw PlatformException
        // a caller might answer with the data-destroying purge() path.
        case 'detached':
          throw BackendUnavailableException(cause: e);
        // purge()'s key-deletion step failed (KeystorePlugin.deleteEntry). By
        // this point the profile's blobs are already removed, so no readable
        // ciphertext is left behind; the (now value-less) key surviving is a
        // transient/environmental condition. Map it to the recoverable
        // BackendUnavailableException for parity with Darwin/Linux purge()
        // (which route their native delete through _mapError), rather than
        // leaking a raw PlatformException only on Android.
        case 'delete_entry_failed':
          throw BackendUnavailableException(cause: e);
        // An UnlockedDeviceRequired (non-authenticated) key cannot DECRYPT while
        // the screen is locked: the native layer probes KeyguardManager and
        // emits `device_locked` instead of collapsing it into the fatal
        // `decrypt_failed`. The key and data are intact — it is recoverable
        // (retry once the device is unlocked), mirroring Darwin's
        // `interaction_not_allowed`. See AndroidSecretAccess.unlockedDeviceRequired,
        // which documents fetch() failing recoverably until unlock.
        case 'device_locked':
          throw AuthenticationFailedException(key: key, cause: e);
        // Too many failed biometric attempts locked biometry out (BiometricPrompt
        // ERROR_LOCKOUT / ERROR_LOCKOUT_PERMANENT, emitted by BiometricAuth). On
        // the biometric-only `authenticatedFatal` profile there is no credential
        // fallback, so the prompt is a dead-end until the user clears the lockout
        // by unlocking the device with the passcode. Recoverable (data intact,
        // never purge); the lockout flag lets the caller show that hint rather
        // than a bare "try again" — parity with Darwin's `biometry_lockout`.
        case 'biometry_lockout':
          throw AuthenticationFailedException(
            key: key,
            lockout: true,
            cause: e,
          );
        case 'auth_failed':
        case 'auth_error':
        // The native layer derives the prompt's allowed authenticators from the
        // key's own KeyInfo, and refuses (fail-closed, before any prompt) when
        // that authenticator set cannot be read. The key and data are intact —
        // it is recoverable like any other unsatisfied auth gate; never purge().
        case 'key_auth_type_unknown':
          throw AuthenticationFailedException(key: key, cause: e);
        case 'auth_cancelled': // emitted by BiometricAuth for user-cancel codes
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
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_storedKey(key));
  }

  @override
  Future<void> purge() => _withProfilePurge(() async {
    // Remove every blob in this profile's slot namespace, then the shared key.
    // Order matters only for cleanliness: even if key deletion fails, no
    // readable ciphertext is left behind.
    final prefs = await SharedPreferences.getInstance();
    // Slot ownership is exact: a slot belongs to this profile iff it begins
    // with `prefix + slotSeparator`. The separator's position encodes the
    // prefix length, so a sibling whose prefix nests under ours (e.g.
    // `authenticated_fatal_` vs `authenticated_`, or a custom `app_admin_`
    // under `app_`) never matches — its slots carry the separator at a
    // different offset. No exclude list is needed.
    final owned = access.prefix + slotSeparator;
    final slots = prefs.getKeys().where((k) => k.startsWith(owned)).toList();
    for (final slot in slots) {
      await prefs.remove(slot);
    }
    // Idempotent on the native side: deleting an absent alias is a no-op, so a
    // partially-wiped profile (e.g. dead key, blobs already gone) still clears.
    // Routed through _mapError so a native delete failure surfaces as a typed
    // (recoverable) OublietteException, matching Darwin/Linux purge().
    await _mapError('<purge>', () => _keystore.deleteEntry(access.keyAlias));
  });

  @override
  Future<bool> exists(String key) async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.containsKey(_storedKey(key));
  }

  @override
  Future<List<String>> keys() async {
    // Pure Dart — SharedPreferences is reachable here, so no native call. Mirror
    // purge()'s ownership rule exactly: a slot belongs to this profile iff it
    // begins with `prefix + slotSeparator` (the separator's position encodes the
    // prefix length, so a nested sibling never matches). Return the logical keys
    // with that owned-prefix stripped — never the raw slots, never any value.
    final prefs = await SharedPreferences.getInstance();
    final owned = access.prefix + slotSeparator;
    return prefs
        .getKeys()
        .where((k) => k.startsWith(owned))
        .map((k) => k.substring(owned.length))
        .toList(growable: false);
  }

  /// Runs [body] after any in-flight operation for [key] completes, so same-key
  /// writes are serialized. Different keys run concurrently. The lock entry is
  /// removed once this call is the tail of the chain, bounding map growth.
  Future<T> _withKeyLock<T>(String key, Future<T> Function() body) async {
    // Wait out any in-flight purge of this profile before acquiring a slot
    // lock, so a write cannot race past a concurrent purge's enumeration.
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

  /// Runs a profile-destroying [body] under the profile-wide purge gate: it
  /// serializes against other purges of this profile and drains any in-flight
  /// per-slot writes first, so no write is still mid-flight when the profile is
  /// destroyed. New writes started after this acquires the gate wait for it
  /// (see [_withKeyLock]).
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
      // Drain in-flight per-slot writes for this profile before destroying it.
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
