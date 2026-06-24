import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:keychain/keychain.dart';
import 'package:oubliette/oubliette.dart';

import 'src/slot.dart';

class DarwinOubliette extends Oubliette {
  DarwinOubliette({required this.access})
    : _keychain = Keychain(config: access.toConfig()),
      super.internal();

  final DarwinSecretAccess access;
  final Keychain _keychain;

  /// Per-slot serialization, mirroring the Android side. On Darwin `secItemAdd`
  /// already fails closed (`errSecDuplicateItem` → `already_exists`), so this
  /// is defense-in-depth / symmetry rather than the primary guard. Static and
  /// keyed by the full slot so it spans separate instances like Android's.
  static final Map<String, Future<void>> _locks = {};

  /// Profile-wide purge gate, keyed by `access.prefix`. `purge()` holds it while
  /// it drains in-flight per-slot writes and deletes the profile's items;
  /// `store()` waits on it first so a write cannot land an item a concurrent
  /// purge already enumerated past. Store-vs-store concurrency is preserved
  /// (stores only wait on the gate). Best-effort within an isolate; the
  /// documented "must not run purge concurrently" contract (see
  /// [Oubliette.purge]) still stands.
  static final Map<String, Future<void>> _purges = {};

  String _storedKey(String key) => buildSlot(access.prefix, key);

  /// FROZEN: the current Darwin blob format version. Every value written to the
  /// Keychain is prefixed with this 1-byte header. It mirrors the Android
  /// [EncryptedPayload] `version`: native Keychain items carry no format of
  /// their own, so without this header a future change to how Darwin lays out
  /// its bytes could not be told apart from old data — exactly the upgrade
  /// data-loss this library exists to prevent. Bump only by *adding* a reader
  /// for the new value; never reinterpret an existing one (append-only).
  static const int _darwinFormatV1 = 1;

  /// Prepends the [_darwinFormatV1] header to [value].
  Uint8List _wrap(Uint8List value) {
    final out = Uint8List(value.length + 1);
    out[0] = _darwinFormatV1;
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
    if (version != _darwinFormatV1) {
      throw PayloadCorruptException(
        'stored blob for key "$key" has unknown Darwin format version '
        '$version (this build reads v$_darwinFormatV1)',
      );
    }
    return Uint8List.sublistView(stored, 1);
  }

  /// Ensures the Secure Enclave key pair exists when this profile uses it.
  /// No-op when [DarwinSecretAccess.secureEnclave] is false. Idempotent.
  Future<void> _ensureKey() async {
    if (!access.secureEnclave) return;
    // _mapError like every other native call: ensure can now fail with
    // se_key_fetch_failed / se_ensure_key_failed (environmental — locked
    // keychain, entitlement), which must surface as a recoverable typed
    // error, never a raw PlatformException.
    await _mapError('<ensure-key>', () => _keychain.ensureEnclaveKeyPair());
  }

  @override
  Future<void> init() async {
    if (!access.secureEnclave) return;
    final existed = await _mapError(
      '<init>',
      () => _keychain.ensureEnclaveKeyPair(),
    );
    debugPrint(
      existed
          ? '[Oubliette] Darwin SE key already exists (service: ${access.service})'
          : '[Oubliette] Darwin SE key generated (service: ${access.service})',
    );
  }

  @override
  Future<void> store(String key, Uint8List value) {
    return _withKeyLock(key, () async {
      bool present;
      try {
        present = await exists(key);
      } on AuthenticationFailedException {
        // On an authenticated profile contains() cannot return a definite
        // answer: the UI-suppressed probe (kSecUseAuthenticationUIFail) makes
        // the OS report a presence-gated item with errSecInteractionNotAllowed
        // even when it plainly exists (see KeychainQueries.contains doc). Don't
        // let that surface as a misleading "authenticate & retry"; fall through
        // to secItemAdd, whose errSecDuplicateItem → `already_exists` →
        // StateError is the authoritative put-if-absent for these profiles
        // (parity with Android, which reads SharedPreferences and yields the
        // same StateError). A genuinely-absent key still returns false here.
        present = false;
      }
      if (present) {
        throw StateError(
          'A value already exists for key "$key". Call trash() first.',
        );
      }
      await _ensureKey();
      // SecItemAdd is the authoritative put-if-absent (errSecDuplicateItem →
      // native `already_exists`). If a concurrent writer won the race the
      // best-effort precheck above cannot close, unify it with the precheck so
      // store() throws ONE error type for "already present", never a raw
      // PlatformException. Nothing is overwritten either way.
      try {
        await _mapError(
          key,
          () => _keychain.secItemAdd(_storedKey(key), _wrap(value)),
        );
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
    final stored = await _mapError(
      key,
      () => _keychain.secItemCopyMatching(_storedKey(key)),
    );
    if (stored == null) return null;
    return _unwrap(key, stored);
  }

  /// Translates known native keychain error codes into typed
  /// [OublietteException]s so callers can branch on `recoverable`.
  ///
  /// For OS invalidation of a plain keychain item (passcode/biometry change),
  /// the item is deleted, surfacing as a `null` fetch. For Secure-Enclave
  /// profiles the native **read** path no longer regenerates a missing SE key
  /// (that would mint a key unable to decrypt existing data) — it returns
  /// `se_key_missing`, mapped here to [KeyNotFoundException] (`recoverable:
  /// false`): the SE key is gone (non-exportable, not migrated across
  /// devices/restores), so the ciphertext under it is unreadable and the only
  /// way forward is an explicit `purge()` + `init()` + re-entry. A genuine
  /// cryptographic failure (key present, ciphertext bad) stays
  /// `se_decrypt_failed` → [DecryptionFailedException].
  ///
  /// Deliberately-unmapped codes pass through as the raw [PlatformException] by
  /// design (never a data-recovery outcome): `se_requires_device_only_accessibility`
  /// (a fail-closed config rejection — the caller asked for a non-ThisDeviceOnly
  /// SE item), `macos_auth_requires_data_protection` (a fail-closed macOS config
  /// rejection — an authentication-required item needs the data-protection
  /// keychain) and `bad_args` (a contract/programming error). The write path's
  /// `already_exists` (from `SecItemAdd`'s `errSecDuplicateItem`) is translated
  /// by [store] itself into the same `StateError` the precheck throws, so it does
  /// not escape `store()` as a PlatformException. Any genuinely-unknown code
  /// likewise rethrows untouched — never guess a typed meaning that could steer a
  /// caller toward purge().
  Future<T> _mapError<T>(String key, Future<T> Function() op) async {
    try {
      return await op();
    } on PlatformException catch (e) {
      switch (e.code) {
        case 'se_key_missing':
          throw KeyNotFoundException(
            keyAlias: access.service ?? 'secureEnclave',
            cause: e,
          );
        // The SE key *fetch* itself failed with an unexpected status (e.g. an
        // entitlement or keychain-domain hiccup) — distinct from "not found".
        // Mapped to a recoverable error: the key may well still exist, so the
        // data-destroying KeyNotFound remediation (purge + re-entry) must not
        // be suggested for a transient failure.
        case 'se_key_fetch_failed':
        // Write-path Secure-Enclave failures: key generation, ECIES
        // encryption, or access-control creation failed with an unexpected
        // status (entitlement, hardware, or keychain-domain misconfig). The
        // secret was never written, so nothing is lost; like a fetch failure
        // these are environmental and recoverable — fix the environment and
        // retry. They must NOT map to the data-destroying KeyNotFound path.
        case 'se_key_gen_failed':
        case 'se_encrypt_failed':
        case 'access_control_failed':
        // ensureEnclaveKeyPair returned a null/absent result over the wire —
        // the facade fails closed rather than report "key just created".
        case 'se_ensure_key_failed':
        // A code-signing / `keychain-access-groups` entitlement defect
        // (`errSecMissingEntitlement`). This is a build/signing fault, not a
        // data fault — the stored item is intact and the key (if any) still
        // exists, so it must NEVER steer a caller toward the data-destroying
        // purge() path. It is environmental in the same sense as the SE-fetch
        // failures above (fix the entitlement / re-sign, then the same op
        // succeeds), so it maps to the recoverable BackendUnavailableException
        // rather than rethrowing a raw PlatformException a caller might treat
        // as fatal.
        case 'missing_entitlement':
        // A plain-keychain *fetch* (SecItemCopyMatching) failed with an
        // unexpected OSStatus (not item-not-found, not auth) — a locked
        // Data-Protection keychain, an entitlement/domain misconfig, or a
        // transient Security-framework error. The blob is not known to be
        // damaged, so like the other environmental failures it is recoverable
        // and must not trigger purge().
        case 'sec_item_copy_failed':
        // The add (SecItemAdd) and delete (SecItemDelete / delete-by-prefix)
        // paths' generic OSStatus fallbacks — the symmetric counterparts of
        // `sec_item_copy_failed`. An add failure wrote nothing; a delete
        // failure left the existing blob intact. Neither is data loss, both
        // are environmental (locked keychain, entitlement/domain misconfig,
        // transient framework error), so they map to the recoverable
        // BackendUnavailableException rather than leaking a raw
        // PlatformException a caller might answer with purge().
        case 'sec_item_add_failed':
        case 'sec_item_delete_failed':
          throw BackendUnavailableException(cause: e);
        case 'se_decrypt_failed':
          throw DecryptionFailedException(key: key, cause: e);
        case 'auth_failed':
        case 'interaction_not_allowed': // device locked — retry when unlocked
          throw AuthenticationFailedException(key: key, cause: e);
        case 'biometry_lockout':
          // Recoverable like any unsatisfied auth gate, but the user must unlock
          // the device with the passcode to clear the lockout before biometry
          // works again — flag it so the caller can show the right hint.
          throw AuthenticationFailedException(
            key: key,
            lockout: true,
            cause: e,
          );
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
    // _mapError on every native call (like store/fetch and the Linux backend):
    // a delete on a locked Data Protection keychain can fail with
    // `interaction_not_allowed`, which callers must see as a typed,
    // recoverable error — not a raw PlatformException they may treat as fatal.
    await _mapError(key, () => _keychain.secItemDelete(_storedKey(key)));
  }

  @override
  Future<void> purge() => _withProfilePurge(() async {
    // Keychain has no "delete by account-prefix" query, so the native side
    // enumerates this profile's items (scoped by service/accessGroup) and
    // deletes those whose account begins with `prefix + slotSeparator`.
    // Ownership is exact: the separator's position encodes the prefix length,
    // so a sibling profile whose prefix nests under ours is never matched
    // (e.g. purging `authenticated` never wipes `authenticated_fatal`, nor a
    // custom `app_` ever wipe `app_admin_`). No exclude list is needed.
    await _mapError(
      '<purge>',
      () => _keychain.deleteByPrefix(access.prefix + slotSeparator),
    );
    // The Secure Enclave key is deliberately NOT deleted. Its identity is
    // (service, accessibility, accessGroup) — it does not include the prefix —
    // so two profiles that differ only by prefix share one key (e.g. the
    // default `onlyUnlocked` and `authenticated` both use
    // `whenUnlockedThisDeviceOnly`). Deleting it here could silently brick a
    // sibling profile. The key is also inert once its blobs are gone, and SE
    // keys are not subject to the `KeyInvalidatedException` wedge (they carry
    // only `.privateKeyUsage`), so there is no recovery reason to remove it.
  });

  @override
  Future<bool> exists(String key) {
    return _mapError(key, () => _keychain.contains(_storedKey(key)));
  }

  @override
  Future<List<String>> keys() async {
    // The non-destructive twin of purge(): purge() calls deleteByPrefix on the
    // same owned prefix; keys() lists the matching accounts instead. Routed
    // through _mapError so a locked keychain surfaces as a typed (recoverable)
    // exception, never a raw PlatformException. Strip the owned prefix so the
    // caller gets logical keys, not raw kSecAttrAccount slots.
    final owned = access.prefix + slotSeparator;
    final accounts = await _mapError(
      '<keys>',
      () => _keychain.listByPrefix(owned),
    );
    return accounts
        .map((a) => a.substring(owned.length))
        .toList(growable: false);
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
