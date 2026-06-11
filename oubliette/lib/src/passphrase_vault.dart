import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter/services.dart';
import 'package:pointycastle/export.dart';

import '../oubliette.dart';
import 'slot.dart' show isWellFormedUtf16;

/// Argon2id cost parameters. Stored inside each passphrase-mode envelope so a
/// future parameter change never strands old data (the on-disk blob always
/// records the params it was written with — upgrade-safe).
class Argon2idParams {
  /// Memory cost in KiB.
  final int memoryKiB;

  /// Time cost (iterations / passes).
  final int iterations;

  /// Degree of parallelism (lanes).
  final int parallelism;

  const Argon2idParams({
    required this.memoryKiB,
    required this.iterations,
    required this.parallelism,
  });

  /// OWASP-minimum Argon2id (19 MiB, t=2, p=1). Mobile-friendly baseline; the
  /// same parameters used by the `recoverbull` seed-backup library.
  static const owasp = Argon2idParams(
    memoryKiB: 19 * 1024,
    iterations: 2,
    parallelism: 1,
  );

  /// Stronger desktop / wallet-seed preset (256 MiB, t=10, p=4) — matches
  /// Sparrow Wallet. Prefer this for a mnemonic on a desktop.
  static const sensitive = Argon2idParams(
    memoryKiB: 256 * 1024,
    iterations: 10,
    parallelism: 4,
  );
}

/// An application-level encryption layer that wraps any [Oubliette] backend and
/// protects each value with **AES-256-GCM** under a key from one of two
/// explicitly chosen sources:
///
/// - [PassphraseVault.passphrase] — the key is derived from a user passphrase
///   via **Argon2id** (per-secret random salt). Strong: a leaked/backed-up blob
///   is useless without the passphrase, and it is portable across devices. This
///   is the recommended mode for wallet mnemonics.
/// - [PassphraseVault.keyring] — the key is a random 32-byte secret kept in the
///   platform backend (Keystore/Keychain/Secret Service) and mixed per-slot via
///   HKDF. Convenience tier: no passphrase to type, but its confidentiality is
///   exactly the platform backend's (readable by a same-user process once the
///   session/keyring is unlocked) and it is device-bound (lost on a keyring
///   reset → restore from your offline backup).
///
/// The two modes are mutually exclusive and never silently fall back to one
/// another, and a passphrase vault **never** stores plaintext (an empty
/// passphrase is rejected at construction). The vault adds no UI: the
/// passphrase is passed in as bytes; reads go through [useAndForget].
///
/// The encrypted blob is stored via the wrapped backend, so it also inherits
/// that backend's protections (e.g. hardware-key wrapping on Android, the
/// Keychain on Darwin) — this layer composes on top, it does not replace them.
final class PassphraseVault {
  final Oubliette _inner;
  final int _mode;
  final Uint8List?
  _passphrase; // owned copy (passphrase mode); zeroed by dispose
  final Argon2idParams _params; // passphrase mode
  Uint8List? _keyringKek; // cached random KEK (keyring mode)
  bool _disposed = false;

  /// Bumped by [purge] and [dispose]. The KEK lifecycle ([_ensureKeyringKek])
  /// re-reads this after every `await`: an epoch change means the state it
  /// observed before the gap (a KEK it fetched or minted) predates a purge and
  /// must be discarded — caching it would resurrect key material the purge
  /// just destroyed, silently binding new data to a key that exists nowhere on
  /// disk.
  int _kekEpoch = 0;

  PassphraseVault._(this._inner, this._mode, this._passphrase, this._params);

  /// Passphrase-derived key (Argon2id). [passphrase] must be non-empty — there
  /// is no silent no-protection path. Pass bytes you can zero (a Dart `String`
  /// cannot be wiped). Tune [params] up to [Argon2idParams.sensitive] for a
  /// desktop wallet seed.
  ///
  /// **Scope of the tamper binding:** the GCM AAD binds the envelope header
  /// and the *logical key*, not the wrapped profile's storage prefix (which
  /// the vault never sees). If you open **two different backend profiles with
  /// the same passphrase**, an attacker who can rewrite the backend could swap
  /// the blob for key `k` between those profiles undetected — same key, same
  /// passphrase, same AAD. Use distinct passphrases (or distinct logical keys)
  /// per profile if that matters to your threat model. Keyring mode is immune:
  /// its KEK is random per profile.
  factory PassphraseVault.passphrase({
    required Oubliette inner,
    required Uint8List passphrase,
    Argon2idParams params = Argon2idParams.owasp,
  }) {
    if (passphrase.isEmpty) {
      throw ArgumentError.value(
        passphrase,
        'passphrase',
        'must not be empty — a passphrase vault never stores unprotected data',
      );
    }
    // Reject bad caller params up front (developer misconfiguration), so the
    // first store() can't surface a raw ArgumentError from the KDF that bypasses
    // the sealed OublietteException taxonomy.
    _checkArgon2idParams(params);
    return PassphraseVault._(
      inner,
      _modePassphrase,
      Uint8List.fromList(passphrase),
      params,
    );
  }

  /// Random key kept in the platform keyring/keystore (convenience tier — no
  /// passphrase). Confidentiality equals the wrapped backend's.
  factory PassphraseVault.keyring({required Oubliette inner}) {
    return PassphraseVault._(inner, _modeKeyring, null, Argon2idParams.owasp);
  }

  // --- Frozen on-disk envelope constants (append-only) ---
  static const int _formatV1 = 1;
  static const int _modeKeyring = 0;
  static const int _modePassphrase = 1;
  static const int _saltLen = 16;
  static const int _nonceLen = 12; // 96-bit GCM nonce (NIST SP 800-38D)
  static const int _keyLen = 32; // AES-256
  static const int _tagBits = 128;

  // Sane bounds for Argon2id params read back from the (attacker-writable)
  // envelope. A legitimately-written envelope always falls inside these; an
  // out-of-range value is treated as corruption and rejected BEFORE the KDF
  // runs, so a crafted blob cannot force a multi-GB allocation (decrypt-time
  // OOM/DoS). RFC 9106 / OWASP give defensible ceilings.
  static const int _minMemoryKiB = 8;
  static const int _maxMemoryKiB = 1024 * 1024; // 1 GiB
  static const int _minIterations = 1;
  static const int _maxIterations = 64;
  static const int _minParallelism = 1;
  static const int _maxParallelism = 16;

  /// Reserved key under which the keyring-mode random KEK is stored in the
  /// wrapped backend. Do not use this as a logical key.
  static const String reservedKekKey = '__oubliette_vault_kek__';

  static final Random _rng = Random.secure();

  Uint8List _randomBytes(int n) {
    final b = Uint8List(n);
    for (var i = 0; i < n; i++) {
      b[i] = _rng.nextInt(256);
    }
    return b;
  }

  void _zero(Uint8List b) => b.fillRange(0, b.length, 0);

  /// Provisions the backend and, in keyring mode, mints the random KEK if it
  /// does not yet exist. Idempotent.
  Future<void> init() async {
    _checkDisposed();
    await _inner.init();
    if (_mode == _modeKeyring) {
      await _ensureKeyringKek();
    }
  }

  /// A disposed vault must never be used again: in passphrase mode the
  /// passphrase bytes were zeroed *in place* (the field is final), so a
  /// post-dispose `store()` would otherwise derive its key from an all-zero
  /// passphrase — data that is both trivially decryptable offline and
  /// unreadable by the real passphrase. Fail loudly instead.
  void _checkDisposed() {
    if (_disposed) {
      throw StateError(
        'PassphraseVault was used after dispose(); create a new vault',
      );
    }
  }

  /// Guards the public API against the reserved KEK key. In keyring mode the
  /// random KEK lives in the wrapped backend under [reservedKekKey]; letting a
  /// caller `store`/`trash`/`useAndForget`/`exists` it would silently corrupt or
  /// delete the master key, making every keyring-mode secret permanently
  /// undecryptable — exactly the silent data loss this library exists to
  /// prevent. The internal KEK management talks to `_inner` directly, so this
  /// guard never blocks legitimate KEK access. Rejected in both modes (the key
  /// is reserved regardless of mode), as a developer error.
  void _rejectReservedKey(String key) {
    if (key == reservedKekKey) {
      throw ArgumentError.value(
        key,
        'key',
        'is reserved for the vault\'s internal key material and must not be '
            'used as a logical key',
      );
    }
  }

  /// Validates a caller-supplied logical key: rejects the reserved KEK key and
  /// malformed UTF-16. The latter is a *vault-level* injectivity requirement,
  /// not just slot hygiene: the key is bound into the GCM AAD via
  /// `utf8.encode`, where every unpaired surrogate encodes to the same U+FFFD
  /// replacement bytes — two distinct malformed keys would share one AAD, so a
  /// blob relocated between them would still authenticate. The real backends
  /// reject such keys in `buildSlot`, but the vault accepts any [Oubliette]
  /// implementation and must enforce this itself.
  void _checkKey(String key) {
    _rejectReservedKey(key);
    if (!isWellFormedUtf16(key)) {
      throw ArgumentError.value(
        key,
        'key',
        'contains an unpaired surrogate (malformed UTF-16)',
      );
    }
  }

  Future<void> store(String key, Uint8List value) async {
    _checkDisposed();
    _checkKey(key);
    final envelope = await _encrypt(key, value);
    await _inner.store(key, envelope);
  }

  /// Fetches and decrypts the secret for [key], passes the plaintext to
  /// [action], then zeroes it — mirroring [Oubliette.useAndForget]. Returns
  /// `null` if absent. A wrong passphrase or tampered blob throws
  /// [DecryptionFailedException].
  Future<T?> useAndForget<T>(
    String key,
    Future<T> Function(Uint8List bytes) action,
  ) {
    _checkDisposed();
    _checkKey(key);
    return _inner.useAndForget(key, (envelope) async {
      final plaintext = await _decrypt(key, envelope);
      try {
        return await action(plaintext);
      } finally {
        _zero(plaintext);
      }
    });
  }

  Future<void> trash(String key) {
    _checkDisposed();
    _checkKey(key);
    return _inner.trash(key);
  }

  Future<bool> exists(String key) {
    _checkDisposed();
    _checkKey(key);
    return _inner.exists(key);
  }

  /// Destroys the wrapped profile — including the keyring-mode KEK, so the
  /// profile is fully forgotten. The in-memory KEK cache is dropped too:
  /// keeping it would let a post-purge `store()` encrypt under a key that no
  /// longer exists anywhere on disk, making that data permanently
  /// undecryptable after the next restart.
  ///
  /// Do **not** run [purge] concurrently with an in-flight [store] /
  /// [useAndForget] on the same vault (the same contract as
  /// [Oubliette.purge]). The vault fails closed if the race is detected: an
  /// operation that crossed the purge throws [StateError] rather than encrypt
  /// under key material the purge destroyed.
  Future<void> purge() async {
    _checkDisposed();
    await _inner.purge();
    final k = _keyringKek;
    if (k != null) {
      _zero(k);
      _keyringKek = null;
    }
    _kekEpoch++;
  }

  /// Zeroes the in-memory passphrase / cached KEK and permanently retires this
  /// vault — every later call throws [StateError]. Best-effort zeroing (the
  /// Dart VM may have copied bytes).
  void dispose() {
    _disposed = true;
    final p = _passphrase;
    if (p != null) _zero(p);
    final k = _keyringKek;
    if (k != null) {
      _zero(k);
      _keyringKek = null;
    }
    _kekEpoch++;
  }

  // --- crypto ---

  Future<Uint8List> _encrypt(String key, Uint8List value) async {
    final keyBytes = Uint8List.fromList(utf8.encode(key));
    final salt = _randomBytes(_saltLen);
    final nonce = _randomBytes(_nonceLen);
    final header = _header(salt, nonce);
    // AAD binds the FULL header (version, mode, params, salt, nonce) plus the
    // logical key, so any header tamper fails the GCM tag rather than being
    // silently honored.
    final aad = _concat(header, keyBytes);
    final kek = await _deriveKey(salt, keyBytes);
    try {
      final ct = _gcm(true, kek, nonce, aad, value);
      return _concat(header, ct);
    } finally {
      _zero(kek);
    }
  }

  Future<Uint8List> _decrypt(String key, Uint8List env) async {
    // Re-checked here (not only at the public entry): the envelope fetch in
    // `_inner.useAndForget` is a suspension point, and `dispose()` zeroes the
    // passphrase *in place* during it. Without this check a dispose that lands
    // in that gap would derive a key from the all-zero passphrase and surface
    // as a misleading DecryptionFailedException ("wrong passphrase") instead
    // of the truthful StateError. From here to the KDF there is no further
    // suspension, so the check cannot be raced.
    _checkDisposed();
    final keyBytes = Uint8List.fromList(utf8.encode(key));
    final r = _Reader(key, env);
    if (r.byte() != _formatV1) {
      throw PayloadCorruptException(
        'vault envelope for "$key" has an unknown format version',
      );
    }
    final mode = r.byte();
    if (mode != _mode) {
      throw PayloadCorruptException(
        'vault envelope for "$key" was written with a different key source; '
        'open it with the matching PassphraseVault mode',
      );
    }
    Argon2idParams? storedParams;
    if (mode == _modePassphrase) {
      storedParams = Argon2idParams(
        memoryKiB: r.uint32(),
        iterations: r.uint32(),
        parallelism: r.uint32(),
      );
      // VAULT-1: reject out-of-range cost params from the (untrusted) blob
      // BEFORE running the KDF, so a crafted envelope cannot trigger an
      // unbounded allocation.
      _validateParams(key, storedParams);
    }
    // VAULT-2: the writer only ever emits salt==16 / nonce==12; any other
    // length is corruption, surfaced as the typed PayloadCorruptException
    // (never a raw ArgumentError from the crypto layer).
    final saltLen = r.byte();
    if (saltLen != _saltLen) {
      throw PayloadCorruptException(
        'vault envelope for "$key" has an invalid salt length ($saltLen)',
      );
    }
    final salt = r.bytes(saltLen);
    final nonceLen = r.byte();
    if (nonceLen != _nonceLen) {
      throw PayloadCorruptException(
        'vault envelope for "$key" has an invalid nonce length ($nonceLen)',
      );
    }
    final nonce = r.bytes(nonceLen);
    final header = Uint8List.sublistView(env, 0, r.offset);
    final ct = r.rest();
    // A ciphertext shorter than the GCM tag cannot have been written by this
    // library (the tag is always appended) — classify it precisely as on-disk
    // corruption rather than letting the AEAD report a generic tag failure.
    if (ct.length < _tagBits ~/ 8) {
      throw PayloadCorruptException(
        'vault envelope for "$key" is truncated (ciphertext shorter than the '
        'GCM tag)',
      );
    }
    final aad = _concat(header, keyBytes);
    final Uint8List kek;
    try {
      kek = await _deriveKey(salt, keyBytes, paramsOverride: storedParams);
    } on ArgumentError catch (e) {
      // Defensive: a malformed (but in-range) value reaching the KDF is still
      // corruption, not a recoverable crypto failure.
      throw PayloadCorruptException(
        'vault envelope for "$key" is malformed: ${e.message}',
      );
    }
    try {
      return _gcm(false, kek, nonce, aad, ct);
    } on InvalidCipherTextException catch (e) {
      // Wrong passphrase, wrong key, or a tampered blob — all fail the GCM tag.
      throw DecryptionFailedException(key: key, cause: e);
    } finally {
      _zero(kek);
    }
  }

  /// Validates caller-supplied Argon2id params at construction. Throws a
  /// developer-facing [ArgumentError] (not the on-disk [PayloadCorruptException])
  /// for an out-of-range preset, including pointycastle's `memory >= 2*lanes`
  /// invariant (memoryKiB >= 2*parallelism).
  static void _checkArgon2idParams(Argon2idParams p) {
    final ok =
        p.memoryKiB >= _minMemoryKiB &&
        p.memoryKiB <= _maxMemoryKiB &&
        p.iterations >= _minIterations &&
        p.iterations <= _maxIterations &&
        p.parallelism >= _minParallelism &&
        p.parallelism <= _maxParallelism &&
        p.memoryKiB >= 2 * p.parallelism;
    if (!ok) {
      throw ArgumentError.value(
        p,
        'params',
        'invalid Argon2id parameters: memoryKiB in [$_minMemoryKiB, '
            '$_maxMemoryKiB] and >= 2*parallelism, iterations in '
            '[$_minIterations, $_maxIterations], parallelism in '
            '[$_minParallelism, $_maxParallelism]',
      );
    }
  }

  void _validateParams(String key, Argon2idParams p) {
    final ok =
        p.memoryKiB >= _minMemoryKiB &&
        p.memoryKiB <= _maxMemoryKiB &&
        p.iterations >= _minIterations &&
        p.iterations <= _maxIterations &&
        p.parallelism >= _minParallelism &&
        p.parallelism <= _maxParallelism;
    if (!ok) {
      throw PayloadCorruptException(
        'vault envelope for "$key" has out-of-range Argon2id parameters '
        '(memoryKiB=${p.memoryKiB}, iterations=${p.iterations}, '
        'parallelism=${p.parallelism})',
      );
    }
  }

  Future<Uint8List> _deriveKey(
    Uint8List salt,
    Uint8List keyBytes, {
    Argon2idParams? paramsOverride,
  }) async {
    if (_mode == _modePassphrase) {
      return _argon2(_passphrase!, salt, paramsOverride ?? _params);
    }
    final vaultKek = await _ensureKeyringKek();
    // The await above is a suspension point: a concurrent purge()/dispose()
    // may have zeroed the cached KEK buffer *in place* during the gap (and
    // dropped it from the cache). Deriving from that zeroed buffer would be
    // catastrophic on the encrypt path — the subkey becomes HKDF(all-zeros,
    // public salt, public key), so the stored blob is decryptable offline by
    // anyone AND unreadable by every future vault. Re-check synchronously
    // (there is no further suspension before the KDF runs, so this cannot be
    // raced within the isolate) and fail closed.
    if (_disposed || !identical(_keyringKek, vaultKek)) {
      throw StateError(
        'PassphraseVault was disposed or purged during an in-flight '
        'operation; the operation was aborted to avoid using destroyed key '
        'material',
      );
    }
    // Per-slot subkey: HKDF(vaultKek, salt, info = the logical key).
    return _hkdf(vaultKek, salt, keyBytes);
  }

  /// Serializes the envelope header (everything before the ciphertext). Used
  /// both as the stored prefix and as the GCM AAD prefix.
  Uint8List _header(Uint8List salt, Uint8List nonce) {
    final out = BytesBuilder();
    out.addByte(_formatV1);
    out.addByte(_mode);
    if (_mode == _modePassphrase) {
      final pd = ByteData(12)
        ..setUint32(0, _params.memoryKiB)
        ..setUint32(4, _params.iterations)
        ..setUint32(8, _params.parallelism);
      out.add(pd.buffer.asUint8List());
    }
    out.addByte(salt.length);
    out.add(salt);
    out.addByte(nonce.length);
    out.add(nonce);
    return out.toBytes();
  }

  Uint8List _concat(Uint8List a, Uint8List b) {
    final out = Uint8List(a.length + b.length);
    out.setRange(0, a.length, a);
    out.setRange(a.length, out.length, b);
    return out;
  }

  /// The KEK is always written as [_keyLen] bytes; any other length read back
  /// is on-disk corruption. Catching it here prevents a *new* store from
  /// silently binding data to truncated/corrupt key material.
  Uint8List _checkKekLength(Uint8List kek) {
    if (kek.length != _keyLen) {
      _zero(kek);
      throw const PayloadCorruptException(
        'the stored vault KEK has an invalid length',
      );
    }
    return kek;
  }

  /// Validates the vault is still live after an `await` inside the KEK
  /// lifecycle, zeroing [scratch] (fetched/minted key material that must not
  /// outlive the check) first when the vault moved on. Returns `true` when a
  /// concurrent [purge] bumped the epoch — the caller's observations predate
  /// the purge and it must retry from scratch. Throws after [dispose]: caching
  /// key material into a disposed vault would resurrect bytes `dispose()`
  /// promised to drop.
  bool _kekStateMoved(int epoch, Uint8List? scratch) {
    if (_disposed) {
      if (scratch != null) _zero(scratch);
      throw StateError(
        'PassphraseVault was disposed during an in-flight operation; create '
        'a new vault',
      );
    }
    if (epoch != _kekEpoch) {
      if (scratch != null) _zero(scratch);
      return true;
    }
    return false;
  }

  Future<Uint8List> _ensureKeyringKek() async {
    // Retried whenever a concurrent purge() invalidates what an await observed
    // (epoch bump). Each pass either returns a KEK that is canonical *for the
    // current epoch* or starts over against post-purge state — so a purge can
    // never be straddled into caching a KEK that no longer exists on disk.
    while (true) {
      final cached = _keyringKek;
      if (cached != null) return cached;
      final epoch = _kekEpoch;
      final existing = await _inner.useAndForget(
        reservedKekKey,
        (b) async => Uint8List.fromList(b),
      );
      if (_kekStateMoved(epoch, existing)) continue;
      final cachedNow = _keyringKek;
      if (cachedNow != null) {
        // A concurrent caller cached first. Keep ONE canonical buffer: callers
        // verify `identical(_keyringKek, …)` after their awaits, so caching a
        // second (equal-bytes) copy here would spuriously fail them.
        if (existing != null) _zero(existing);
        return cachedNow;
      }
      if (existing != null) {
        _keyringKek = _checkKekLength(existing);
        return existing;
      }
      final fresh = _randomBytes(_keyLen);
      try {
        await _inner.store(reservedKekKey, fresh);
      } on Object catch (e) {
        // Lost a concurrent mint — re-read the winner. In-isolate races
        // surface as StateError (the backend's duplicate-store guard);
        // cross-process races on Darwin/Linux surface as the raw native
        // `already_exists`.
        final lostRace =
            e is StateError ||
            (e is PlatformException && e.code == 'already_exists');
        if (!lostRace) {
          _zero(fresh); // never used to encrypt anything — just hygiene
          rethrow;
        }
        final raced = await _inner.useAndForget(
          reservedKekKey,
          (b) async => Uint8List.fromList(b),
        );
        _zero(fresh);
        if (_kekStateMoved(epoch, raced)) continue;
        if (raced != null) {
          final cachedAfterRace = _keyringKek;
          if (cachedAfterRace != null) {
            _zero(raced);
            return cachedAfterRace;
          }
          _keyringKek = _checkKekLength(raced);
          return raced;
        }
        rethrow;
      }
      // The mint landed in the backend. If a purge crossed it, the stored KEK
      // may already have been deleted (or may have landed just after the
      // purge's enumeration) — discard our buffer and retry: the next pass
      // re-reads the backend's post-purge truth instead of trusting ours.
      if (_kekStateMoved(epoch, fresh)) continue;
      final cachedAfterMint = _keyringKek;
      if (cachedAfterMint != null) {
        _zero(fresh);
        return cachedAfterMint;
      }
      _keyringKek = fresh;
      return fresh;
    }
  }

  Uint8List _argon2(Uint8List passphrase, Uint8List salt, Argon2idParams p) {
    final params = Argon2Parameters(
      Argon2Parameters.ARGON2_id,
      salt,
      version: Argon2Parameters.ARGON2_VERSION_13,
      iterations: p.iterations,
      memory: p.memoryKiB,
      lanes: p.parallelism,
      desiredKeyLength: _keyLen,
    );
    final d = KeyDerivator('argon2')..init(params);
    return d.process(passphrase);
  }

  Uint8List _hkdf(Uint8List ikm, Uint8List salt, Uint8List info) {
    final d = HKDFKeyDerivator(SHA256Digest())
      ..init(HkdfParameters(ikm, _keyLen, salt, info));
    return d.process(Uint8List(0));
  }

  Uint8List _gcm(
    bool encrypt,
    Uint8List key,
    Uint8List nonce,
    Uint8List aad,
    Uint8List input,
  ) {
    final c = GCMBlockCipher(AESEngine())
      ..init(encrypt, AEADParameters(KeyParameter(key), _tagBits, nonce, aad));
    return c.process(input);
  }
}

/// Bounds-checked cursor over an envelope; any overrun is on-disk corruption.
class _Reader {
  final String _key;
  final Uint8List _b;
  int _off = 0;

  _Reader(this._key, this._b);

  /// Bytes consumed so far (start offset of the ciphertext after the header).
  int get offset => _off;

  void _need(int n) {
    if (_off + n > _b.length) {
      throw PayloadCorruptException(
        'vault envelope for "$_key" is truncated or malformed',
      );
    }
  }

  int byte() {
    _need(1);
    return _b[_off++];
  }

  int uint32() {
    _need(4);
    final v = ByteData.sublistView(_b, _off, _off + 4).getUint32(0);
    _off += 4;
    return v;
  }

  Uint8List bytes(int n) {
    _need(n);
    final out = Uint8List.fromList(_b.sublist(_off, _off + n));
    _off += n;
    return out;
  }

  Uint8List rest() {
    final out = Uint8List.fromList(_b.sublist(_off));
    _off = _b.length;
    return out;
  }
}
