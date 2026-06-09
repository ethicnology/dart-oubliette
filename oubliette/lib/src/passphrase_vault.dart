import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import '../oubliette.dart';

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

  PassphraseVault._(this._inner, this._mode, this._passphrase, this._params);

  /// Passphrase-derived key (Argon2id). [passphrase] must be non-empty — there
  /// is no silent no-protection path. Pass bytes you can zero (a Dart `String`
  /// cannot be wiped). Tune [params] up to [Argon2idParams.sensitive] for a
  /// desktop wallet seed.
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
    await _inner.init();
    if (_mode == _modeKeyring) {
      await _ensureKeyringKek();
    }
  }

  Future<void> store(String key, Uint8List value) async {
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
    return _inner.useAndForget(key, (envelope) async {
      final plaintext = await _decrypt(key, envelope);
      try {
        return await action(plaintext);
      } finally {
        _zero(plaintext);
      }
    });
  }

  Future<void> trash(String key) => _inner.trash(key);

  Future<bool> exists(String key) => _inner.exists(key);

  /// Destroys the wrapped profile — including the keyring-mode KEK, so the
  /// profile is fully forgotten.
  Future<void> purge() => _inner.purge();

  /// Zeroes the in-memory passphrase / cached KEK. Call when the vault is no
  /// longer needed. Best-effort (the Dart VM may have copied bytes).
  void dispose() {
    final p = _passphrase;
    if (p != null) _zero(p);
    final k = _keyringKek;
    if (k != null) {
      _zero(k);
      _keyringKek = null;
    }
  }

  // --- crypto ---

  Future<Uint8List> _encrypt(String key, Uint8List value) async {
    final aad = Uint8List.fromList(utf8.encode(key));
    final salt = _randomBytes(_saltLen);
    final nonce = _randomBytes(_nonceLen);
    final kek = await _deriveKey(salt, aad);
    try {
      final ct = _gcm(true, kek, nonce, aad, value);
      return _encode(salt, nonce, ct);
    } finally {
      _zero(kek);
    }
  }

  Future<Uint8List> _decrypt(String key, Uint8List env) async {
    final aad = Uint8List.fromList(utf8.encode(key));
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
    }
    final salt = r.bytes(r.byte());
    final nonce = r.bytes(r.byte());
    final ct = r.rest();
    final kek = await _deriveKey(salt, aad, paramsOverride: storedParams);
    try {
      return _gcm(false, kek, nonce, aad, ct);
    } on InvalidCipherTextException catch (e) {
      // Wrong passphrase, wrong key, or a tampered blob — all fail the GCM tag.
      throw DecryptionFailedException(key: key, cause: e);
    } finally {
      _zero(kek);
    }
  }

  Future<Uint8List> _deriveKey(
    Uint8List salt,
    Uint8List aad, {
    Argon2idParams? paramsOverride,
  }) async {
    if (_mode == _modePassphrase) {
      return _argon2(_passphrase!, salt, paramsOverride ?? _params);
    }
    final vaultKek = await _ensureKeyringKek();
    // Per-slot subkey: HKDF(vaultKek, salt, info = the logical key).
    return _hkdf(vaultKek, salt, aad);
  }

  Uint8List _encode(Uint8List salt, Uint8List nonce, Uint8List ct) {
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
    out.add(ct);
    return out.toBytes();
  }

  Future<Uint8List> _ensureKeyringKek() async {
    final cached = _keyringKek;
    if (cached != null) return cached;
    final existing = await _inner.useAndForget(
      reservedKekKey,
      (b) async => Uint8List.fromList(b),
    );
    if (existing != null) {
      _keyringKek = existing;
      return existing;
    }
    final fresh = _randomBytes(_keyLen);
    try {
      await _inner.store(reservedKekKey, fresh);
    } on StateError {
      // Lost a concurrent mint — re-read the winner.
      final raced = await _inner.useAndForget(
        reservedKekKey,
        (b) async => Uint8List.fromList(b),
      );
      if (raced != null) {
        _zero(fresh);
        _keyringKek = raced;
        return raced;
      }
      rethrow;
    }
    _keyringKek = fresh;
    return fresh;
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
