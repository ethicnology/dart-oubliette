import 'dart:async';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:oubliette/oubliette.dart';

/// In-memory [Oubliette] backend, so the vault's crypto is exercised without a
/// platform channel. `store` rejects duplicates (like the real backends), so
/// the keyring-mode KEK get-or-create race path is covered.
class _FakeOubliette extends Oubliette {
  _FakeOubliette() : super.internal();
  final Map<String, Uint8List> store_ = {};

  @override
  Future<void> init() async {}

  @override
  Future<void> store(String key, Uint8List value) async {
    if (store_.containsKey(key)) {
      throw StateError('A value already exists for key "$key".');
    }
    store_[key] = Uint8List.fromList(value);
  }

  @override
  Future<Uint8List?> fetch(String key) async {
    final v = store_[key];
    return v == null ? null : Uint8List.fromList(v);
  }

  @override
  Future<void> trash(String key) async {
    store_.remove(key);
  }

  @override
  Future<bool> exists(String key) async => store_.containsKey(key);

  @override
  Future<void> purge() async => store_.clear();

  @override
  Future<List<String>> keys() async => store_.keys.toList(growable: false);
}

/// A [_FakeOubliette] whose `fetch`/`store` can be suspended per key on a
/// [Completer] gate, to deterministically interleave a `purge()`/`dispose()`
/// into the middle of an in-flight vault operation.
class _GatedOubliette extends _FakeOubliette {
  final Map<String, Completer<void>> fetchGates = {};
  final Map<String, Completer<void>> storeGates = {};

  @override
  Future<Uint8List?> fetch(String key) async {
    final gate = fetchGates[key];
    if (gate != null) await gate.future;
    return super.fetch(key);
  }

  @override
  Future<void> store(String key, Uint8List value) async {
    final gate = storeGates[key];
    if (gate != null) await gate.future;
    return super.store(key, value);
  }
}

/// A backend whose `init()` fails, to verify the vault surfaces backend errors
/// eagerly from `init()` rather than deferring them to the first store.
class _InitFailingOubliette extends _FakeOubliette {
  @override
  Future<void> init() async =>
      throw const BackendUnavailableException(cause: 'init probe failed');
}

Uint8List _bytes(List<int> b) => Uint8List.fromList(b);

Uint8List _hex(String s) => Uint8List.fromList([
  for (var i = 0; i < s.length; i += 2)
    int.parse(s.substring(i, i + 2), radix: 16),
]);

/// Whether [haystack] contains [needle] as a contiguous subsequence.
bool _containsSeq(Uint8List haystack, Uint8List needle) {
  for (var i = 0; i + needle.length <= haystack.length; i++) {
    var match = true;
    for (var j = 0; j < needle.length; j++) {
      if (haystack[i + j] != needle[j]) {
        match = false;
        break;
      }
    }
    if (match) return true;
  }
  return false;
}

// Tiny params so Argon2id is fast in tests (NOT for production use).
const _fastParams = Argon2idParams(
  memoryKiB: 256,
  iterations: 1,
  parallelism: 1,
);

void main() {
  group('PassphraseVault — passphrase mode', () {
    late _FakeOubliette backend;
    PassphraseVault vault([Uint8List? pass]) => PassphraseVault.passphrase(
      inner: backend,
      passphrase: pass ?? _bytes([1, 2, 3, 4]),
      params: _fastParams,
    );

    setUp(() => backend = _FakeOubliette());

    test('store then read round-trips the plaintext', () async {
      final v = vault();
      final secret = _bytes([9, 8, 7, 6, 5]);
      await v.store('seed', secret);
      final out = await v.useAndForget(
        'seed',
        (b) async => Uint8List.fromList(b),
      );
      expect(out, secret);
    });

    test('GOLDEN v1 passphrase envelope still decrypts (format lock)', () async {
      // A v1 envelope frozen from the current writer (params: _fastParams,
      // passphrase [7x8], plaintext below). This is the only test pinning the
      // on-disk v1 *read* path to a fixed byte sequence — round-trip tests can't
      // catch a format change that breaks OLD data because writer and reader
      // drift together. If this ever fails, v1 data written by a shipped build
      // is unreadable: never edit these bytes; add a v2 reader instead.
      final golden = _hex(
        '0101000001000000000100000001109a9bcc5222142e25bec986acc047b930'
        '0caf5ddc389d6c90bbc068ca9aeffccda30a6e8ef68a7802f91d17e940fa71'
        'd9798295abc7',
      );
      backend.store_['seed'] = golden;
      final v = PassphraseVault.passphrase(
        inner: backend,
        passphrase: _bytes([7, 7, 7, 7, 7, 7, 7, 7]),
        params: _fastParams,
      );
      final out = await v.useAndForget(
        'seed',
        (b) async => Uint8List.fromList(b),
      );
      expect(out, _bytes([0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
    });

    test('the stored blob is ciphertext, not the plaintext', () async {
      final v = vault();
      final secret = _bytes([0xDE, 0xAD, 0xBE, 0xEF]);
      await v.store('seed', secret);
      final raw = backend.store_['seed']!;
      expect(raw[0], 1, reason: 'frozen format version');
      expect(raw[1], 1, reason: 'mode = passphrase');
      expect(
        _containsSeq(raw, secret),
        isFalse,
        reason: 'the plaintext run must not appear anywhere in the envelope',
      );
      expect(
        await v.useAndForget('seed', (b) async => Uint8List.fromList(b)),
        secret,
        reason: 'but it still round-trips',
      );
    });

    test('invalid Argon2id params are rejected at construction (VAULT2-ENC)', () {
      // memoryKiB < 2*parallelism violates pointycastle's invariant — must fail
      // fast as a developer-facing ArgumentError, not a raw error from store().
      expect(
        () => PassphraseVault.passphrase(
          inner: backend,
          passphrase: _bytes([1, 2, 3]),
          params: const Argon2idParams(
            memoryKiB: 8,
            iterations: 2,
            parallelism: 16,
          ),
        ),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('empty passphrase is rejected (no silent plaintext)', () {
      expect(
        () => PassphraseVault.passphrase(
          inner: backend,
          passphrase: Uint8List(0),
        ),
        throwsA(isA<ArgumentError>()),
      );
    });

    test(
      'wrong passphrase fails closed with DecryptionFailedException',
      () async {
        await vault(_bytes([1, 1, 1, 1])).store('k', _bytes([5, 5, 5]));
        final wrong = vault(_bytes([2, 2, 2, 2]));
        await expectLater(
          wrong.useAndForget('k', (b) async => b),
          throwsA(
            isA<DecryptionFailedException>().having(
              (e) => e.recoverable,
              'recoverable',
              false,
            ),
          ),
        );
      },
    );

    test('a tampered ciphertext byte fails the GCM tag', () async {
      final v = vault();
      await v.store('k', _bytes([7, 7, 7, 7]));
      final raw = backend.store_['k']!;
      raw[raw.length - 1] ^= 0xFF; // flip a tag byte
      await expectLater(
        v.useAndForget('k', (b) async => b),
        throwsA(isA<DecryptionFailedException>()),
      );
    });

    test('relocating a blob to another key fails (AAD = key)', () async {
      final v = vault();
      await v.store('a', _bytes([1, 2, 3]));
      // Move a's ciphertext under key b: AAD no longer matches → tag fails.
      backend.store_['b'] = backend.store_['a']!;
      await expectLater(
        v.useAndForget('b', (x) async => x),
        throwsA(isA<DecryptionFailedException>()),
      );
    });

    test(
      'each write uses a fresh GCM nonce (no nonce reuse under a key)',
      () async {
        // The single most important GCM safety property. Encrypt the same
        // plaintext many times and assert every 12-byte nonce (envelope bytes
        // 32..43 in passphrase mode: 1 version + 1 mode + 12 params + 1 saltLen
        // + 16 salt + 1 nonceLen) is distinct. Runs against the REAL vault
        // crypto (no cipher mock), so a regression to a fixed/derived nonce
        // fails here.
        final v = vault();
        const n = 50;
        final nonces = <String>{};
        final envelopes = <String>{};
        for (var i = 0; i < n; i++) {
          final key = 'k$i';
          await v.store(key, _bytes([1, 2, 3, 4]));
          final raw = backend.store_[key]!;
          nonces.add(raw.sublist(32, 44).join(','));
          envelopes.add(raw.join(','));
        }
        expect(nonces.length, n, reason: 'all $n nonces must be unique');
        expect(envelopes.length, n, reason: 'all $n envelopes must differ');
      },
    );

    test('an over-ceiling Argon2id memory param is rejected before the KDF runs '
        '(decrypt-time OOM/DoS guard)', () async {
      // A tamper attacker (in-scope per SECURITY.md) rewrites the envelope's
      // Argon2 memory cost. It must fail fast as PayloadCorruptException — the
      // validation gate runs before key derivation — rather than allocating a
      // process-killing amount of memory. memoryKiB lives at envelope bytes
      // 2..5 (big-endian, right after version+mode).
      final v = vault();
      await v.store('k', _bytes([1, 2, 3]));
      final raw = backend.store_['k']!;
      // 256 MiB + 1 KiB = 262145 = 0x00040001 — one past the ceiling.
      raw[2] = 0x00;
      raw[3] = 0x04;
      raw[4] = 0x00;
      raw[5] = 0x01;
      await expectLater(
        v.useAndForget('k', (b) async => b),
        throwsA(isA<PayloadCorruptException>()),
      );
    });

    test(
      'params are recorded in the envelope (decrypts after a param bump)',
      () async {
        // Write with sensitive-ish small params, read with a vault constructed
        // with different default params: the envelope's own params must win.
        final writer = PassphraseVault.passphrase(
          inner: backend,
          passphrase: _bytes([9, 9]),
          params: const Argon2idParams(
            memoryKiB: 512,
            iterations: 2,
            parallelism: 1,
          ),
        );
        await writer.store('k', _bytes([1, 2, 3]));
        final reader = PassphraseVault.passphrase(
          inner: backend,
          passphrase: _bytes([9, 9]),
          params: _fastParams, // different from what was written
        );
        expect(
          await reader.useAndForget('k', (b) async => Uint8List.fromList(b)),
          _bytes([1, 2, 3]),
        );
      },
    );

    test('read of an absent key returns null', () async {
      expect(await vault().useAndForget('nope', (b) async => b), isNull);
    });
  });

  group('PassphraseVault — keyring mode', () {
    late _FakeOubliette backend;
    setUp(() => backend = _FakeOubliette());

    test(
      'store/read round-trips and persists the KEK in the backend',
      () async {
        final v = PassphraseVault.keyring(inner: backend);
        await v.init();
        await v.store('seed', _bytes([3, 1, 4, 1, 5]));
        expect(
          backend.store_.containsKey(PassphraseVault.reservedKekKey),
          true,
          reason: 'random KEK stored in the backend',
        );
        expect(
          await v.useAndForget('seed', (b) async => Uint8List.fromList(b)),
          _bytes([3, 1, 4, 1, 5]),
        );
      },
    );

    test('a second vault over the same backend reads prior data', () async {
      final v1 = PassphraseVault.keyring(inner: backend);
      await v1.init();
      await v1.store('k', _bytes([2, 7, 1, 8]));
      final v2 = PassphraseVault.keyring(inner: backend); // fresh instance
      expect(
        await v2.useAndForget('k', (b) async => Uint8List.fromList(b)),
        _bytes([2, 7, 1, 8]),
      );
    });

    test('keyring blob carries mode=0', () async {
      final v = PassphraseVault.keyring(inner: backend);
      await v.store('k', _bytes([1]));
      expect(backend.store_['k']![1], 0);
    });

    test('the reserved KEK key is rejected on the public API (cannot brick the '
        'vault by deleting/overwriting the master key)', () async {
      final v = PassphraseVault.keyring(inner: backend);
      await v.init();
      await v.store('real', _bytes([1, 2, 3]));
      final reserved = PassphraseVault.reservedKekKey;

      expect(
        () => v.store(reserved, _bytes([0])),
        throwsA(isA<ArgumentError>()),
      );
      expect(() => v.trash(reserved), throwsA(isA<ArgumentError>()));
      expect(() => v.exists(reserved), throwsA(isA<ArgumentError>()));
      expect(
        () => v.useAndForget(reserved, (b) async => b),
        throwsA(isA<ArgumentError>()),
      );

      // The KEK and existing secret survive the rejected calls.
      expect(backend.store_.containsKey(reserved), true);
      expect(
        await v.useAndForget('real', (b) async => Uint8List.fromList(b)),
        _bytes([1, 2, 3]),
      );
    });

    test(
      'purge() drops the cached KEK — post-purge data is readable by a FRESH '
      'vault (the documented purge → init recovery flow)',
      () async {
        final v = PassphraseVault.keyring(inner: backend);
        await v.init();
        await v.store('seed', _bytes([1, 2, 3]));

        await v.purge();
        await v.init(); // re-provision: must mint & PERSIST a new KEK
        await v.store('seed', _bytes([4, 5, 6]));

        expect(
          backend.store_.containsKey(PassphraseVault.reservedKekKey),
          true,
          reason:
              'the KEK encrypting post-purge data must exist in the backend — '
              'a stale in-memory KEK would strand the data on restart',
        );

        // Simulates an app restart: a fresh vault has no in-memory cache and
        // must decrypt using only what the backend holds.
        final fresh = PassphraseVault.keyring(inner: backend);
        expect(
          await fresh.useAndForget('seed', (b) async => Uint8List.fromList(b)),
          _bytes([4, 5, 6]),
        );
      },
    );

    test('a corrupt (wrong-length) stored KEK is refused, not used', () async {
      final v1 = PassphraseVault.keyring(inner: backend);
      await v1.init();
      // Corrupt the KEK behind the vault's back.
      backend.store_[PassphraseVault.reservedKekKey] = _bytes([1, 2, 3]);
      final v2 = PassphraseVault.keyring(inner: backend); // no cache
      await expectLater(
        v2.store('k', _bytes([9])),
        throwsA(isA<PayloadCorruptException>()),
      );
    });

    test(
      'relocating a blob to another key fails (AAD + per-slot subkey)',
      () async {
        // Keyring mode binds the key into BOTH the GCM AAD and the HKDF subkey
        // info, so a relocated blob must fail closed — the immunity SECURITY.md
        // markets for keyring mode (random per-profile KEK).
        final v = PassphraseVault.keyring(inner: backend);
        await v.init();
        await v.store('a', _bytes([1, 2, 3]));
        backend.store_['b'] =
            backend.store_['a']!; // move a's ciphertext under b
        await expectLater(
          v.useAndForget('b', (x) async => x),
          throwsA(isA<DecryptionFailedException>()),
        );
      },
    );

    test(
      'init() surfaces backend errors eagerly (not deferred to store)',
      () async {
        final v = PassphraseVault.keyring(inner: _InitFailingOubliette());
        await expectLater(
          v.init(),
          throwsA(isA<BackendUnavailableException>()),
        );
      },
    );
  });

  group('PassphraseVault — lifecycle (dispose)', () {
    test('every operation throws StateError after dispose()', () async {
      final backend = _FakeOubliette();
      final v = PassphraseVault.passphrase(
        inner: backend,
        passphrase: _bytes([1, 2, 3, 4]),
        params: _fastParams,
      );
      await v.store('k', _bytes([9]));
      v.dispose();

      // store() after dispose is the dangerous one: the passphrase bytes were
      // zeroed in place, so it would otherwise encrypt under an all-zero
      // passphrase — trivially derivable offline AND unreadable by the real
      // passphrase.
      await expectLater(v.store('k2', _bytes([1])), throwsStateError);
      // The non-async methods throw synchronously — assert via closures.
      expect(() => v.useAndForget('k', (b) async => b), throwsStateError);
      expect(() => v.trash('k'), throwsStateError);
      expect(() => v.exists('k'), throwsStateError);
      await expectLater(v.purge(), throwsStateError);
      await expectLater(v.init(), throwsStateError);

      // Nothing was written by the rejected post-dispose store.
      expect(backend.store_.containsKey('k2'), false);
    });

    test('keyring mode is equally dead after dispose()', () async {
      final backend = _FakeOubliette();
      final v = PassphraseVault.keyring(inner: backend);
      await v.init();
      v.dispose();
      await expectLater(v.store('k', _bytes([1])), throwsStateError);
    });
  });

  group('PassphraseVault — modes do not silently cross', () {
    test('a keyring vault refuses a passphrase-written blob', () async {
      final backend = _FakeOubliette();
      await PassphraseVault.passphrase(
        inner: backend,
        passphrase: _bytes([1, 2]),
        params: _fastParams,
      ).store('k', _bytes([9]));
      final keyringVault = PassphraseVault.keyring(inner: backend);
      await expectLater(
        keyringVault.useAndForget('k', (b) async => b),
        throwsA(isA<PayloadCorruptException>()),
      );
    });
  });

  group('PassphraseVault — tampered-envelope hardening (VAULT-1/2/3)', () {
    late _FakeOubliette backend;
    setUp(() => backend = _FakeOubliette());

    // Passphrase envelope layout: [0]=ver, [1]=mode, [2..13]=argon2 params
    // (mem,iter,par uint32), [14]=saltLen(16), [15..30]=salt, [31]=nonceLen(12),
    // [32..43]=nonce, [44..]=ct.
    Future<Uint8List> writeBlob() async {
      final v = PassphraseVault.passphrase(
        inner: backend,
        passphrase: _bytes([1, 2, 3, 4]),
        params: _fastParams,
      );
      await v.store('k', _bytes([5, 6, 7, 8]));
      return backend.store_['k']!;
    }

    PassphraseVault reader() => PassphraseVault.passphrase(
      inner: backend,
      passphrase: _bytes([1, 2, 3, 4]),
      params: _fastParams,
    );

    test(
      'VAULT-1: an absurd memoryKiB is rejected before the KDF runs',
      () async {
        final raw = await writeBlob();
        // Patch memoryKiB (bytes 2..5) to ~2 GiB → must be rejected, NOT allocated.
        raw.buffer.asByteData().setUint32(2, 0x7FFFFFFF);
        await expectLater(
          reader().useAndForget('k', (b) async => b),
          throwsA(isA<PayloadCorruptException>()),
        );
      },
    );

    test(
      'VAULT-2: a bad nonce length surfaces as PayloadCorruptException',
      () async {
        final raw = await writeBlob();
        raw[31] = 0; // nonceLen byte → 0 (writer always emits 12)
        await expectLater(
          reader().useAndForget('k', (b) async => b),
          throwsA(isA<PayloadCorruptException>()),
        );
      },
    );

    test(
      'VAULT-2: a bad salt length surfaces as PayloadCorruptException',
      () async {
        final raw = await writeBlob();
        raw[14] = 8; // saltLen byte → 8 (writer always emits 16)
        await expectLater(
          reader().useAndForget('k', (b) async => b),
          throwsA(isA<PayloadCorruptException>()),
        );
      },
    );

    test('VAULT-3: an in-range header tamper fails the GCM tag', () async {
      final raw = await writeBlob();
      // Flip iterations 1→2 (still in range, so it passes validation) — the
      // header is bound into the AAD and the derived key differs, so it fails
      // closed as a decryption failure.
      raw[9] = 2; // low byte of iterations uint32 (bytes 6..9)
      await expectLater(
        reader().useAndForget('k', (b) async => b),
        throwsA(isA<DecryptionFailedException>()),
      );
    });
  });

  group('PassphraseVault — hostile envelope (second pass)', () {
    late _FakeOubliette backend;
    setUp(() => backend = _FakeOubliette());

    Future<Uint8List> writeBlob() async {
      final v = PassphraseVault.passphrase(
        inner: backend,
        passphrase: _bytes([1, 2, 3, 4]),
        params: _fastParams,
      );
      await v.store('k', _bytes([5, 6, 7, 8]));
      return backend.store_['k']!;
    }

    PassphraseVault reader() => PassphraseVault.passphrase(
      inner: backend,
      passphrase: _bytes([1, 2, 3, 4]),
      params: _fastParams,
    );

    test(
      'EVERY truncation of the envelope fails typed — never RangeError/OOM',
      () async {
        final raw = Uint8List.fromList(await writeBlob());
        // Envelope: 44-byte header (ver,mode,params,saltLen,salt,nonceLen,
        // nonce) + 4-byte ct + 16-byte tag = 64 bytes.
        expect(raw.length, 64, reason: 'frozen layout assumption');
        final v = reader();
        for (var cut = 0; cut < raw.length; cut++) {
          backend.store_['k'] = Uint8List.fromList(raw.sublist(0, cut));
          await expectLater(
            v.useAndForget('k', (b) async => b),
            throwsA(isA<OublietteException>()),
            reason: 'cut at $cut must surface a typed failure',
          );
        }
        // Cuts inside the header or shorter than the GCM tag are corruption,
        // classified precisely (no KDF ever ran for them).
        backend.store_['k'] = Uint8List.fromList(raw.sublist(0, 50));
        await expectLater(
          v.useAndForget('k', (b) async => b),
          throwsA(isA<PayloadCorruptException>()),
        );
      },
    );

    test('a lying length field cannot read out of bounds', () async {
      final raw = await writeBlob();
      raw[14] = 0xFF; // saltLen byte claims 255 (buffer has 16)
      await expectLater(
        reader().useAndForget('k', (b) async => b),
        throwsA(isA<PayloadCorruptException>()),
      );
    });

    test('out-of-range iterations is rejected before the KDF', () async {
      final raw = await writeBlob();
      raw.buffer.asByteData().setUint32(6, 65); // ceiling is 64
      await expectLater(
        reader().useAndForget('k', (b) async => b),
        throwsA(isA<PayloadCorruptException>()),
      );
    });

    test('zero parallelism is rejected before the KDF', () async {
      final raw = await writeBlob();
      raw.buffer.asByteData().setUint32(10, 0); // floor is 1
      await expectLater(
        reader().useAndForget('k', (b) async => b),
        throwsA(isA<PayloadCorruptException>()),
      );
    });

    test('an unknown format version fails typed', () async {
      final raw = await writeBlob();
      raw[0] = 2;
      await expectLater(
        reader().useAndForget('k', (b) async => b),
        throwsA(isA<PayloadCorruptException>()),
      );
    });

    test('a flipped mode byte is refused as a cross-mode blob', () async {
      final raw = await writeBlob();
      raw[1] = 0; // passphrase → keyring
      await expectLater(
        reader().useAndForget('k', (b) async => b),
        throwsA(isA<PayloadCorruptException>()),
      );
    });

    test('appended garbage fails the GCM tag', () async {
      final raw = await writeBlob();
      backend.store_['k'] = Uint8List.fromList([...raw, 0xAA, 0xBB, 0xCC]);
      await expectLater(
        reader().useAndForget('k', (b) async => b),
        throwsA(isA<DecryptionFailedException>()),
      );
    });
  });

  group('PassphraseVault — key validation (AAD injectivity)', () {
    test('a lone-surrogate key is rejected on every public entry', () async {
      // The key feeds the AAD via utf8.encode, where every lone surrogate
      // collapses into the same U+FFFD bytes — 'a\uD800' and 'a\uDC00' would
      // share one AAD, so a blob swapped between them would still decrypt.
      final backend = _FakeOubliette();
      final v = PassphraseVault.passphrase(
        inner: backend,
        passphrase: _bytes([1, 2]),
        params: _fastParams,
      );
      const bad = 'a\uD800';
      await expectLater(v.store(bad, _bytes([1])), throwsArgumentError);
      expect(() => v.useAndForget(bad, (b) async => b), throwsArgumentError);
      expect(() => v.trash(bad), throwsArgumentError);
      expect(() => v.exists(bad), throwsArgumentError);
      expect(backend.store_, isEmpty);
    });

    test(
      'a well-formed surrogate PAIR (emoji key) still round-trips',
      () async {
        final backend = _FakeOubliette();
        final v = PassphraseVault.passphrase(
          inner: backend,
          passphrase: _bytes([1, 2]),
          params: _fastParams,
        );
        await v.store('seed\u{1F4B0}', _bytes([4, 2]));
        expect(
          await v.useAndForget(
            'seed\u{1F4B0}',
            (b) async => Uint8List.fromList(b),
          ),
          _bytes([4, 2]),
        );
      },
    );
  });

  group('PassphraseVault — purge/dispose racing in-flight ops', () {
    test('keyring store racing purge() fails closed — never encrypts under the '
        'zeroed KEK buffer', () async {
      final backend = _FakeOubliette();
      final v = PassphraseVault.keyring(inner: backend);
      await v.init(); // KEK minted and cached
      // purge() first, store() second: purge's continuation (which zeroes
      // the cached KEK buffer IN PLACE) runs before the store's key
      // derivation resumes. Without the post-await liveness check the store
      // would HKDF an all-zero KEK — producing a blob anyone can decrypt
      // offline and no future vault can read.
      final p = v.purge();
      final f = v.store('k', _bytes([9, 9, 9]));
      await expectLater(f, throwsStateError);
      await p;
      expect(
        backend.store_.containsKey('k'),
        false,
        reason: 'the aborted store must not have written anything',
      );
    });

    test('dispose() while the KEK fetch is in flight aborts the store and '
        'never re-caches key material into the disposed vault', () async {
      final backend = _GatedOubliette();
      backend.fetchGates[PassphraseVault.reservedKekKey] = Completer<void>();
      final v = PassphraseVault.keyring(inner: backend);
      final f = v.store('k', _bytes([1]));
      await Future<void>.delayed(Duration.zero); // reach the gated fetch
      v.dispose();
      backend.fetchGates[PassphraseVault.reservedKekKey]!.complete();
      await expectLater(f, throwsStateError);
      expect(backend.store_.containsKey('k'), false);
    });

    test(
      'purge() crossing a KEK mint is retried against post-purge truth — the '
      'KEK that encrypts the data is the one persisted in the backend',
      () async {
        final backend = _GatedOubliette();
        backend.storeGates[PassphraseVault.reservedKekKey] = Completer<void>();
        final v = PassphraseVault.keyring(inner: backend);
        final f = v.store('k', _bytes([7, 7]));
        await Future<void>.delayed(Duration.zero); // mint reaches gated store
        await v.purge(); // epoch bump while the mint is suspended
        backend.storeGates[PassphraseVault.reservedKekKey]!.complete();
        await f; // must complete coherently (retried, not wedged)
        expect(
          backend.store_.containsKey(PassphraseVault.reservedKekKey),
          true,
        );
        // The acid test: a FRESH vault (no in-memory state) can decrypt with
        // only what the backend holds — no phantom in-memory-only KEK.
        final fresh = PassphraseVault.keyring(inner: backend);
        expect(
          await fresh.useAndForget('k', (b) async => Uint8List.fromList(b)),
          _bytes([7, 7]),
        );
      },
    );

    test('passphrase-mode read racing dispose() surfaces StateError, not a '
        'misleading wrong-passphrase DecryptionFailedException', () async {
      final backend = _GatedOubliette();
      final v = PassphraseVault.passphrase(
        inner: backend,
        passphrase: _bytes([1, 2]),
        params: _fastParams,
      );
      await v.store('k', _bytes([9]));
      backend.fetchGates['k'] = Completer<void>();
      final f = v.useAndForget('k', (b) async => Uint8List.fromList(b));
      await Future<void>.delayed(Duration.zero); // suspend on the fetch
      v.dispose(); // zeroes the passphrase in place
      backend.fetchGates['k']!.complete();
      await expectLater(f, throwsStateError);
    });
  });

  group('PassphraseVault — delegation', () {
    test('exists / trash / purge pass through to the backend', () async {
      final backend = _FakeOubliette();
      final v = PassphraseVault.passphrase(
        inner: backend,
        passphrase: _bytes([1]),
        params: _fastParams,
      );
      await v.store('a', _bytes([1]));
      expect(await v.exists('a'), true);
      await v.trash('a');
      expect(await v.exists('a'), false);
      await v.store('b', _bytes([2]));
      await v.purge();
      expect(await v.exists('b'), false);
    });
  });
}
