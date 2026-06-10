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
}

Uint8List _bytes(List<int> b) => Uint8List.fromList(b);

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

    test(
      'the reserved KEK key is rejected on the public API (cannot brick the '
      'vault by deleting/overwriting the master key)',
      () async {
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
      },
    );
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
