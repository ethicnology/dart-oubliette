import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:keystore/keystore.dart';

void main() {
  // Canonical payload shared by the format tests and the golden vectors below.
  final payload = EncryptedPayload(
    version: 1,
    nonce: Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]),
    ciphertext: Uint8List.fromList([42, 43, 44]),
    aad: 'oubliette_only_unlocked_k',
    keyAlias: 'oubliette_only_unlocked',
  );

  group('EncryptedPayload', () {
    test('round-trips through JSON', () {
      final restored = EncryptedPayload.fromJson(payload.toJson());
      expect(restored.version, payload.version);
      expect(restored.nonce, payload.nonce);
      expect(restored.ciphertext, payload.ciphertext);
      expect(restored.aad, payload.aad);
      expect(restored.keyAlias, payload.keyAlias);
    });

    test('uses the snake_case key_alias wire key', () {
      expect(payload.toMap().containsKey('key_alias'), isTrue);
      expect(payload.toMap().containsKey('keyAlias'), isFalse);
    });

    test('base64-encodes nonce and ciphertext', () {
      final map = payload.toMap();
      expect(map['nonce'], isA<String>());
      expect(map['ciphertext'], isA<String>());
    });

    test('rejects a malformed blob', () {
      expect(
        () => EncryptedPayload.fromJson('{"version":"oops"}'),
        throwsA(isA<FormatException>()),
      );
    });

    test('rejects non-object JSON', () {
      expect(
        () => EncryptedPayload.fromJson('[1,2,3]'),
        throwsA(isA<FormatException>()),
      );
    });
  });

  // UPGRADE-SAFETY GUARANTEE. These golden vectors freeze the v1 on-disk wire
  // format. A future change that makes the *current* code unable to read data
  // written by v1.0.0 will fail here. If a vector must change, that is a
  // breaking on-disk format change requiring an explicit migration + a new
  // format version — never silently edit a golden string. (Mirrors Tink's
  // cross-version test vectors.)
  group('golden v1 wire format', () {
    // Frozen literal exactly as v1.0.0 serialises the canonical payload above.
    const goldenV1 =
        '{"version":1,'
        '"nonce":"AQIDBAUGBwgJCgsM",'
        '"ciphertext":"Kiss",'
        '"aad":"oubliette_only_unlocked_k",'
        '"key_alias":"oubliette_only_unlocked"}';

    test('current code still serialises to the frozen v1 bytes', () {
      expect(
        payload.toJson(),
        goldenV1,
        reason: 'serialisation drift would orphan data on upgrade',
      );
    });

    test('current code still reads a frozen v1 blob', () {
      final restored = EncryptedPayload.fromJson(goldenV1);
      expect(restored.version, 1);
      expect(
        restored.nonce,
        Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]),
      );
      expect(restored.ciphertext, Uint8List.fromList([42, 43, 44]));
      expect(restored.aad, 'oubliette_only_unlocked_k');
      expect(restored.keyAlias, 'oubliette_only_unlocked');
    });

    test('forward-compatible: unknown future fields are ignored, not fatal', () {
      // A later version may add envelope fields; v1 readers must tolerate them
      // so a downgrade/mixed-version install does not hard-fail on read.
      const withFutureField =
          '{"version":1,'
          '"nonce":"AQIDBAUGBwgJCgsM",'
          '"ciphertext":"Kiss",'
          '"aad":"oubliette_only_unlocked_k",'
          '"key_alias":"oubliette_only_unlocked",'
          '"future_field":"ignored","format":2}';
      final restored = EncryptedPayload.fromJson(withFutureField);
      expect(restored.version, 1);
      expect(restored.keyAlias, 'oubliette_only_unlocked');
    });
  });

  // Corruption must surface as a clear FormatException, never as a silently
  // wrong payload or an opaque downstream `decrypt_failed`. The oubliette layer
  // translates these into a typed PayloadCorruptException.
  group('deserialization hardening', () {
    String blob({
      String version = '1',
      String nonce = 'AQIDBAUGBwgJCgsM',
      String ciphertext = 'Kiss',
    }) =>
        '{"version":$version,"nonce":"$nonce","ciphertext":"$ciphertext",'
        '"aad":"a","key_alias":"k"}';

    test('rejects an empty nonce', () {
      expect(
        () => EncryptedPayload.fromJson(blob(nonce: '')),
        throwsA(isA<FormatException>()),
      );
    });

    test('rejects an empty ciphertext', () {
      expect(
        () => EncryptedPayload.fromJson(blob(ciphertext: '')),
        throwsA(isA<FormatException>()),
      );
    });

    test('rejects a version below 1', () {
      expect(
        () => EncryptedPayload.fromJson(blob(version: '0')),
        throwsA(isA<FormatException>()),
      );
      expect(
        () => EncryptedPayload.fromJson(blob(version: '-3')),
        throwsA(isA<FormatException>()),
      );
    });

    test('rejects non-base64 nonce/ciphertext', () {
      expect(
        () => EncryptedPayload.fromJson(blob(nonce: '!!!notb64!!!')),
        throwsA(isA<FormatException>()),
      );
      expect(
        () => EncryptedPayload.fromJson(blob(ciphertext: '@@@')),
        throwsA(isA<FormatException>()),
      );
    });

    // Pins the defense-in-depth bounds: an implausibly large version or an
    // oversized field must be rejected up front as corruption, not parsed.
    test('rejects an implausibly large version', () {
      expect(
        () => EncryptedPayload.fromJson(blob(version: '${(1 << 20) + 1}')),
        throwsA(isA<FormatException>()),
      );
    });

    test('rejects an oversized field', () {
      // 64 KiB + 4 chars of valid base64 — over the per-field cap.
      final huge = 'AAAA' * (16 * 1024 + 1);
      expect(
        () => EncryptedPayload.fromJson(blob(nonce: huge)),
        throwsA(isA<FormatException>()),
      );
    });

    test('rejects a missing field', () {
      // key_alias absent.
      expect(
        () => EncryptedPayload.fromJson(
          '{"version":1,"nonce":"AQIDBAUGBwgJCgsM","ciphertext":"Kiss","aad":"a"}',
        ),
        throwsA(isA<FormatException>()),
      );
    });
  });

  // WRITE/READ SYMMETRY. The read path has always capped fields (above); these
  // pin the write-side mirror. Without it, an oversized secret stores
  // successfully and then EVERY read rejects it as corruption — self-inflicted,
  // permanent data stranding. The invariant under test: anything constructable
  // (and therefore storable) is readable back, and anything over the cap fails
  // loudly at write time, before any data exists to strand.
  group('write-side size caps (fail the write, never strand the data)', () {
    EncryptedPayload build({
      Uint8List? nonce,
      Uint8List? ciphertext,
      String aad = 'a',
      String keyAlias = 'k',
    }) => EncryptedPayload(
      version: 1,
      nonce: nonce ?? Uint8List(12),
      ciphertext: ciphertext ?? Uint8List.fromList([42]),
      aad: aad,
      keyAlias: keyAlias,
    );

    test('rejects a ciphertext one byte over the cap at construction', () {
      expect(
        () => build(ciphertext: Uint8List(EncryptedPayload.maxFieldBytes + 1)),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('rejects an oversized nonce at construction', () {
      expect(
        () => build(nonce: Uint8List(EncryptedPayload.maxFieldBytes + 1)),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('rejects an oversized aad / keyAlias at construction', () {
      final huge = 'a' * (EncryptedPayload.maxFieldChars + 1);
      expect(() => build(aad: huge), throwsA(isA<ArgumentError>()));
      expect(() => build(keyAlias: huge), throwsA(isA<ArgumentError>()));
    });

    test('boundary: a maxFieldBytes ciphertext writes AND reads back', () {
      // The largest storable field must survive the full round trip: 48 KiB of
      // bytes base64-encodes to exactly the 64 Ki-char read cap, so a payload
      // the constructor accepts can never be rejected by fromMap. A drift
      // between the two constants (write cap above read cap) fails here.
      final maxCiphertext = Uint8List.fromList(
        List.generate(EncryptedPayload.maxFieldBytes, (i) => i % 251),
      );
      final written = build(ciphertext: maxCiphertext);
      final restored = EncryptedPayload.fromJson(written.toJson());
      expect(restored.ciphertext, maxCiphertext);
      expect(restored.nonce, written.nonce);
    });

    test('the shared constants agree (write cap encodes to the read cap)', () {
      // 4 base64 chars per 3 bytes, exact at the boundary.
      expect(
        base64Encode(Uint8List(EncryptedPayload.maxFieldBytes)).length,
        EncryptedPayload.maxFieldChars,
      );
    });
  });
}
