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
}
