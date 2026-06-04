import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:keystore/keystore.dart';

void main() {
  group('EncryptedPayload', () {
    final payload = EncryptedPayload(
      version: 1,
      nonce: Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]),
      ciphertext: Uint8List.fromList([42, 43, 44]),
      aad: 'oubliette_only_unlocked_k',
      keyAlias: 'oubliette_only_unlocked',
    );

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
}
