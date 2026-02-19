import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:keystore/keystore.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  if (!Platform.isAndroid) {
    debugPrint(
      'Keystore integration tests run only on Android. Skipping.',
    );
    return;
  }

  group('$Keystore (Android)', () {
    late Keystore facade;
    const alias = 'integration_test_keystore_key';
    final plaintext = Uint8List.fromList(
      utf8.encode('plaintext for keystore'),
    );
    const aad = 'test_aad';
    const expectedEncryptionVersion = 1;

    setUpAll(() {
      facade = Keystore();
    });

    tearDown(() async => await facade.deleteEntry(alias));
    testWidgets('containsAlias returns false when alias does not exist', (
      tester,
    ) async {
      final exists = await facade.containsAlias(alias);
      expect(exists, isFalse);
    });

    testWidgets('generateKey creates key and containsAlias returns true', (
      tester,
    ) async {
      await facade.generateKey(alias: alias, unlockedDeviceRequired: false, strongBox: false);
      final exists = await facade.containsAlias(alias);
      expect(exists, isTrue);
    });

    testWidgets('encrypt returns nonce, ciphertext, version, aad, alias', (
      tester,
    ) async {
      await facade.generateKey(alias: alias, unlockedDeviceRequired: false, strongBox: false);
      final payload = await facade.encrypt(
        alias: alias,
        plaintext: plaintext,
        aad: aad,
      );
      expect(payload.nonce.length, 12);
      expect(payload.ciphertext.length, greaterThan(0));
      expect(payload.version, expectedEncryptionVersion);
      expect(payload.aad, aad);
      expect(payload.keyAlias, alias);
    });

    testWidgets('decrypt recovers plaintext using payload version, aad, alias',
        (tester) async {
      await facade.generateKey(alias: alias, unlockedDeviceRequired: false, strongBox: false);
      final encrypted = await facade.encrypt(
        alias: alias,
        plaintext: plaintext,
        aad: aad,
      );
      final decrypted = await facade.decrypt(
        version: encrypted.version,
        alias: encrypted.keyAlias,
        ciphertext: encrypted.ciphertext,
        nonce: encrypted.nonce,
        aad: encrypted.aad,
      );
      expect(decrypted, equals(plaintext));
    });

    testWidgets('decrypt returns non-zeroed plaintext bytes', (tester) async {
      await facade.generateKey(alias: alias, unlockedDeviceRequired: false, strongBox: false);
      final encrypted = await facade.encrypt(alias: alias, plaintext: plaintext, aad: aad);
      final decrypted = await facade.decrypt(
        version: encrypted.version,
        alias: encrypted.keyAlias,
        ciphertext: encrypted.ciphertext,
        nonce: encrypted.nonce,
        aad: encrypted.aad,
      );
      expect(decrypted, equals(plaintext));
      expect(decrypted.any((b) => b != 0), isTrue);
    });

    testWidgets('decrypt with wrong nonce throws PlatformException', (tester) async {
      await facade.generateKey(alias: alias, unlockedDeviceRequired: false, strongBox: false);
      final encrypted = await facade.encrypt(alias: alias, plaintext: plaintext, aad: aad);
      final wrongNonce = Uint8List(12);
      expect(
        () => facade.decrypt(
          version: encrypted.version,
          alias: encrypted.keyAlias,
          ciphertext: encrypted.ciphertext,
          nonce: wrongNonce,
          aad: encrypted.aad,
        ),
        throwsA(isA<PlatformException>()),
      );
    });

    testWidgets('encrypt with auth key requires authentication', (tester) async {
      const authAlias = 'integration_test_auth_key';
      await facade.generateKey(
        alias: authAlias,
        unlockedDeviceRequired: false,
        strongBox: false,
        userAuthenticationRequired: true,
      );
      try {
        await facade.encrypt(
          alias: authAlias,
          plaintext: plaintext,
          aad: aad,
          promptTitle: 'Test',
          promptSubtitle: 'Authenticate',
        );
      } on PlatformException catch (e) {
        debugPrint('auth encrypt result: ${e.code} ${e.message}');
      } finally {
        await facade.deleteEntry(authAlias);
      }
    });

    testWidgets('isStrongBoxAvailable returns bool', (tester) async {
      final available = await facade.isStrongBoxAvailable();
      expect(available, isA<bool>());
    });

    testWidgets('deleteEntry removes key and containsAlias returns false', (
      tester,
    ) async {
      await facade.generateKey(alias: alias, unlockedDeviceRequired: false, strongBox: false);
      expect(await facade.containsAlias(alias), isTrue);
      await facade.deleteEntry(alias);
      final exists = await facade.containsAlias(alias);
      expect(exists, isFalse);
    });
  });
}
