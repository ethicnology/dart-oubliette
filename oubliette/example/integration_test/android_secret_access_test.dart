import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:oubliette/oubliette.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  if (!Platform.isAndroid) {
    debugPrint('AndroidSecretAccess tests run only on Android. Skipping.');
    return;
  }

  group('AndroidSecretAccess.evenLocked', () {
    late Oubliette storage;

    setUp(() {
      storage = Oubliette(
        android: const AndroidSecretAccess.evenLocked(prefix: 'test_el_'),
        darwin: const DarwinSecretAccess.evenLocked(),
      );
    });

    testWidgets('store/useAndForget/trash round-trip', (tester) async {
      const key = 'el_key';
      final value = Uint8List.fromList(utf8.encode('even locked secret'));
      await storage.store(key, value);
      final decoded = await storage.useAndForget<String>(
        key,
        (bytes) async => utf8.decode(bytes),
      );
      expect(decoded, 'even locked secret');
      await storage.trash(key);
      final missing = await storage.useAndForget<String>(
        key,
        (bytes) async => utf8.decode(bytes),
      );
      expect(missing, isNull);
    });

    testWidgets('exists returns true after store, false after trash', (
      tester,
    ) async {
      const key = 'el_exists';
      expect(await storage.exists(key), false);
      await storage.store(key, Uint8List.fromList([1, 2, 3]));
      expect(await storage.exists(key), true);
      await storage.trash(key);
      expect(await storage.exists(key), false);
    });
  });

  group('AndroidSecretAccess.onlyUnlocked', () {
    late Oubliette storage;

    setUp(() {
      storage = Oubliette(
        android: const AndroidSecretAccess.onlyUnlocked(
          prefix: 'test_ou_',
          strongBox: false,
        ),
        darwin: const DarwinSecretAccess.onlyUnlocked(secureEnclave: false),
      );
    });

    testWidgets('store/useAndForget/trash round-trip', (tester) async {
      const key = 'ou_key';
      final value = Uint8List.fromList(utf8.encode('only unlocked secret'));
      await storage.store(key, value);
      final decoded = await storage.useAndForget<String>(
        key,
        (bytes) async => utf8.decode(bytes),
      );
      expect(decoded, 'only unlocked secret');
      await storage.trash(key);
      final missing = await storage.useAndForget<String>(
        key,
        (bytes) async => utf8.decode(bytes),
      );
      expect(missing, isNull);
    });

    testWidgets('exists returns true after store, false after trash', (
      tester,
    ) async {
      const key = 'ou_exists';
      expect(await storage.exists(key), false);
      await storage.store(key, Uint8List.fromList([4, 5, 6]));
      expect(await storage.exists(key), true);
      await storage.trash(key);
      expect(await storage.exists(key), false);
    });
  });

  group('AndroidSecretAccess.biometric (requires fingerprint / PIN)', () {
    late Oubliette storage;

    setUp(() {
      storage = Oubliette(
        android: const AndroidSecretAccess.biometric(
          prefix: 'test_bio_',
          strongBox: false,
          promptTitle: 'Oubliette Test',
          promptSubtitle: 'Authenticate for biometric test',
        ),
        darwin: const DarwinSecretAccess.evenLocked(),
      );
    });

    testWidgets('store/useAndForget round-trip — authenticate when prompted', (
      tester,
    ) async {
      const key = 'bio_key';
      final value = Uint8List.fromList(utf8.encode('biometric secret'));
      await storage.store(key, value);
      final decoded = await storage.useAndForget<String>(
        key,
        (bytes) async => utf8.decode(bytes),
      );
      expect(decoded, 'biometric secret');
      await storage.trash(key);
    });
  });

  group('AndroidSecretAccess.biometricFatal (requires fingerprint / PIN)', () {
    late Oubliette storage;

    setUp(() {
      storage = Oubliette(
        android: const AndroidSecretAccess.biometricFatal(
          prefix: 'test_bio_strict_',
          strongBox: false,
          promptTitle: 'Oubliette Test',
          promptSubtitle: 'Authenticate for biometricFatal test',
        ),
        darwin: const DarwinSecretAccess.evenLocked(),
      );
    });

    testWidgets('store/useAndForget round-trip — authenticate when prompted', (
      tester,
    ) async {
      const key = 'bio_strict_key';
      final value = Uint8List.fromList(utf8.encode('strict biometric secret'));
      await storage.store(key, value);
      final decoded = await storage.useAndForget<String>(
        key,
        (bytes) async => utf8.decode(bytes),
      );
      expect(decoded, 'strict biometric secret');
      await storage.trash(key);
    });
  });
}
