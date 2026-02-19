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
        android: const AndroidSecretAccess.evenLocked(prefix: 'test_el_', strongBox: false),
        darwin: const DarwinSecretAccess.evenLocked(secureEnclave: false),
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

  group('AndroidSecretAccess.authenticated (requires fingerprint / PIN)', () {
    late Oubliette storage;

    setUp(() {
      storage = Oubliette(
        android: const AndroidSecretAccess.authenticated(
          prefix: 'test_auth_',
          strongBox: false,
          promptTitle: 'Oubliette Test',
          promptSubtitle: 'Authenticate for test',
        ),
        darwin: const DarwinSecretAccess.evenLocked(secureEnclave: false),
      );
    });

    testWidgets('store/useAndForget round-trip — authenticate when prompted', (
      tester,
    ) async {
      const key = 'auth_key';
      final value = Uint8List.fromList(utf8.encode('authenticated secret'));
      await storage.store(key, value);
      final decoded = await storage.useAndForget<String>(
        key,
        (bytes) async => utf8.decode(bytes),
      );
      expect(decoded, 'authenticated secret');
      await storage.trash(key);
    });
  });

  group('AndroidSecretAccess.authenticatedFatal (requires fingerprint / PIN)', () {
    late Oubliette storage;

    setUp(() {
      storage = Oubliette(
        android: const AndroidSecretAccess.authenticatedFatal(
          prefix: 'test_af_',
          strongBox: false,
          promptTitle: 'Oubliette Test',
          promptSubtitle: 'Authenticate for authenticatedFatal test',
        ),
        darwin: const DarwinSecretAccess.evenLocked(secureEnclave: false),
      );
    });

    testWidgets('store/useAndForget round-trip — authenticate when prompted', (
      tester,
    ) async {
      const key = 'af_key';
      final value = Uint8List.fromList(utf8.encode('fatal authenticated secret'));
      await storage.store(key, value);
      final decoded = await storage.useAndForget<String>(
        key,
        (bytes) async => utf8.decode(bytes),
      );
      expect(decoded, 'fatal authenticated secret');
      await storage.trash(key);
    });
  });
}
