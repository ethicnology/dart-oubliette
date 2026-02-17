import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:oubliette/oubliette.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  if (!Platform.isIOS && !Platform.isMacOS) {
    debugPrint('DarwinSecretAccess tests run only on iOS and macOS. Skipping.');
    return;
  }

  group('DarwinSecretAccess.evenLocked', () {
    late Oubliette storage;
    const prefix = 'test_even_locked_';

    setUp(() {
      storage = Oubliette(
        android: const AndroidSecretAccess.evenLocked(),
        darwin: const DarwinSecretAccess.evenLocked(prefix: prefix),
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

  group('DarwinSecretAccess.onlyUnlocked', () {
    late Oubliette storage;
    const prefix = 'test_only_unlocked_';

    setUp(() {
      storage = Oubliette(
        android: const AndroidSecretAccess.onlyUnlocked(strongBox: false),
        darwin: const DarwinSecretAccess.onlyUnlocked(
          prefix: prefix,
          secureEnclave: false,
        ),
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

  group('DarwinSecretAccess.biometric (requires Touch ID / Face ID)', () {
    late Oubliette storage;
    const prefix = 'test_bio_';

    setUp(() {
      storage = Oubliette(
        android: const AndroidSecretAccess.evenLocked(),
        darwin: const DarwinSecretAccess.biometric(
          prefix: prefix,
          promptReason: 'Authenticate for biometric test',
          secureEnclave: true,
        ),
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

  group('DarwinSecretAccess.biometricFatal (requires Touch ID / Face ID)', () {
    late Oubliette storage;
    const prefix = 'test_bio_strict_';

    setUp(() {
      storage = Oubliette(
        android: const AndroidSecretAccess.evenLocked(),
        darwin: const DarwinSecretAccess.biometricFatal(
          prefix: prefix,
          promptReason: 'Authenticate for biometricFatal test',
          secureEnclave: true,
        ),
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
