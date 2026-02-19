import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:oubliette/oubliette.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  group('Oubliette (end-user API)', () {
    late Oubliette storage;

    setUp(() {
      storage = Oubliette(
        android: const AndroidSecretAccess.onlyUnlocked(strongBox: false),
        darwin: const DarwinSecretAccess.onlyUnlocked(secureEnclave: false),
      );
    });

    testWidgets('store/useAndForget/trash bytes round-trip', (WidgetTester tester) async {
      const key = 'api_test_bytes';
      final value = Uint8List.fromList(utf8.encode('secret bytes'));
      await storage.store(key, value);
      final decoded = await storage.useAndForget<String>(key, (bytes) async => utf8.decode(bytes));
      expect(decoded, 'secret bytes');
      await storage.trash(key);
      final missing = await storage.useAndForget<String>(key, (bytes) async => utf8.decode(bytes));
      expect(missing, isNull);
    });

    testWidgets('store/useAndForget/trash string-as-bytes round-trip', (WidgetTester tester) async {
      const key = 'api_test_string';
      final value = Uint8List.fromList(utf8.encode('secret string'));
      await storage.store(key, value);
      final fetched = await storage.useAndForget<String>(key, (bytes) async => utf8.decode(bytes));
      expect(fetched, 'secret string');
      await storage.trash(key);
      final missing = await storage.useAndForget<String>(key, (bytes) async => utf8.decode(bytes));
      expect(missing, isNull);
    });

    testWidgets('exists returns true after store, false after trash', (WidgetTester tester) async {
      const key = 'api_test_exists';
      expect(await storage.exists(key), false);
      await storage.store(key, Uint8List.fromList([1, 2, 3]));
      expect(await storage.exists(key), true);
      await storage.trash(key);
      expect(await storage.exists(key), false);
    });

    testWidgets('store fails if key already exists', (WidgetTester tester) async {
      const key = 'api_test_dup';
      await storage.store(key, Uint8List.fromList(utf8.encode('first')));
      try {
        await storage.store(key, Uint8List.fromList(utf8.encode('second')));
        fail('Expected store to fail on duplicate key');
      } catch (_) {}
      await storage.trash(key);
    });
  });
}
