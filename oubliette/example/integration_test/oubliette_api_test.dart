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
      storage = createOubliette();
    });

    testWidgets('store/fetch/trash bytes round-trip', (WidgetTester tester) async {
      const key = 'api_test_bytes';
      final value = Uint8List.fromList(utf8.encode('secret bytes'));
      await storage.store(key, value);
      final fetched = await storage.fetch(key);
      expect(fetched, isNotNull);
      expect(utf8.decode(fetched!), 'secret bytes');
      await storage.trash(key);
      expect(await storage.fetch(key), isNull);
    });

    testWidgets('storeString/fetchString/trash round-trip', (WidgetTester tester) async {
      const key = 'api_test_string';
      const value = 'secret string';
      await storage.storeString(key, value);
      final fetched = await storage.fetchString(key);
      expect(fetched, value);
      await storage.trash(key);
      expect(await storage.fetchString(key), isNull);
    });

    testWidgets('exists returns true after store, false after trash', (WidgetTester tester) async {
      const key = 'api_test_exists';
      expect(await storage.exists(key), false);
      await storage.store(key, Uint8List.fromList([1, 2, 3]));
      expect(await storage.exists(key), true);
      await storage.trash(key);
      expect(await storage.exists(key), false);
    });

    testWidgets('store overwrites existing value', (WidgetTester tester) async {
      const key = 'api_test_overwrite';
      await storage.store(key, Uint8List.fromList(utf8.encode('first')));
      await storage.store(key, Uint8List.fromList(utf8.encode('second')));
      final fetched = await storage.fetchString(key);
      expect(fetched, 'second');
      await storage.trash(key);
    });
  });
}
