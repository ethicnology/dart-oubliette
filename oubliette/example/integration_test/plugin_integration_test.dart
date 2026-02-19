import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:oubliette/oubliette.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('store/useAndForget/trash round-trip', (WidgetTester tester) async {
    final plugin = Oubliette(
        android: const AndroidSecretAccess.onlyUnlocked(strongBox: false),
      darwin: const DarwinSecretAccess.onlyUnlocked(secureEnclave: false),
    );
    const key = 'plugin_test_key';
    final value = Uint8List.fromList(utf8.encode('hello plugin'));
    await plugin.trash(key);
    await plugin.store(key, value);
    final fetched = await plugin.useAndForget<String>(key, (bytes) async => utf8.decode(bytes));
    expect(fetched, 'hello plugin');
    await plugin.trash(key);
    final missing = await plugin.useAndForget<String>(key, (bytes) async => utf8.decode(bytes));
    expect(missing, isNull);
  });
}
