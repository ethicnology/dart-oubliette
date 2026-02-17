import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:oubliette/oubliette.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('store/useStringAndForget/trash round-trip', (WidgetTester tester) async {
    final plugin = Oubliette(
        android: const AndroidSecretAccess.onlyUnlocked(strongBox: false),
      darwin: const DarwinSecretAccess.onlyUnlocked(secureEnclave: false),
    );
    const key = 'plugin_test_key';
    const value = 'hello plugin';
    await plugin.storeString(key, value);
    final fetched = await plugin.useStringAndForget<String>(key, (v) async => v);
    expect(fetched, value);
    await plugin.trash(key);
    final missing = await plugin.useStringAndForget<String>(key, (v) async => v);
    expect(missing, isNull);
  });
}
