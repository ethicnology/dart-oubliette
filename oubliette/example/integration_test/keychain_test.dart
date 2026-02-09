import 'dart:convert';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:keychain/keychain.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  if (!Platform.isIOS && !Platform.isMacOS) {
    debugPrint(
      'Keychain integration tests run only on iOS and macOS. Skipping.',
    );
    return;
  }

  group('$Keychain (iOS / macOS) ${Platform.localeName}', () {
    late Keychain facade;
    const alias = 'integration_test_keychain_item';
    final data = Uint8List.fromList(
      utf8.encode('secret data for keychain'),
    );

    setUpAll(() {
      facade = Keychain();
    });

    tearDown(() => facade.secItemDelete(alias));

    testWidgets('contains returns false when alias does not exist', (
      tester,
    ) async {
      final exists = await facade.contains(alias);
      expect(exists, isFalse);
    });

    testWidgets('secItemAdd then contains returns true', (tester) async {
      await facade.secItemAdd(alias, data);
      final exists = await facade.contains(alias);
      expect(exists, isTrue);
    });

    testWidgets('secItemCopyMatching returns stored data after secItemAdd', (
      tester,
    ) async {
      await facade.secItemAdd(alias, data);
      final fetched = await facade.secItemCopyMatching(alias);
      expect(fetched, isNotNull);
      expect(fetched, equals(data));
    });

    testWidgets('secItemCopyMatching returns null when alias does not exist', (
      tester,
    ) async {
      final fetched = await facade.secItemCopyMatching('nonexistent_alias_xyz');
      expect(fetched, isNull);
    });

    testWidgets('secItemAdd with explicit accessibility', (tester) async {
      await facade.secItemAdd(
        alias,
        data,
        accessibility: KeychainAccessibility.whenUnlockedThisDeviceOnly,
      );
      final exists = await facade.contains(alias);
      expect(exists, isTrue);
    });

    testWidgets('secItemAdd accepts every KeychainAccessibility value', (
      tester,
    ) async {
      for (final accessibility in KeychainAccessibility.values) {
        final itemAlias = '${alias}_${accessibility.name}';
        addTearDown(() => facade.secItemDelete(itemAlias));
        await facade.secItemAdd(itemAlias, data, accessibility: accessibility);
        expect(await facade.contains(itemAlias), isTrue);
        final fetched = await facade.secItemCopyMatching(itemAlias);
        expect(fetched, equals(data));
      }
    });

    testWidgets('secItemDelete removes item and contains returns false', (
      tester,
    ) async {
      await facade.secItemAdd(alias, data);
      expect(await facade.contains(alias), isTrue);
      await facade.secItemDelete(alias);
      final exists = await facade.contains(alias);
      expect(exists, isFalse);
    });
  });
}
