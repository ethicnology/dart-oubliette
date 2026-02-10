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
      final fetched =
          await facade.secItemCopyMatching('nonexistent_alias_xyz');
      expect(fetched, isNull);
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

  group('$Keychain with KeychainConfig (iOS / macOS) ${Platform.localeName}',
      () {
    const alias = 'config_test_item';
    final data = Uint8List.fromList(utf8.encode('config test value'));

    testWidgets('explicit accessibility in config is respected', (
      tester,
    ) async {
      final facade = Keychain(
        config: const KeychainConfig(
          accessibility: KeychainAccessibility.whenUnlockedThisDeviceOnly,
        ),
      );
      addTearDown(() => facade.secItemDelete(alias));

      await facade.secItemAdd(alias, data);
      final exists = await facade.contains(alias);
      expect(exists, isTrue);
    });

    testWidgets('every KeychainAccessibility value works via config', (
      tester,
    ) async {
      for (final accessibility in KeychainAccessibility.values) {
        final itemAlias = '${alias}_${accessibility.name}';
        final facade = Keychain(
          config: KeychainConfig(accessibility: accessibility),
        );
        addTearDown(() => facade.secItemDelete(itemAlias));

        await facade.secItemAdd(itemAlias, data);
        expect(await facade.contains(itemAlias), isTrue);
        final fetched = await facade.secItemCopyMatching(itemAlias);
        expect(fetched, equals(data));
      }
    });
  });

  group(
      '$Keychain with service config (iOS / macOS) ${Platform.localeName}',
      () {
    late Keychain facadeA;
    late Keychain facadeB;
    late Keychain facadeNoService;
    const alias = 'service_test_item';
    final dataA = Uint8List.fromList(utf8.encode('service_a_value'));
    final dataB = Uint8List.fromList(utf8.encode('service_b_value'));

    setUpAll(() {
      facadeA = Keychain(
        config: const KeychainConfig(service: 'com.test.serviceA'),
      );
      facadeB = Keychain(
        config: const KeychainConfig(service: 'com.test.serviceB'),
      );
      facadeNoService = Keychain();
    });

    tearDown(() async {
      await facadeA.secItemDelete(alias);
      await facadeB.secItemDelete(alias);
      await facadeNoService.secItemDelete(alias);
    });

    testWidgets('same alias in different services are independent', (
      tester,
    ) async {
      await facadeA.secItemAdd(alias, dataA);
      await facadeB.secItemAdd(alias, dataB);

      final fetchedA = await facadeA.secItemCopyMatching(alias);
      final fetchedB = await facadeB.secItemCopyMatching(alias);

      expect(fetchedA, equals(dataA));
      expect(fetchedB, equals(dataB));
    });

    testWidgets('contains is scoped to service', (tester) async {
      await facadeA.secItemAdd(alias, dataA);

      expect(await facadeA.contains(alias), isTrue);
      expect(await facadeB.contains(alias), isFalse);
    });

    testWidgets('delete in one service does not affect another', (
      tester,
    ) async {
      await facadeA.secItemAdd(alias, dataA);
      await facadeB.secItemAdd(alias, dataB);

      await facadeA.secItemDelete(alias);

      expect(await facadeA.contains(alias), isFalse);
      expect(await facadeB.contains(alias), isTrue);
      expect(await facadeB.secItemCopyMatching(alias), equals(dataB));
    });

    testWidgets('no-service query matches items regardless of service', (
      tester,
    ) async {
      await facadeA.secItemAdd(alias, dataA);

      final fetched = await facadeNoService.secItemCopyMatching(alias);
      expect(fetched, isNotNull);
    });
  });
}
