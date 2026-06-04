import 'dart:io';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:keystore/keystore.dart';
import 'package:oubliette/oubliette.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// On-device regression tests for behaviors introduced by the security
/// refactor. The Dart unit tests cover these against a mocked channel; these
/// exercise the real native layer. Biometric/SE-dependent fixes (fail-closed
/// auth, key_invalidated) need an enrolled credential and live in the manual
/// RELEASE_CHECKLIST instead.
void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  // Cross-profile isolation works on every platform; run it everywhere.
  group('cross-profile slot isolation (#11 / #12 / #13)', () {
    testWidgets('a key stored under one profile is invisible to another',
        (tester) async {
      final onlyUnlocked = Oubliette(
        android: const AndroidSecretAccess.onlyUnlocked(strongBox: false),
        darwin: const DarwinSecretAccess.onlyUnlocked(secureEnclave: false),
      );
      final evenLocked = Oubliette(
        android: const AndroidSecretAccess.evenLocked(strongBox: false),
        darwin: const DarwinSecretAccess.evenLocked(secureEnclave: false),
      );

      const key = 'iso_shared_key';
      addTearDown(() async {
        await onlyUnlocked.trash(key);
        await evenLocked.trash(key);
      });

      await onlyUnlocked.store(key, Uint8List.fromList([1, 2, 3]));

      // Same logical key, different profile → different slot → not found.
      expect(await evenLocked.exists(key), isFalse);
      final cross = await evenLocked.useAndForget<List<int>>(
        key,
        (bytes) async => List<int>.from(bytes),
      );
      expect(cross, isNull);

      // The owning profile still reads it back.
      final own = await onlyUnlocked.useAndForget<List<int>>(
        key,
        (bytes) async => List<int>.from(bytes),
      );
      expect(own, equals([1, 2, 3]));
    });
  });

  group('idempotent init & lazy-ensure (N2 / N6)', () {
    testWidgets('store works without an explicit init() call', (tester) async {
      final storage = Oubliette(
        android: const AndroidSecretAccess.onlyUnlocked(
          prefix: 'reg_lazy_',
          strongBox: false,
        ),
        darwin: const DarwinSecretAccess.onlyUnlocked(
          prefix: 'reg_lazy_',
          secureEnclave: false,
        ),
      );
      const key = 'lazy_key';
      addTearDown(() => storage.trash(key));

      // No init() — store must lazily ensure the key exists.
      await storage.store(key, Uint8List.fromList([9, 9, 9]));
      final out = await storage.useAndForget<List<int>>(
        key,
        (bytes) async => List<int>.from(bytes),
      );
      expect(out, equals([9, 9, 9]));
    });

    testWidgets('init() is idempotent across repeated calls', (tester) async {
      final storage = Oubliette(
        android: const AndroidSecretAccess.onlyUnlocked(
          prefix: 'reg_init_',
          strongBox: false,
        ),
        darwin: const DarwinSecretAccess.onlyUnlocked(
          prefix: 'reg_init_',
          secureEnclave: false,
        ),
      );
      // None of these should throw, even called concurrently.
      await storage.init();
      await Future.wait([storage.init(), storage.init()]);
    });
  });

  group('Android-only refactor regressions', () {
    if (!Platform.isAndroid) {
      return;
    }

    testWidgets('StrongBox is fail-closed when unavailable (N1)',
        (tester) async {
      final keystore = Keystore();
      final hasStrongBox = await keystore.isStrongBoxAvailable();
      if (hasStrongBox) {
        // This device has StrongBox; the fail-closed path can't be exercised.
        return;
      }
      const alias = 'reg_strongbox_alias';
      addTearDown(() => keystore.deleteEntry(alias));

      await expectLater(
        keystore.generateKey(
          alias: alias,
          unlockedDeviceRequired: false,
          strongBox: true,
        ),
        throwsA(
          isA<PlatformException>()
              .having((e) => e.code, 'code', 'strongbox_unavailable'),
        ),
      );
      // No key must have been created as a silent TEE fallback.
      expect(await keystore.containsAlias(alias), isFalse);
    });

    testWidgets('fetch rejects a tampered payload (#5 / M1)', (tester) async {
      final storage = Oubliette(
        android: const AndroidSecretAccess.onlyUnlocked(
          prefix: 'reg_tamper_',
          strongBox: false,
        ),
        darwin: const DarwinSecretAccess.onlyUnlocked(secureEnclave: false),
      );
      const key = 'tamper_key';
      const slot = 'reg_tamper_$key';
      addTearDown(() => storage.trash(key));

      await storage.store(key, Uint8List.fromList([7, 7, 7]));

      // Rewrite the on-disk blob so its aad points at a different slot —
      // simulating an attacker relocating the payload in SharedPreferences.
      final prefs = await SharedPreferences.getInstance();
      final original = EncryptedPayload.fromJson(prefs.getString(slot)!);
      final tampered = EncryptedPayload(
        version: original.version,
        nonce: original.nonce,
        ciphertext: original.ciphertext,
        aad: 'reg_tamper_some_other_key',
        keyAlias: original.keyAlias,
      );
      await prefs.setString(slot, tampered.toJson());

      await expectLater(
        storage.useAndForget<void>(key, (_) async {}),
        throwsA(isA<PayloadTamperException>()),
      );
    });
  });
}
