import 'package:flutter_test/flutter_test.dart';
import 'package:oubliette/oubliette.dart';
import 'package:oubliette/src/slot.dart';

/// Slot isolation is a security boundary: the four named profiles must each
/// default to a distinct storage prefix (#11 / #12 / #13), and the custom
/// constructors must reject collisions with those reserved prefixes.
void main() {
  group('Android default prefixes are distinct (#11)', () {
    const profiles = <String, AndroidSecretAccess>{
      'evenLocked': AndroidSecretAccess.evenLocked(strongBox: false),
      'onlyUnlocked': AndroidSecretAccess.onlyUnlocked(strongBox: false),
      'authenticated': AndroidSecretAccess.authenticated(
        strongBox: false,
        promptTitle: 't',
        promptSubtitle: 's',
      ),
      'authenticatedFatal': AndroidSecretAccess.authenticatedFatal(
        strongBox: false,
        promptTitle: 't',
        promptSubtitle: 's',
      ),
    };

    test('all four prefixes are unique', () {
      final prefixes = profiles.values.map((p) => p.prefix).toSet();
      expect(prefixes, hasLength(4));
    });

    test('custom rejects a reserved prefix', () {
      expect(
        () => AndroidSecretAccess.custom(
          prefix: 'oubliette_only_unlocked_',
          keyAlias: 'my_alias',
          strongBox: false,
          unlockedDeviceRequired: true,
          invalidatedByBiometricEnrollment: false,
          promptTitle: null,
          promptSubtitle: null,
        ),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('custom rejects a reserved key alias', () {
      expect(
        () => AndroidSecretAccess.custom(
          prefix: 'my_prefix_',
          keyAlias: 'oubliette_only_unlocked',
          strongBox: false,
          unlockedDeviceRequired: true,
          invalidatedByBiometricEnrollment: false,
          promptTitle: null,
          promptSubtitle: null,
        ),
        throwsA(isA<ArgumentError>()),
      );
    });

    AndroidSecretAccess androidCustom(String prefix) => AndroidSecretAccess.custom(
          prefix: prefix,
          keyAlias: 'unique_alias',
          strongBox: false,
          unlockedDeviceRequired: true,
          invalidatedByBiometricEnrollment: false,
          promptTitle: null,
          promptSubtitle: null,
        );

    test('custom rejects a prefix that is a prefix OF a reserved prefix', () {
      // "oubliette_only_unlocked" + "_k" would collide with onlyUnlocked + "k".
      expect(() => androidCustom('oubliette_only_unlocked'),
          throwsA(isA<ArgumentError>()));
    });

    test('custom rejects a prefix that EXTENDS a reserved prefix', () {
      // reserved + "x_" + key collides with this prefix + key.
      expect(() => androidCustom('oubliette_only_unlocked_x_'),
          throwsA(isA<ArgumentError>()));
    });

    test('custom accepts a clearly distinct prefix', () {
      expect(androidCustom('my_app_secrets_').prefix, 'my_app_secrets_');
    });

    test('custom rejects an empty prefix', () {
      expect(() => androidCustom(''), throwsA(isA<ArgumentError>()));
    });

    test('custom rejects a prefix containing the reserved slot separator', () {
      expect(() => androidCustom('bad${slotSeparator}prefix_'),
          throwsA(isA<ArgumentError>()));
    });

    test('custom rejects an empty keyAlias', () {
      expect(
        () => AndroidSecretAccess.custom(
          prefix: 'fine_prefix_',
          keyAlias: '',
          strongBox: false,
          unlockedDeviceRequired: true,
          invalidatedByBiometricEnrollment: false,
          promptTitle: null,
          promptSubtitle: null,
        ),
        throwsA(isA<ArgumentError>()),
      );
    });
  });

  group('Darwin default prefixes are distinct (#12 / #13)', () {
    const profiles = <String, DarwinSecretAccess>{
      'evenLocked': DarwinSecretAccess.evenLocked(secureEnclave: false),
      'onlyUnlocked': DarwinSecretAccess.onlyUnlocked(secureEnclave: false),
      'authenticated': DarwinSecretAccess.authenticated(
        promptReason: 'r',
        secureEnclave: false,
      ),
      'authenticatedFatal': DarwinSecretAccess.authenticatedFatal(
        promptReason: 'r',
        secureEnclave: false,
      ),
    };

    test('all four prefixes are unique', () {
      final prefixes = profiles.values.map((p) => p.prefix).toSet();
      expect(prefixes, hasLength(4));
    });

    test('Android and Darwin use the same prefix per profile', () {
      // Cross-platform symmetry: storing under "onlyUnlocked" lands in the same
      // logical slot name regardless of platform.
      expect(
        const AndroidSecretAccess.onlyUnlocked(strongBox: false).prefix,
        const DarwinSecretAccess.onlyUnlocked(secureEnclave: false).prefix,
      );
    });

    DarwinSecretAccess darwinCustom(String prefix) => DarwinSecretAccess.custom(
          prefix: prefix,
          service: null,
          accessibility: KeychainAccessibility.whenUnlockedThisDeviceOnly,
          useDataProtection: false,
          authenticationRequired: false,
          biometryCurrentSetOnly: false,
          authenticationPrompt: null,
          secureEnclave: false,
          accessGroup: null,
        );

    test('custom rejects a reserved prefix', () {
      expect(() => darwinCustom('oubliette_authenticated_'),
          throwsA(isA<ArgumentError>()));
    });

    test('custom rejects a prefix that is a prefix OF a reserved prefix', () {
      expect(() => darwinCustom('oubliette_authenticated'),
          throwsA(isA<ArgumentError>()));
    });

    test('custom rejects a prefix that EXTENDS a reserved prefix', () {
      expect(() => darwinCustom('oubliette_authenticated_extra_'),
          throwsA(isA<ArgumentError>()));
    });

    test('custom accepts a clearly distinct prefix', () {
      expect(darwinCustom('my_app_secrets_').prefix, 'my_app_secrets_');
    });

    test('custom rejects an empty prefix', () {
      expect(() => darwinCustom(''), throwsA(isA<ArgumentError>()));
    });

    test('custom rejects a prefix containing the reserved slot separator', () {
      expect(() => darwinCustom('bad${slotSeparator}prefix_'),
          throwsA(isA<ArgumentError>()));
    });

    DarwinSecretAccess darwinCustomAccess(KeychainAccessibility a) =>
        DarwinSecretAccess.custom(
          prefix: 'device_local_test_',
          service: null,
          accessibility: a,
          useDataProtection: false,
          authenticationRequired: false,
          biometryCurrentSetOnly: false,
          authenticationPrompt: null,
          secureEnclave: false,
          accessGroup: null,
        );

    test('custom rejects non-ThisDeviceOnly accessibility (every profile is '
        'device-local)', () {
      expect(() => darwinCustomAccess(KeychainAccessibility.whenUnlocked),
          throwsA(isA<ArgumentError>()));
      expect(() => darwinCustomAccess(KeychainAccessibility.afterFirstUnlock),
          throwsA(isA<ArgumentError>()));
    });

    test('custom accepts every *ThisDeviceOnly accessibility', () {
      expect(
          darwinCustomAccess(KeychainAccessibility.whenUnlockedThisDeviceOnly)
              .accessibility,
          KeychainAccessibility.whenUnlockedThisDeviceOnly);
      expect(
          darwinCustomAccess(
                  KeychainAccessibility.afterFirstUnlockThisDeviceOnly)
              .accessibility,
          KeychainAccessibility.afterFirstUnlockThisDeviceOnly);
      expect(
          darwinCustomAccess(
                  KeychainAccessibility.whenPasscodeSetThisDeviceOnly)
              .accessibility,
          KeychainAccessibility.whenPasscodeSetThisDeviceOnly);
    });
  });
}
