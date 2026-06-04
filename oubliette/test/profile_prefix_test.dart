import 'package:flutter_test/flutter_test.dart';
import 'package:oubliette/oubliette.dart';

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

    test('custom rejects a reserved prefix', () {
      expect(
        () => DarwinSecretAccess.custom(
          prefix: 'oubliette_authenticated_',
          service: null,
          accessibility: KeychainAccessibility.whenUnlockedThisDeviceOnly,
          useDataProtection: false,
          authenticationRequired: false,
          biometryCurrentSetOnly: false,
          authenticationPrompt: null,
          secureEnclave: false,
          accessGroup: null,
        ),
        throwsA(isA<ArgumentError>()),
      );
    });
  });
}
