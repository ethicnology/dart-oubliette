import 'package:flutter_test/flutter_test.dart';
import 'package:oubliette/oubliette.dart';

/// Each named profile encodes a security posture as a fixed set of native
/// flags. A regression here is a silent downgrade (e.g. an "authenticated"
/// profile that no longer requires auth), so every field of every profile is
/// pinned explicitly — not just the prefix (covered in profile_prefix_test).
void main() {
  group('AndroidSecretAccess profile → flags', () {
    test('evenLocked', () {
      const a = AndroidSecretAccess.evenLocked(strongBox: false);
      expect(a.keyAlias, 'oubliette_even_locked');
      expect(a.prefix, 'oubliette_even_locked_');
      expect(a.unlockedDeviceRequired, false);
      expect(a.userAuthenticationRequired, false);
      expect(a.invalidatedByBiometricEnrollment, false);
      expect(a.promptTitle, isNull);
      expect(a.promptSubtitle, isNull);
    });

    test('onlyUnlocked', () {
      const a = AndroidSecretAccess.onlyUnlocked(strongBox: false);
      expect(a.keyAlias, 'oubliette_only_unlocked');
      expect(a.prefix, 'oubliette_only_unlocked_');
      expect(a.unlockedDeviceRequired, true);
      expect(a.userAuthenticationRequired, false);
      expect(a.invalidatedByBiometricEnrollment, false);
    });

    test('authenticated requires auth, survives enrollment change', () {
      const a = AndroidSecretAccess.authenticated(
        strongBox: false,
        promptTitle: 't',
        promptSubtitle: 's',
      );
      expect(a.keyAlias, 'oubliette_authenticated');
      expect(a.prefix, 'oubliette_authenticated_');
      expect(a.unlockedDeviceRequired, true);
      expect(a.userAuthenticationRequired, true);
      expect(a.invalidatedByBiometricEnrollment, false);
      expect(a.promptTitle, 't');
      expect(a.promptSubtitle, 's');
    });

    test('authenticatedFatal invalidates on enrollment change', () {
      const a = AndroidSecretAccess.authenticatedFatal(
        strongBox: false,
        promptTitle: 't',
        promptSubtitle: 's',
      );
      expect(a.keyAlias, 'oubliette_authenticated_fatal');
      expect(a.prefix, 'oubliette_authenticated_fatal_');
      expect(a.unlockedDeviceRequired, true);
      expect(a.userAuthenticationRequired, true);
      expect(a.invalidatedByBiometricEnrollment, true);
    });

    test('strongBox flag is carried through unchanged', () {
      expect(
        const AndroidSecretAccess.onlyUnlocked(strongBox: true).strongBox,
        true,
      );
      expect(
        const AndroidSecretAccess.onlyUnlocked(strongBox: false).strongBox,
        false,
      );
    });

    test('custom derives userAuthenticationRequired from promptTitle', () {
      final withPrompt = AndroidSecretAccess.custom(
        prefix: 'p_',
        keyAlias: 'a',
        strongBox: false,
        unlockedDeviceRequired: true,
        invalidatedByBiometricEnrollment: false,
        promptTitle: 'unlock',
        promptSubtitle: null,
      );
      expect(withPrompt.userAuthenticationRequired, true);

      final noPrompt = AndroidSecretAccess.custom(
        prefix: 'p_',
        keyAlias: 'a',
        strongBox: false,
        unlockedDeviceRequired: true,
        invalidatedByBiometricEnrollment: false,
        promptTitle: null,
        promptSubtitle: null,
      );
      expect(noPrompt.userAuthenticationRequired, false);
    });
  });

  group('DarwinSecretAccess profile → flags', () {
    test('evenLocked', () {
      const d = DarwinSecretAccess.evenLocked(secureEnclave: false);
      expect(d.accessibility,
          KeychainAccessibility.afterFirstUnlockThisDeviceOnly);
      expect(d.useDataProtection, false);
      expect(d.authenticationRequired, false);
      expect(d.biometryCurrentSetOnly, false);
      expect(d.authenticationPrompt, isNull);
    });

    test('onlyUnlocked', () {
      const d = DarwinSecretAccess.onlyUnlocked(secureEnclave: false);
      expect(
          d.accessibility, KeychainAccessibility.whenUnlockedThisDeviceOnly);
      expect(d.useDataProtection, false);
      expect(d.authenticationRequired, false);
      expect(d.biometryCurrentSetOnly, false);
    });

    test('authenticated → data protection + auth, no current-set-only', () {
      const d = DarwinSecretAccess.authenticated(
        promptReason: 'why',
        secureEnclave: false,
      );
      expect(
          d.accessibility, KeychainAccessibility.whenUnlockedThisDeviceOnly);
      expect(d.useDataProtection, true);
      expect(d.authenticationRequired, true);
      expect(d.biometryCurrentSetOnly, false);
      expect(d.authenticationPrompt, 'why');
    });

    test('authenticatedFatal → passcode-set accessibility + current-set-only',
        () {
      const d = DarwinSecretAccess.authenticatedFatal(
        promptReason: 'why',
        secureEnclave: false,
      );
      expect(d.accessibility,
          KeychainAccessibility.whenPasscodeSetThisDeviceOnly);
      expect(d.useDataProtection, true);
      expect(d.authenticationRequired, true);
      expect(d.biometryCurrentSetOnly, true);
      expect(d.authenticationPrompt, 'why');
    });

    test('secureEnclave flag is carried through unchanged', () {
      expect(
        const DarwinSecretAccess.onlyUnlocked(secureEnclave: true).secureEnclave,
        true,
      );
      expect(
        const DarwinSecretAccess.onlyUnlocked(secureEnclave: false)
            .secureEnclave,
        false,
      );
    });
  });

  group('DarwinSecretAccess.toConfig().toMap() wire shape', () {
    test('onlyUnlocked omits false/null flags', () {
      final map = const DarwinSecretAccess.onlyUnlocked(secureEnclave: false)
          .toConfig()
          .toMap();
      expect(map['accessibility'], 'whenUnlockedThisDeviceOnly');
      // Falsey/absent options must not be present (native reads `?? false`).
      expect(map.containsKey('useDataProtection'), false);
      expect(map.containsKey('authenticationRequired'), false);
      expect(map.containsKey('biometryCurrentSetOnly'), false);
      expect(map.containsKey('secureEnclave'), false);
      expect(map.containsKey('service'), false);
      expect(map.containsKey('accessGroup'), false);
      expect(map.containsKey('authenticationPrompt'), false);
    });

    test('authenticatedFatal serializes all security flags', () {
      final map = const DarwinSecretAccess.authenticatedFatal(
        promptReason: 'reason',
        secureEnclave: true,
        service: 'svc',
      ).toConfig().toMap();
      expect(map['accessibility'], 'whenPasscodeSetThisDeviceOnly');
      expect(map['useDataProtection'], true);
      expect(map['authenticationRequired'], true);
      expect(map['biometryCurrentSetOnly'], true);
      expect(map['secureEnclave'], true);
      expect(map['authenticationPrompt'], 'reason');
      expect(map['service'], 'svc');
    });
  });
}
