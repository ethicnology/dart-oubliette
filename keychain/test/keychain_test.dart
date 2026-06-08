import 'package:flutter_test/flutter_test.dart';
import 'package:keychain/keychain.dart';

/// The `KeychainConfig.toMap()` wire shape is a security contract: the native
/// side reads optional flags with `?? false`, so a falsey/absent flag MUST be
/// omitted (never sent as `false`), and a set flag MUST be present. A
/// regression here could silently drop an access-control or accessibility
/// attribute, downgrading protection.
void main() {
  KeychainConfig config({
    String? service,
    KeychainAccessibility accessibility =
        KeychainAccessibility.whenUnlockedThisDeviceOnly,
    bool useDataProtection = false,
    bool authenticationRequired = false,
    bool biometryCurrentSetOnly = false,
    String? authenticationPrompt,
    bool secureEnclave = false,
    String? accessGroup,
  }) => KeychainConfig(
    service: service,
    accessibility: accessibility,
    useDataProtection: useDataProtection,
    authenticationRequired: authenticationRequired,
    biometryCurrentSetOnly: biometryCurrentSetOnly,
    authenticationPrompt: authenticationPrompt,
    secureEnclave: secureEnclave,
    accessGroup: accessGroup,
  );

  group('KeychainAccessibility', () {
    test('every value maps to its documented string', () {
      expect(KeychainAccessibility.whenUnlocked.value, 'whenUnlocked');
      expect(
        KeychainAccessibility.whenUnlockedThisDeviceOnly.value,
        'whenUnlockedThisDeviceOnly',
      );
      expect(KeychainAccessibility.afterFirstUnlock.value, 'afterFirstUnlock');
      expect(
        KeychainAccessibility.afterFirstUnlockThisDeviceOnly.value,
        'afterFirstUnlockThisDeviceOnly',
      );
      expect(
        KeychainAccessibility.whenPasscodeSetThisDeviceOnly.value,
        'whenPasscodeSetThisDeviceOnly',
      );
    });
  });

  group('KeychainConfig.toMap() wire shape', () {
    test('omits every falsey/null option (native reads ?? false)', () {
      final map = config().toMap();
      expect(map['accessibility'], 'whenUnlockedThisDeviceOnly');
      for (final absent in const [
        'service',
        'useDataProtection',
        'authenticationRequired',
        'biometryCurrentSetOnly',
        'authenticationPrompt',
        'secureEnclave',
        'accessGroup',
      ]) {
        expect(
          map.containsKey(absent),
          isFalse,
          reason: '$absent must be omitted when unset',
        );
      }
    });

    test('includes each flag only when set', () {
      final map = config(
        service: 'svc',
        accessibility: KeychainAccessibility.whenPasscodeSetThisDeviceOnly,
        useDataProtection: true,
        authenticationRequired: true,
        biometryCurrentSetOnly: true,
        authenticationPrompt: 'why',
        secureEnclave: true,
        accessGroup: 'group.app',
      ).toMap();
      expect(map['accessibility'], 'whenPasscodeSetThisDeviceOnly');
      expect(map['service'], 'svc');
      expect(map['useDataProtection'], true);
      expect(map['authenticationRequired'], true);
      expect(map['biometryCurrentSetOnly'], true);
      expect(map['authenticationPrompt'], 'why');
      expect(map['secureEnclave'], true);
      expect(map['accessGroup'], 'group.app');
    });

    test('a false flag is omitted, not sent as false', () {
      final map = config(authenticationRequired: false).toMap();
      expect(map.containsKey('authenticationRequired'), isFalse);
    });
  });
}
