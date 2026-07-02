import 'package:flutter_test/flutter_test.dart';
import 'package:oubliette/oubliette.dart';
import 'package:oubliette/src/slot.dart';

/// Slot isolation is a security boundary: the four named profiles must each
/// default to a distinct storage prefix (#11 / #12 / #13), and the custom
/// constructors must reject collisions with those reserved prefixes.
void main() {
  group('Android default prefixes are distinct (#11)', () {
    setUp(AndroidSecretAccess.resetCustomAliasRegistry);

    const profiles = <String, AndroidSecretAccess>{
      'evenLocked': AndroidSecretAccess.evenLocked(
        strongBox: false,
        requireHardwareBacking: false,
      ),
      'onlyUnlocked': AndroidSecretAccess.onlyUnlocked(
        strongBox: false,
        requireHardwareBacking: false,
      ),
      'authenticated': AndroidSecretAccess.authenticated(
        strongBox: false,
        requireHardwareBacking: false,
        promptTitle: 't',
        promptSubtitle: 's',
      ),
      'authenticatedFatal': AndroidSecretAccess.authenticatedFatal(
        strongBox: false,
        requireHardwareBacking: false,
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
          requireHardwareBacking: false,
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
          requireHardwareBacking: false,
          unlockedDeviceRequired: true,
          invalidatedByBiometricEnrollment: false,
          promptTitle: null,
          promptSubtitle: null,
        ),
        throwsA(isA<ArgumentError>()),
      );
    });

    AndroidSecretAccess androidCustom(String prefix) =>
        AndroidSecretAccess.custom(
          prefix: prefix,
          keyAlias: 'unique_alias',
          strongBox: false,
          requireHardwareBacking: false,
          unlockedDeviceRequired: true,
          invalidatedByBiometricEnrollment: false,
          promptTitle: null,
          promptSubtitle: null,
        );

    test('custom rejects a prefix that is a prefix OF a reserved prefix', () {
      // "oubliette_only_unlocked" + "_k" would collide with onlyUnlocked + "k".
      expect(
        () => androidCustom('oubliette_only_unlocked'),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('custom rejects a prefix that EXTENDS a reserved prefix', () {
      // reserved + "x_" + key collides with this prefix + key.
      expect(
        () => androidCustom('oubliette_only_unlocked_x_'),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('custom accepts a clearly distinct prefix', () {
      expect(androidCustom('my_app_secrets_').prefix, 'my_app_secrets_');
    });

    test('custom rejects an empty prefix', () {
      expect(() => androidCustom(''), throwsA(isA<ArgumentError>()));
    });

    test('custom rejects a prefix containing the reserved slot separator', () {
      expect(
        () => androidCustom('bad${slotSeparator}prefix_'),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('custom rejects an empty keyAlias', () {
      expect(
        () => AndroidSecretAccess.custom(
          prefix: 'fine_prefix_',
          keyAlias: '',
          strongBox: false,
          requireHardwareBacking: false,
          unlockedDeviceRequired: true,
          invalidatedByBiometricEnrollment: false,
          promptTitle: null,
          promptSubtitle: null,
        ),
        throwsA(isA<ArgumentError>()),
      );
    });

    // L-2: two custom profiles sharing a Keystore alias would share key
    // material — purge() of one deletes the shared key and permanently bricks
    // the other. The per-isolate registry rejects the second claim.
    test(
      'custom rejects a keyAlias already claimed by another custom profile',
      () {
        // First claim succeeds.
        AndroidSecretAccess.custom(
          prefix: 'domain_a_',
          keyAlias: 'shared_key',
          strongBox: false,
          requireHardwareBacking: false,
          unlockedDeviceRequired: true,
          invalidatedByBiometricEnrollment: false,
          promptTitle: null,
          promptSubtitle: null,
        );
        // Second claim with the same alias but a different prefix — the exact
        // collision that would brick the first profile on purge().
        expect(
          () => AndroidSecretAccess.custom(
            prefix: 'domain_b_',
            keyAlias: 'shared_key',
            strongBox: false,
            requireHardwareBacking: false,
            unlockedDeviceRequired: true,
            invalidatedByBiometricEnrollment: false,
            promptTitle: null,
            promptSubtitle: null,
          ),
          throwsA(isA<ArgumentError>()),
        );
      },
    );
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
        const AndroidSecretAccess.onlyUnlocked(
          strongBox: false,
          requireHardwareBacking: false,
        ).prefix,
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
      expect(
        () => darwinCustom('oubliette_authenticated_'),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('custom rejects a prefix that is a prefix OF a reserved prefix', () {
      expect(
        () => darwinCustom('oubliette_authenticated'),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('custom rejects a prefix that EXTENDS a reserved prefix', () {
      expect(
        () => darwinCustom('oubliette_authenticated_extra_'),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('custom accepts a clearly distinct prefix', () {
      expect(darwinCustom('my_app_secrets_').prefix, 'my_app_secrets_');
    });

    test('custom rejects an empty prefix', () {
      expect(() => darwinCustom(''), throwsA(isA<ArgumentError>()));
    });

    test('custom rejects a prefix containing the reserved slot separator', () {
      expect(
        () => darwinCustom('bad${slotSeparator}prefix_'),
        throwsA(isA<ArgumentError>()),
      );
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
      expect(
        () => darwinCustomAccess(KeychainAccessibility.whenUnlocked),
        throwsA(isA<ArgumentError>()),
      );
      expect(
        () => darwinCustomAccess(KeychainAccessibility.afterFirstUnlock),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('custom accepts every *ThisDeviceOnly accessibility', () {
      expect(
        darwinCustomAccess(
          KeychainAccessibility.whenUnlockedThisDeviceOnly,
        ).accessibility,
        KeychainAccessibility.whenUnlockedThisDeviceOnly,
      );
      expect(
        darwinCustomAccess(
          KeychainAccessibility.afterFirstUnlockThisDeviceOnly,
        ).accessibility,
        KeychainAccessibility.afterFirstUnlockThisDeviceOnly,
      );
      expect(
        darwinCustomAccess(
          KeychainAccessibility.whenPasscodeSetThisDeviceOnly,
        ).accessibility,
        KeychainAccessibility.whenPasscodeSetThisDeviceOnly,
      );
    });

    DarwinSecretAccess darwinCustomAuth({
      required bool authenticationRequired,
      required bool biometryCurrentSetOnly,
    }) => DarwinSecretAccess.custom(
      prefix: 'auth_combo_test_',
      service: null,
      accessibility: KeychainAccessibility.whenPasscodeSetThisDeviceOnly,
      useDataProtection: true,
      authenticationRequired: authenticationRequired,
      biometryCurrentSetOnly: biometryCurrentSetOnly,
      authenticationPrompt: 'auth',
      secureEnclave: false,
      accessGroup: null,
    );

    test('custom rejects biometryCurrentSetOnly without authenticationRequired '
        '(would store an un-gated item)', () {
      expect(
        () => darwinCustomAuth(
          authenticationRequired: false,
          biometryCurrentSetOnly: true,
        ),
        throwsA(isA<ArgumentError>()),
      );
    });

    test(
      'custom accepts biometryCurrentSetOnly with authenticationRequired',
      () {
        expect(
          darwinCustomAuth(
            authenticationRequired: true,
            biometryCurrentSetOnly: true,
          ).biometryCurrentSetOnly,
          true,
        );
      },
    );
  });

  group('buildSlot rejects malformed UTF-16 (slot-isolation)', () {
    // Distinct Dart strings whose lone surrogates UTF-8-encode to the SAME
    // replacement bytes — without the guard they collide into one native slot
    // (and one vault AAD), so fetching one key could return the other's secret.
    test('two keys differing only by an unpaired surrogate would collide', () {
      expect('a\uD800' == 'a\uDC00', isFalse, reason: 'distinct in Dart');
      expect(() => buildSlot('p_', 'a\uD800'), throwsA(isA<ArgumentError>()));
      expect(() => buildSlot('p_', 'a\uDC00'), throwsA(isA<ArgumentError>()));
    });

    test('unpaired surrogate in the prefix is rejected too', () {
      expect(() => buildSlot('p\uD800_', 'key'), throwsA(isA<ArgumentError>()));
      expect(
        () => validateSlotPrefix('p\uDFFF_'),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('well-formed non-ASCII keys still pass', () {
      // Properly paired surrogates (an emoji) and plain accents are fine.
      expect(
        buildSlot('p_', 'caf\u00e9\u{1F511}'),
        'p_${slotSeparator}caf\u00e9\u{1F511}',
      );
    });
  });

  group('buildSlot rejects embedded NUL (Linux C-string truncation)', () {
    // On the Linux backend the slot is a libsecret attribute value / D-Bus
    // string - a NUL-terminated C string - so a key containing U+0000 truncates
    // at the first NUL. Two distinct keys sharing a NUL-truncation prefix would
    // then collide into one native slot (fetch of one could return the other's
    // secret). NUL is well-formed UTF-16, so the surrogate guard misses it.
    test('two keys differing only after a NUL would collide', () {
      expect('a\u0000b' == 'a\u0000c', isFalse, reason: 'distinct in Dart');
      expect(() => buildSlot('p_', 'a\u0000b'), throwsA(isA<ArgumentError>()));
      expect(() => buildSlot('p_', 'a\u0000c'), throwsA(isA<ArgumentError>()));
    });

    test('NUL in the key or prefix is rejected', () {
      expect(
        () => buildSlot('p_', '\u0000probe'),
        throwsA(isA<ArgumentError>()),
      );
      expect(() => buildSlot('p\u0000_', 'key'), throwsA(isA<ArgumentError>()));
      expect(
        () => validateSlotPrefix('p\u0000_'),
        throwsA(isA<ArgumentError>()),
      );
    });
  });
}
