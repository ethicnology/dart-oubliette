import 'package:flutter/services.dart';
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

  group('Keychain method-channel contract', () {
    TestWidgetsFlutterBinding.ensureInitialized();
    const channel = MethodChannel('keychain');
    final binding = TestDefaultBinaryMessengerBinding.instance;

    MethodCall? lastCall;
    Object? Function(MethodCall call)? handler;

    setUp(() {
      lastCall = null;
      handler = null;
      binding.defaultBinaryMessenger.setMockMethodCallHandler(channel, (call) async {
        lastCall = call;
        return handler?.call(call);
      });
    });

    tearDown(() {
      binding.defaultBinaryMessenger.setMockMethodCallHandler(channel, null);
    });

    Keychain keychain({bool secureEnclave = false, bool auth = false}) =>
        Keychain(
          config: config(
            service: 'svc',
            secureEnclave: secureEnclave,
            authenticationRequired: auth,
            accessGroup: 'group.app',
          ),
        );

    test('contains throws on a null native answer (never silent false)', () {
      handler = (_) => null;
      expect(
        () => keychain().contains('k'),
        throwsA(
          isA<PlatformException>().having(
            (e) => e.code,
            'code',
            'keychain_contains_failed',
          ),
        ),
      );
    });

    test(
      // `false` ("just created") is the restore-detection signal: a fresh SE
      // key cannot decrypt pre-existing ciphertext, and a caller acting on a
      // bogus `false` could take a data-destroying recovery path. A null /
      // indeterminate native answer must therefore throw, not default.
      'ensureEnclaveKeyPair throws on a null native answer (never "just created")',
      () {
        handler = (_) => null;
        expect(
          () => keychain(secureEnclave: true).ensureEnclaveKeyPair(),
          throwsA(
            isA<PlatformException>().having(
              (e) => e.code,
              'code',
              'se_ensure_key_failed',
            ),
          ),
        );
      },
    );

    test('ensureEnclaveKeyPair passes through the native tri-state', () async {
      handler = (_) => true;
      expect(
        await keychain(secureEnclave: true).ensureEnclaveKeyPair(),
        isTrue,
      );
      handler = (_) => false;
      expect(
        await keychain(secureEnclave: true).ensureEnclaveKeyPair(),
        isFalse,
      );
    });

    test('ensureEnclaveKeyPair sends only SE-key-identity scoping args', () async {
      // The SE key identity is (service, accessibility, accessGroup) plus the
      // macOS keychain-domain selector. Leaking item-level flags (alias,
      // authenticationRequired, …) here would desynchronize the native tag
      // from the one used on store/fetch.
      handler = (_) => true;
      await keychain(secureEnclave: true, auth: true).ensureEnclaveKeyPair();
      final args = (lastCall!.arguments as Map).cast<String, Object?>();
      expect(lastCall!.method, 'ensureEnclaveKeyPair');
      expect(args, {
        'service': 'svc',
        'accessibility': 'whenUnlockedThisDeviceOnly',
        'accessGroup': 'group.app',
      });
    });

    test('secItemCopyMatching returns null for a definite not-found', () async {
      handler = (_) => null;
      expect(await keychain().secItemCopyMatching('k'), isNull);
    });

    test('native error codes propagate untranslated', () {
      // The facade must not swallow or remap native codes — the oubliette
      // layer branches on them (se_key_missing → KeyNotFound, etc.).
      handler = (_) => throw PlatformException(code: 'se_key_missing');
      expect(
        () => keychain(secureEnclave: true).secItemCopyMatching('k'),
        throwsA(
          isA<PlatformException>().having(
            (e) => e.code,
            'code',
            'se_key_missing',
          ),
        ),
      );
    });

    test('deleteByPrefix rejects an empty prefix (never wipe-all)', () async {
      // An empty prefix would hasPrefix-match every account in scope. Guard it
      // at the facade so a malformed direct call cannot purge the whole scope.
      expect(() => keychain().deleteByPrefix(''), throwsA(isA<ArgumentError>()));
    });

    test('deleteByPrefix sends prefix, exclusions, and config scope', () async {
      await keychain().deleteByPrefix('p_', excludePrefixes: ['q_']);
      final args = (lastCall!.arguments as Map).cast<String, Object?>();
      expect(lastCall!.method, 'secItemDeleteByPrefix');
      expect(args['prefix'], 'p_');
      expect(args['excludePrefixes'], ['q_']);
      expect(args['service'], 'svc');
      expect(args['accessGroup'], 'group.app');
      expect(args.containsKey('alias'), isFalse);
    });
  });
}
