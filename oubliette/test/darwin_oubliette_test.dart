import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:oubliette/darwin_oubliette.dart';
import 'package:oubliette/oubliette.dart';
import 'package:oubliette/src/slot.dart';

/// In-memory stand-in for the native `keychain` MethodChannel. Keys items by
/// the full account (`prefix + key`) so slot isolation and round-trips behave
/// like the real Keychain. `secItemAdd` rejects duplicates with
/// `already_exists`, mirroring `errSecDuplicateItem`.
class _MockKeychain {
  final Map<String, Uint8List> items = {};
  int ensureEnclaveCalls = 0;
  int deleteEnclaveCalls = 0;

  /// When set, secItemCopyMatching and secItemDelete throw a PlatformException
  /// with this code — exercises the Darwin typed-error mapping on both the read
  /// and the delete path.
  String? fetchErrorCode;

  Future<Object?> handle(MethodCall call) async {
    final args = (call.arguments as Map).cast<String, dynamic>();
    switch (call.method) {
      case 'keychainContains':
        return items.containsKey(args['alias']);
      case 'secItemAdd':
        final alias = args['alias'] as String;
        if (items.containsKey(alias)) {
          throw PlatformException(code: 'already_exists', message: 'dup');
        }
        items[alias] = args['data'] as Uint8List;
        return null;
      case 'secItemCopyMatching':
        if (fetchErrorCode != null) {
          throw PlatformException(code: fetchErrorCode!, message: 'forced');
        }
        return items[args['alias'] as String];
      case 'secItemDelete':
        if (fetchErrorCode != null) {
          throw PlatformException(code: fetchErrorCode!, message: 'forced');
        }
        items.remove(args['alias']);
        return null;
      case 'secItemDeleteByPrefix':
        final prefix = args['prefix'] as String;
        final exclude =
            (args['excludePrefixes'] as List?)?.cast<String>() ?? const [];
        items.removeWhere(
          (account, _) =>
              account.startsWith(prefix) &&
              !exclude.any((e) => account.startsWith(e)),
        );
        return null;
      case 'ensureEnclaveKeyPair':
        ensureEnclaveCalls++;
        return true;
      case 'deleteEnclaveKey':
        deleteEnclaveCalls++;
        return null;
      default:
        return null;
    }
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late _MockKeychain mock;
  const channel = MethodChannel('keychain');

  setUp(() {
    mock = _MockKeychain();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, mock.handle);
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  DarwinOubliette storage([DarwinSecretAccess? access]) => DarwinOubliette(
    access:
        access ?? const DarwinSecretAccess.onlyUnlocked(secureEnclave: false),
  );

  group('round-trip & lifecycle', () {
    test('store then fetch returns the value', () async {
      final s = storage();
      await s.store('seed', Uint8List.fromList([1, 2, 3]));
      // Stored under the profile-prefixed account.
      expect(
        mock.items.containsKey(buildSlot('oubliette_only_unlocked_', 'seed')),
        true,
      );
      expect(await s.fetch('seed'), Uint8List.fromList([1, 2, 3]));
    });

    test('store throws StateError if the key already exists', () async {
      final s = storage();
      await s.store('k', Uint8List.fromList([9]));
      expect(
        () => s.store('k', Uint8List.fromList([8])),
        throwsA(isA<StateError>()),
      );
    });

    test('fetch returns null for an absent key', () async {
      expect(await storage().fetch('nope'), isNull);
    });

    test('exists tracks store and trash', () async {
      final s = storage();
      expect(await s.exists('k'), false);
      await s.store('k', Uint8List.fromList([1]));
      expect(await s.exists('k'), true);
      await s.trash('k');
      expect(await s.exists('k'), false);
    });
  });

  group('typed error mapping (Darwin): branch on recoverable', () {
    test(
      'se_decrypt_failed → DecryptionFailedException (not recoverable)',
      () async {
        final s = storage();
        mock.fetchErrorCode = 'se_decrypt_failed';
        await expectLater(
          s.fetch('k'),
          throwsA(
            isA<DecryptionFailedException>().having(
              (e) => e.recoverable,
              'recoverable',
              false,
            ),
          ),
        );
      },
    );

    test(
      'se_key_missing → KeyNotFoundException (not recoverable, no regen)',
      () async {
        // DARWIN-2: the SE read path is fetch-only and never regenerates a
        // missing key. A gone SE key (e.g. restore/migration carried the
        // ciphertext but not the non-exportable key) surfaces as a clean
        // KeyNotFound, not an opaque decrypt failure.
        final s = storage();
        mock.fetchErrorCode = 'se_key_missing';
        await expectLater(
          s.fetch('k'),
          throwsA(
            isA<KeyNotFoundException>().having(
              (e) => e.recoverable,
              'recoverable',
              false,
            ),
          ),
        );
      },
    );

    test(
      'interaction_not_allowed → AuthenticationFailedException (RECOVERABLE)',
      () async {
        // Device locked — must be recoverable so the caller retries when unlocked
        // rather than purging readable data.
        final s = storage();
        mock.fetchErrorCode = 'interaction_not_allowed';
        await expectLater(
          s.fetch('k'),
          throwsA(
            isA<AuthenticationFailedException>().having(
              (e) => e.recoverable,
              'recoverable',
              true,
            ),
          ),
        );
      },
    );

    test('auth_cancelled → AuthenticationFailedException(cancelled)', () async {
      final s = storage();
      mock.fetchErrorCode = 'auth_cancelled';
      await expectLater(
        s.fetch('k'),
        throwsA(
          isA<AuthenticationFailedException>().having(
            (e) => e.cancelled,
            'cancelled',
            true,
          ),
        ),
      );
    });

    test('auth_failed → AuthenticationFailedException (RECOVERABLE)', () async {
      // A failed (not cancelled) prompt must stay recoverable: the data is
      // intact, the user simply hasn't authenticated — never purge in response.
      final s = storage();
      mock.fetchErrorCode = 'auth_failed';
      await expectLater(
        s.fetch('k'),
        throwsA(
          isA<AuthenticationFailedException>()
              .having((e) => e.cancelled, 'cancelled', false)
              .having((e) => e.recoverable, 'recoverable', true),
        ),
      );
    });

    test(
      'se_key_fetch_failed → BackendUnavailableException (RECOVERABLE, never '
      'purge)',
      () async {
        // DARWIN: an SE key *fetch* that fails with an unexpected status (a
        // missing entitlement / keychain-domain hiccup) is environmental — the
        // key may well still exist. It must be recoverable and NEVER trigger the
        // data-destroying KeyNotFound remediation.
        final s = storage();
        mock.fetchErrorCode = 'se_key_fetch_failed';
        await expectLater(
          s.fetch('k'),
          throwsA(
            isA<BackendUnavailableException>().having(
              (e) => e.recoverable,
              'recoverable',
              true,
            ),
          ),
        );
      },
    );

    for (final code in [
      'se_key_gen_failed',
      'se_encrypt_failed',
      'access_control_failed',
      // A code-signing / keychain-access-groups entitlement defect: a
      // build/signing fault, NOT a data fault. The native keychain plugin
      // emits this (errSecMissingEntitlement); oubliette must map it so a
      // caller never sees a raw PlatformException it might answer with purge().
      'missing_entitlement',
      // A plain-keychain fetch that failed with an unexpected OSStatus
      // (locked keychain / entitlement / transient framework error).
      'sec_item_copy_failed',
    ]) {
      test('$code → BackendUnavailableException (RECOVERABLE, never purge)', () async {
        // DARWIN: write-path SE failures (key gen, ECIES encrypt, access-control
        // creation), an entitlement/build defect (missing_entitlement), or a
        // generic fetch failure (sec_item_copy_failed) are environmental — the
        // stored data is intact / the secret was never written, nothing is
        // lost. They must be recoverable and NEVER map to the data-destroying
        // KeyNotFound remediation.
        final s = storage();
        mock.fetchErrorCode = code;
        await expectLater(
          s.fetch('k'),
          throwsA(
            isA<BackendUnavailableException>().having(
              (e) => e.recoverable,
              'recoverable',
              true,
            ),
          ),
        );
      });
    }

    test('trash surfaces interaction_not_allowed as a typed error', () async {
      // DARWIN: a delete on a locked Data Protection keychain fails with
      // interaction_not_allowed; trash() routes through _mapError so the caller
      // sees a recoverable AuthenticationFailedException, never a raw
      // PlatformException it might treat as fatal (and purge in response).
      final s = storage();
      await s.store('k', Uint8List.fromList([1]));
      mock.fetchErrorCode = 'interaction_not_allowed';
      await expectLater(
        s.trash('k'),
        throwsA(isA<AuthenticationFailedException>()),
      );
    });

    test('store rejects a key containing the slot separator', () async {
      await expectLater(
        storage().store('a${slotSeparator}b', Uint8List.fromList([1])),
        throwsA(isA<ArgumentError>()),
      );
    });
  });

  group('Darwin format version envelope (H2)', () {
    test('store prepends the frozen v1 format header', () async {
      final s = storage();
      await s.store('k', Uint8List.fromList([7, 8, 9]));
      final raw = mock.items[buildSlot('oubliette_only_unlocked_', 'k')]!;
      expect(raw.first, 1, reason: 'frozen 1-byte Darwin format header');
      expect(raw.sublist(1), Uint8List.fromList([7, 8, 9]));
      expect(
        await s.fetch('k'),
        Uint8List.fromList([7, 8, 9]),
        reason: 'round-trip strips the header',
      );
    });

    test('fetch rejects a blob written by an unknown future format', () async {
      final s = storage();
      mock.items[buildSlot('oubliette_only_unlocked_', 'k')] =
          Uint8List.fromList([99, 7, 8, 9]);
      await expectLater(s.fetch('k'), throwsA(isA<PayloadCorruptException>()));
    });

    test('fetch rejects an empty blob', () async {
      final s = storage();
      mock.items[buildSlot('oubliette_only_unlocked_', 'k')] = Uint8List(0);
      await expectLater(s.fetch('k'), throwsA(isA<PayloadCorruptException>()));
    });
  });

  group('per-key store lock', () {
    test(
      'two concurrent stores of the same absent key: exactly one wins',
      () async {
        final s = storage();
        final results = await Future.wait([
          s
              .store('race', Uint8List.fromList([1]))
              .then((_) => 'ok')
              .catchError((_) => 'err'),
          s
              .store('race', Uint8List.fromList([2]))
              .then((_) => 'ok')
              .catchError((_) => 'err'),
        ]);
        expect(results.where((r) => r == 'ok').length, 1);
      },
    );

    test('different keys store concurrently', () async {
      final s = storage();
      await Future.wait([
        s.store('a', Uint8List.fromList([1])),
        s.store('b', Uint8List.fromList([2])),
      ]);
      expect(await s.fetch('a'), Uint8List.fromList([1]));
      expect(await s.fetch('b'), Uint8List.fromList([2]));
    });
  });

  group('Secure Enclave key gating', () {
    test(
      'non-SE profile never asks the native layer to ensure an SE key',
      () async {
        final s = storage(
          const DarwinSecretAccess.onlyUnlocked(secureEnclave: false),
        );
        await s.store('k', Uint8List.fromList([1]));
        await s.init();
        expect(mock.ensureEnclaveCalls, 0);
      },
    );

    test('SE profile ensures the SE key on store', () async {
      final s = storage(
        const DarwinSecretAccess.onlyUnlocked(secureEnclave: true),
      );
      await s.store('k', Uint8List.fromList([1]));
      expect(mock.ensureEnclaveCalls, greaterThanOrEqualTo(1));
    });
  });

  group('purge (whole-profile destroy)', () {
    test('removes every item in the profile by prefix', () async {
      final s = storage();
      await s.store('a', Uint8List.fromList([1]));
      await s.store('b', Uint8List.fromList([2]));

      await s.purge();

      expect(await s.exists('a'), isFalse);
      expect(await s.exists('b'), isFalse);
    });

    test(
      'only wipes its own prefix, leaving sibling profiles intact',
      () async {
        final only = storage(); // onlyUnlocked
        final even = DarwinOubliette(
          access: const DarwinSecretAccess.evenLocked(secureEnclave: false),
        );
        await only.store('k', Uint8List.fromList([1]));
        await even.store('k', Uint8List.fromList([2]));

        await only.purge();

        expect(await only.exists('k'), isFalse);
        expect(
          await even.exists('k'),
          isTrue,
          reason: 'sibling profile must be untouched',
        );
      },
    );

    test(
      'purging authenticated does NOT wipe authenticatedFatal (nested prefix)',
      () async {
        // Regression: `oubliette_authenticated_` is a prefix of
        // `oubliette_authenticated_fatal_`. A naive startsWith wipe would destroy
        // the fatal profile's data when purging the authenticated profile.
        final auth = DarwinOubliette(
          access: const DarwinSecretAccess.authenticated(
            promptReason: 'r',
            secureEnclave: false,
          ),
        );
        final fatal = DarwinOubliette(
          access: const DarwinSecretAccess.authenticatedFatal(
            promptReason: 'r',
            secureEnclave: false,
          ),
        );
        await auth.store('k', Uint8List.fromList([1]));
        await fatal.store('k', Uint8List.fromList([2]));

        await auth.purge();

        expect(await auth.exists('k'), isFalse);
        expect(
          await fatal.exists('k'),
          isTrue,
          reason: 'authenticatedFatal data must survive authenticated.purge()',
        );
      },
    );

    test(
      'purging a custom profile does NOT wipe a nested custom sibling',
      () async {
        // Two *custom* profiles where one prefix nests under the other
        // (`app_` ⊂ `app_admin_`) — the case the constructor cannot catch. The
        // slot separator makes account ownership exact, so the sibling survives.
        DarwinOubliette custom(String prefix) => DarwinOubliette(
          access: DarwinSecretAccess.custom(
            prefix: prefix,
            service: null,
            accessibility: KeychainAccessibility.whenUnlockedThisDeviceOnly,
            useDataProtection: false,
            authenticationRequired: false,
            biometryCurrentSetOnly: false,
            authenticationPrompt: null,
            secureEnclave: false,
            accessGroup: null,
          ),
        );
        final app = custom('app_');
        final admin = custom('app_admin_');
        await app.store('k', Uint8List.fromList([1]));
        await admin.store('k', Uint8List.fromList([2]));

        await app.purge();

        expect(await app.exists('k'), isFalse);
        expect(
          await admin.exists('k'),
          isTrue,
          reason: 'nested custom sibling account must survive',
        );
      },
    );

    test('retains the shared Secure Enclave key (never deletes it)', () async {
      // The SE key is scoped by (service, accessibility, accessGroup), not the
      // prefix, so it can be shared across profiles. purge must never delete it
      // or it could brick a sibling profile.
      final s = storage(
        const DarwinSecretAccess.onlyUnlocked(secureEnclave: true),
      );
      await s.store('k', Uint8List.fromList([1]));
      await s.purge();
      expect(
        mock.deleteEnclaveCalls,
        0,
        reason: 'SE key is shared by scoping and must survive purge',
      );
    });
  });
}
