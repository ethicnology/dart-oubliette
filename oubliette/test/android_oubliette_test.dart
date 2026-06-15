import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:keystore/keystore.dart';
import 'package:oubliette/android_oubliette.dart';
import 'package:oubliette/oubliette.dart';
import 'package:oubliette/src/slot.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// A stateful in-memory stand-in for the native `keystore` MethodChannel.
///
/// `encrypt` echoes the plaintext as ciphertext and `decrypt` returns it, so
/// values round-trip. `generateKey` throws `already_exists` on a second call
/// for the same alias, mirroring the native `IllegalStateException` mapping —
/// this is what exercises the idempotency / concurrency paths.
class _MockKeystore {
  final Set<String> aliases = {};
  final List<Map<String, dynamic>> decryptCalls = [];
  int generateKeyCalls = 0;
  int deleteEntryCalls = 0;

  /// When true, encrypt/authenticateEncrypt throw `key_invalidated` (as the
  /// native layer does for a permanently invalidated key). Cleared on
  /// deleteEntry, mirroring real recovery.
  bool encryptInvalidated = false;

  /// When true, decrypt/authenticateDecrypt throw `key_invalidated`.
  bool decryptInvalidated = false;

  /// When set, decrypt/authenticateDecrypt throw a PlatformException with this
  /// code — exercises the typed-error mapping (M3).
  String? decryptErrorCode;

  Future<Object?> handle(MethodCall call) async {
    final args = (call.arguments as Map).cast<String, dynamic>();
    switch (call.method) {
      case 'containsAlias':
        return aliases.contains(args['alias']);
      case 'generateKey':
        generateKeyCalls++;
        final alias = args['alias'] as String;
        if (aliases.contains(alias)) {
          throw PlatformException(code: 'already_exists', message: 'exists');
        }
        aliases.add(alias);
        return null;
      case 'deleteEntry':
        deleteEntryCalls++;
        aliases.remove(args['alias']);
        encryptInvalidated = false;
        return null;
      case 'encrypt':
      case 'authenticateEncrypt':
        if (encryptInvalidated) {
          throw PlatformException(code: 'key_invalidated', message: 'dead');
        }
        final pt = args['plaintext'] as Uint8List;
        return <String, dynamic>{
          'version': 1,
          'nonce': Uint8List.fromList(List.filled(12, 7)),
          'ciphertext': Uint8List.fromList(pt),
        };
      case 'decrypt':
      case 'authenticateDecrypt':
        if (decryptErrorCode != null) {
          throw PlatformException(code: decryptErrorCode!, message: 'forced');
        }
        if (decryptInvalidated) {
          throw PlatformException(code: 'key_invalidated', message: 'dead');
        }
        decryptCalls.add(args);
        return args['ciphertext'] as Uint8List;
      default:
        return null;
    }
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late _MockKeystore mock;
  const channel = MethodChannel('keystore');

  setUp(() {
    SharedPreferences.setMockInitialValues({});
    mock = _MockKeystore();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, mock.handle);
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  AndroidOubliette storage([AndroidSecretAccess? access]) => AndroidOubliette(
    access:
        access ??
        const AndroidSecretAccess.onlyUnlocked(
          strongBox: false,
          requireHardwareBacking: false,
        ),
  );

  group('round-trip & lazy key-ensure', () {
    test('store generates the key lazily, then fetch returns it', () async {
      final s = storage();
      expect(mock.aliases, isEmpty);

      await s.store('seed', Uint8List.fromList([1, 2, 3]));
      expect(
        mock.aliases,
        contains('oubliette_only_unlocked'),
        reason: 'store() must lazily generate the key (N6)',
      );

      final out = await s.fetch('seed');
      expect(out, equals(Uint8List.fromList([1, 2, 3])));
    });

    test('store throws if key already exists', () async {
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
  });

  group('slot separator is reserved', () {
    test('store rejects a key containing the slot separator', () async {
      await expectLater(
        storage().store('a${slotSeparator}b', Uint8List.fromList([1])),
        throwsA(isA<ArgumentError>()),
        reason: 'a separator in the key could forge another profile\'s slot',
      );
    });

    test(
      'store rejects a separator-containing prefix from a named ctor',
      () async {
        // Named ctors are const and skip validateSlotPrefix; buildSlot must still
        // reject a separator smuggled in via a `prefix:` override.
        final s = AndroidOubliette(
          access: AndroidSecretAccess.onlyUnlocked(
            prefix: 'bad${slotSeparator}_',
            strongBox: false,
            requireHardwareBacking: false,
          ),
        );
        await expectLater(
          s.store('k', Uint8List.fromList([1])),
          throwsA(isA<ArgumentError>()),
        );
      },
    );
  });

  group('decrypt trust boundary (#5 / M1)', () {
    test(
      'fetch decrypts with the slot-derived aad and alias, not the blob',
      () async {
        final s = storage();
        await s.store('k', Uint8List.fromList([4, 5, 6]));
        await s.fetch('k');

        expect(mock.decryptCalls, hasLength(1));
        final call = mock.decryptCalls.single;
        expect(
          call['aad'],
          buildSlot('oubliette_only_unlocked_', 'k'),
          reason: 'aad must be recomputed from prefix + separator + key',
        );
        expect(
          call['alias'],
          'oubliette_only_unlocked',
          reason: 'alias must come from the live profile',
        );
      },
    );

    test('fetch does not regenerate a key when the alias was cleared', () async {
      // Regression: fetch must not call _ensureKey. If the keystore was cleared
      // but the blob remains, regenerating would mint a useless key and mask the
      // real key_not_found behind a GCM decrypt_failed.
      final s = storage();
      await s.store('k', Uint8List.fromList([1]));
      mock.aliases.clear(); // simulate keystore cleared, blob still on disk
      final before = mock.generateKeyCalls;
      await s.fetch('k');
      expect(
        mock.aliases.contains('oubliette_only_unlocked'),
        isFalse,
        reason: 'fetch must not mint a key when the alias is gone',
      );
      expect(mock.generateKeyCalls, before);
    });

    test('fetch throws PayloadTamperException on a relocated aad', () async {
      final s = storage();
      await s.store('k', Uint8List.fromList([1]));

      // Forge a blob whose aad/alias point at a different (weaker) slot.
      final tampered = EncryptedPayload(
        version: 1,
        nonce: Uint8List.fromList(List.filled(12, 0)),
        ciphertext: Uint8List.fromList([1]),
        aad: buildSlot('oubliette_even_locked_', 'k'),
        keyAlias: 'oubliette_even_locked',
      );
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(
        buildSlot('oubliette_only_unlocked_', 'k'),
        tampered.toJson(),
      );

      expect(() => s.fetch('k'), throwsA(isA<PayloadTamperException>()));
    });
  });

  group('key invalidation is surfaced, never auto-resolved', () {
    test('store rethrows key_invalidated and NEVER deletes the key', () async {
      final s = storage(
        const AndroidSecretAccess.authenticatedFatal(
          strongBox: false,
          requireHardwareBacking: false,
          promptTitle: 't',
          promptSubtitle: 's',
        ),
      );
      // Simulate an existing-but-invalidated profile key (enrollment changed):
      // the alias is present, but encrypt throws key_invalidated.
      mock.aliases.add('oubliette_authenticated_fatal');
      mock.encryptInvalidated = true;

      // The error must surface to the caller as a typed KeyInvalidatedException
      // — destroying key material (and the data under it) is the developer's
      // explicit decision, never ours.
      await expectLater(
        s.store('k', Uint8List.fromList([1, 2, 3])),
        throwsA(
          isA<KeyInvalidatedException>().having(
            (e) => e.keyAlias,
            'keyAlias',
            'oubliette_authenticated_fatal',
          ),
        ),
      );
      expect(
        mock.deleteEntryCalls,
        0,
        reason: 'the library must never delete a key on the user\'s behalf',
      );
      expect(
        mock.aliases.contains('oubliette_authenticated_fatal'),
        isTrue,
        reason: 'the (dead) key is left intact for the developer to handle',
      );
    });

    test('fetch surfaces key_invalidated as KeyInvalidatedException', () async {
      final s = storage();
      await s.store('k', Uint8List.fromList([1, 2, 3]));
      // The profile key dies after the blob was written (e.g. lock screen reset).
      mock.decryptInvalidated = true;
      await expectLater(
        s.fetch('k'),
        throwsA(
          isA<KeyInvalidatedException>().having(
            (e) => e.keyAlias,
            'keyAlias',
            'oubliette_only_unlocked',
          ),
        ),
      );
    });
  });

  group('typed error mapping (M3): branch on recoverable, never mis-purge', () {
    Future<AndroidOubliette> seeded() async {
      final s = storage();
      await s.store('k', Uint8List.fromList([1]));
      return s;
    }

    test(
      'decrypt_failed → DecryptionFailedException (not recoverable)',
      () async {
        final s = await seeded();
        mock.decryptErrorCode = 'decrypt_failed';
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

    test('key_not_found → KeyNotFoundException (not recoverable)', () async {
      final s = await seeded();
      mock.decryptErrorCode = 'key_not_found';
      await expectLater(
        s.fetch('k'),
        throwsA(
          isA<KeyNotFoundException>()
              .having((e) => e.keyAlias, 'keyAlias', 'oubliette_only_unlocked')
              .having((e) => e.recoverable, 'recoverable', false),
        ),
      );
    });

    test('auth_failed → AuthenticationFailedException (RECOVERABLE)', () async {
      // The safety-critical case: a failed auth must NOT look fatal, or a caller
      // might purge() readable data the user simply hasn\'t authenticated for.
      final s = await seeded();
      mock.decryptErrorCode = 'auth_failed';
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
    });

    test(
      'auth_error → AuthenticationFailedException (the code Android emits)',
      () async {
        // BiometricAuth.kt emits `auth_error`, not `auth_failed`; both must map.
        final s = await seeded();
        mock.decryptErrorCode = 'auth_error';
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

    test(
      'key_auth_type_unknown → AuthenticationFailedException (RECOVERABLE)',
      () async {
        // The native layer fails closed (before any prompt) when it cannot read
        // the key\'s allowed-authenticator set from KeyInfo. The key and data are
        // intact, so it must map to a recoverable auth failure, never anything a
        // caller might answer with purge().
        final s = await seeded();
        mock.decryptErrorCode = 'key_auth_type_unknown';
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

    test('a malformed on-disk blob → PayloadCorruptException', () async {
      final s = await seeded();
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(
        buildSlot('oubliette_only_unlocked_', 'k'),
        'not valid json',
      );
      await expectLater(s.fetch('k'), throwsA(isA<PayloadCorruptException>()));
    });
  });

  group('idempotent init (N2)', () {
    test('two concurrent init() calls both resolve without throwing', () async {
      final s = storage();
      await Future.wait([s.init(), s.init()]);
      expect(mock.aliases, contains('oubliette_only_unlocked'));
    });

    test('init is a no-op when the key already exists', () async {
      final s = storage();
      await s.init();
      final callsAfterFirst = mock.generateKeyCalls;
      await s.init();
      expect(
        mock.generateKeyCalls,
        callsAfterFirst,
        reason: 'second init must not regenerate',
      );
    });
  });

  group('per-key store lock (A4)', () {
    test(
      'two concurrent stores of the same absent key: exactly one wins',
      () async {
        final s = storage();
        final results = await Future.wait([
          s
              .store('race', Uint8List.fromList([1]))
              .then((_) => 'ok')
              .catchError((e) => 'err:$e'),
          s
              .store('race', Uint8List.fromList([2]))
              .then((_) => 'ok')
              .catchError((e) => 'err:$e'),
        ]);
        final oks = results.where((r) => r == 'ok').length;
        expect(
          oks,
          1,
          reason: 'exactly one concurrent first-write may succeed',
        );
      },
    );

    test(
      'two SEPARATE instances racing the same slot: exactly one wins',
      () async {
        // Regression: _locks must be static + slot-keyed so the "already exists"
        // guarantee holds across instances, not just within one (SharedPreferences
        // has no fail-closed put-if-absent like Darwin's secItemAdd).
        final a = storage();
        final b = storage();
        final results = await Future.wait([
          a
              .store('shared', Uint8List.fromList([1]))
              .then((_) => 'ok')
              .catchError((_) => 'err'),
          b
              .store('shared', Uint8List.fromList([2]))
              .then((_) => 'ok')
              .catchError((_) => 'err'),
        ]);
        expect(
          results.where((r) => r == 'ok').length,
          1,
          reason: 'static slot lock must serialize stores across instances',
        );
      },
    );

    test('different keys store concurrently without interference', () async {
      final s = storage();
      await Future.wait([
        s.store('a', Uint8List.fromList([1])),
        s.store('b', Uint8List.fromList([2])),
      ]);
      expect(await s.fetch('a'), equals(Uint8List.fromList([1])));
      expect(await s.fetch('b'), equals(Uint8List.fromList([2])));
    });
  });

  group('purge (whole-profile destroy)', () {
    test('removes every blob in the profile and deletes the key', () async {
      final s = storage();
      await s.store('a', Uint8List.fromList([1]));
      await s.store('b', Uint8List.fromList([2]));
      expect(mock.aliases, contains('oubliette_only_unlocked'));

      await s.purge();

      expect(await s.exists('a'), isFalse);
      expect(await s.exists('b'), isFalse);
      expect(
        mock.aliases,
        isEmpty,
        reason: 'the shared profile key is deleted',
      );
      expect(mock.deleteEntryCalls, 1);
    });

    test(
      'only wipes its own prefix, leaving sibling profiles intact',
      () async {
        final only = storage(); // onlyUnlocked
        final even = AndroidOubliette(
          access: const AndroidSecretAccess.evenLocked(
            strongBox: false,
            requireHardwareBacking: false,
          ),
        );
        await only.store('k', Uint8List.fromList([1]));
        await even.store('k', Uint8List.fromList([2]));

        await only.purge();

        expect(await only.exists('k'), isFalse);
        expect(
          await even.exists('k'),
          isTrue,
          reason: 'sibling profile slot must be untouched',
        );
        expect(
          mock.aliases,
          contains('oubliette_even_locked'),
          reason: 'sibling profile key must survive',
        );
      },
    );

    test(
      'purging authenticated does NOT wipe authenticatedFatal (nested prefix)',
      () async {
        // Regression: `oubliette_authenticated_` is a prefix of
        // `oubliette_authenticated_fatal_`; a naive startsWith wipe would destroy
        // the fatal profile's blobs (and the fatal key is distinct, so its data
        // would be silently lost) when purging the authenticated profile.
        final auth = AndroidOubliette(
          access: const AndroidSecretAccess.authenticated(
            strongBox: false,
            requireHardwareBacking: false,
            promptTitle: 't',
            promptSubtitle: 's',
          ),
        );
        final fatal = AndroidOubliette(
          access: const AndroidSecretAccess.authenticatedFatal(
            strongBox: false,
            requireHardwareBacking: false,
            promptTitle: 't',
            promptSubtitle: 's',
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
        expect(
          mock.aliases.contains('oubliette_authenticated_fatal'),
          isTrue,
          reason: 'the fatal profile key must survive',
        );
      },
    );

    test(
      'purging a custom profile does NOT wipe a nested custom sibling',
      () async {
        // The case the constructor cannot catch: two *custom* profiles where one
        // prefix nests under the other (`app_` ⊂ `app_admin_`). Before the slot
        // separator, purge('app_') wiped `app_admin_*` — silent data loss. The
        // separator makes ownership exact, so the sibling survives.
        AndroidOubliette custom(String prefix, String alias) =>
            AndroidOubliette(
              access: AndroidSecretAccess.custom(
                prefix: prefix,
                keyAlias: alias,
                strongBox: false,
                requireHardwareBacking: false,
                unlockedDeviceRequired: true,
                invalidatedByBiometricEnrollment: false,
                promptTitle: null,
                promptSubtitle: null,
              ),
            );
        final app = custom('app_', 'app_key');
        final admin = custom('app_admin_', 'app_admin_key');
        await app.store('k', Uint8List.fromList([1]));
        await admin.store('k', Uint8List.fromList([2]));

        await app.purge();

        expect(await app.exists('k'), isFalse);
        expect(
          await admin.exists('k'),
          isTrue,
          reason: 'nested custom sibling data must survive',
        );
        expect(
          mock.aliases.contains('app_admin_key'),
          isTrue,
          reason: 'nested custom sibling key must survive',
        );
      },
    );

    test('unbricks a profile: purge then init mints a fresh key', () async {
      final s = storage();
      await s.store('k', Uint8List.fromList([1]));
      await s.purge();
      expect(mock.aliases, isEmpty);

      await s.init();
      expect(
        mock.aliases,
        contains('oubliette_only_unlocked'),
        reason: 'init after purge regenerates the key',
      );
    });
  });
}
