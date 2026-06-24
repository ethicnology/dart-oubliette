import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:oubliette/linux_oubliette.dart';
import 'package:oubliette/oubliette.dart';
import 'package:oubliette/src/slot.dart';

/// In-memory stand-in for the native `secret_service` MethodChannel. Keys items
/// by the full slot (`prefix + U+001D + key`) so per-slot isolation and
/// round-trips behave like the real Secret Service. `write` rejects duplicates
/// with `already_exists`. Stores the base64 string the facade sends.
class _MockSecretService {
  final Map<String, String> items = {};

  /// When set, the next operation throws a PlatformException with this code —
  /// exercises the Linux typed-error mapping.
  String? errorCode;

  Future<Object?> handle(MethodCall call) async {
    if (errorCode != null) {
      throw PlatformException(code: errorCode!, message: 'forced');
    }
    final args = (call.arguments as Map).cast<String, dynamic>();
    switch (call.method) {
      case 'contains':
        return items.containsKey(args['slot']);
      case 'write':
        final slot = args['slot'] as String;
        if (items.containsKey(slot)) {
          throw PlatformException(code: 'already_exists', message: 'dup');
        }
        items[slot] = args['value'] as String;
        return null;
      case 'read':
        return items[args['slot'] as String];
      case 'delete':
        items.remove(args['slot']);
        return null;
      case 'deleteByPrefix':
        final prefix = args['prefix'] as String;
        items.removeWhere((slot, _) => slot.startsWith(prefix));
        return null;
      case 'listByPrefix':
        // Error injection is handled at the top of `handle` via `errorCode`.
        final prefix = args['prefix'] as String;
        return items.keys.where((slot) => slot.startsWith(prefix)).toList();
      default:
        return null;
    }
  }

  /// Raw stored bytes for [slot] (base64-decoded), or null.
  Uint8List? raw(String slot) {
    final v = items[slot];
    return v == null ? null : base64Decode(v);
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late _MockSecretService mock;
  const channel = MethodChannel('secret_service');

  setUp(() {
    mock = _MockSecretService();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, mock.handle);
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  LinuxOubliette storage([LinuxSecretAccess? access]) =>
      LinuxOubliette(access: access ?? const LinuxSecretAccess.onlyUnlocked());

  group('round-trip & lifecycle', () {
    test('store then fetch returns the value', () async {
      final s = storage();
      await s.store('seed', Uint8List.fromList([1, 2, 3]));
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

    test('init probes the backend without throwing when reachable', () async {
      await storage().init();
    });
  });

  group('Linux format version envelope', () {
    test('store prepends the frozen v1 format header', () async {
      final s = storage();
      await s.store('k', Uint8List.fromList([7, 8, 9]));
      final raw = mock.raw(buildSlot('oubliette_only_unlocked_', 'k'))!;
      expect(raw.first, 1, reason: 'frozen 1-byte Linux format header');
      expect(raw.sublist(1), Uint8List.fromList([7, 8, 9]));
      expect(
        await s.fetch('k'),
        Uint8List.fromList([7, 8, 9]),
        reason: 'round-trip strips the header',
      );
    });

    test('fetch rejects a blob written by an unknown future format', () async {
      final s = storage();
      mock.items[buildSlot('oubliette_only_unlocked_', 'k')] = base64Encode(
        Uint8List.fromList([99, 7, 8, 9]),
      );
      await expectLater(s.fetch('k'), throwsA(isA<PayloadCorruptException>()));
    });

    test('fetch rejects an empty blob', () async {
      final s = storage();
      mock.items[buildSlot('oubliette_only_unlocked_', 'k')] = base64Encode(
        Uint8List(0),
      );
      await expectLater(s.fetch('k'), throwsA(isA<PayloadCorruptException>()));
    });
  });

  group('typed error mapping (Linux): branch on recoverable', () {
    test(
      'backend_unavailable → BackendUnavailableException (recoverable)',
      () async {
        final s = storage();
        mock.errorCode = 'backend_unavailable';
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

    test('keyring_locked → KeyringLockedException (recoverable)', () async {
      final s = storage();
      mock.errorCode = 'keyring_locked';
      await expectLater(
        s.fetch('k'),
        throwsA(
          isA<KeyringLockedException>().having(
            (e) => e.recoverable,
            'recoverable',
            true,
          ),
        ),
      );
    });

    test(
      'keyring_timeout → BackendUnavailableException (recoverable)',
      () async {
        // The per-op watchdog cancelled the call (the keyring did not respond in
        // the bounded window). Transient/environmental like any backend stall:
        // recoverable, retry, never purge.
        final s = storage();
        mock.errorCode = 'keyring_timeout';
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

    test('auth_cancelled → AuthenticationFailedException(cancelled)', () async {
      final s = storage();
      mock.errorCode = 'auth_cancelled';
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

    test('store rejects a key containing the slot separator', () async {
      await expectLater(
        storage().store('a${slotSeparator}b', Uint8List.fromList([1])),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('trash on a locked keyring throws (never a silent no-op)', () async {
      final s = storage();
      mock.errorCode = 'keyring_locked';
      await expectLater(s.trash('k'), throwsA(isA<KeyringLockedException>()));
    });

    test(
      'trash on an unreachable backend throws (never a silent no-op)',
      () async {
        // A delete against a missing keyring daemon / session bus must surface
        // the recoverable BackendUnavailableException, not silently succeed and
        // let the caller believe the secret was removed.
        final s = storage();
        mock.errorCode = 'backend_unavailable';
        await expectLater(
          s.trash('k'),
          throwsA(isA<BackendUnavailableException>()),
        );
      },
    );

    test(
      'init surfaces a locked keyring as a typed error (fail fast)',
      () async {
        // init() probes the backend so a locked/headless environment fails here
        // with a typed, recoverable error rather than on the first store/fetch.
        final s = storage();
        mock.errorCode = 'keyring_locked';
        await expectLater(s.init(), throwsA(isA<KeyringLockedException>()));
      },
    );
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
        final even = LinuxOubliette(
          access: const LinuxSecretAccess.evenLocked(),
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
      'purging a custom profile does NOT wipe a nested custom sibling',
      () async {
        // `app_` nests under `app_admin_`; the U+001D separator makes slot
        // ownership exact, so the sibling survives.
        LinuxOubliette custom(String prefix) =>
            LinuxOubliette(access: LinuxSecretAccess.custom(prefix: prefix));
        final app = custom('app_');
        final admin = custom('app_admin_');
        await app.store('k', Uint8List.fromList([1]));
        await admin.store('k', Uint8List.fromList([2]));
        await app.purge();
        expect(await app.exists('k'), isFalse);
        expect(
          await admin.exists('k'),
          isTrue,
          reason: 'nested custom sibling slot must survive',
        );
      },
    );
  });

  group('keys (enumerate stored keys)', () {
    test('empty profile returns an empty list', () async {
      expect(await storage().keys(), isEmpty);
    });

    test('returns the LOGICAL keys, prefix + separator stripped', () async {
      final s = storage();
      await s.store('alpha', Uint8List.fromList([1]));
      await s.store('beta', Uint8List.fromList([2]));
      expect((await s.keys())..sort(), ['alpha', 'beta']);
    });

    test('shrinks after trash', () async {
      final s = storage();
      await s.store('a', Uint8List.fromList([1]));
      await s.store('b', Uint8List.fromList([2]));
      await s.trash('a');
      expect(await s.keys(), ['b']);
    });

    test('empty after purge', () async {
      final s = storage();
      await s.store('a', Uint8List.fromList([1]));
      await s.purge();
      expect(await s.keys(), isEmpty);
    });

    test('excludes sibling-profile keys (prefix isolation)', () async {
      final only = storage(); // onlyUnlocked
      final even = LinuxOubliette(access: const LinuxSecretAccess.evenLocked());
      await only.store('mine', Uint8List.fromList([1]));
      await even.store('theirs', Uint8List.fromList([2]));
      expect(await only.keys(), ['mine']);
      expect(await even.keys(), ['theirs']);
    });

    test(
      'a locked/unavailable keyring surfaces as a typed exception',
      () async {
        final s = storage();
        mock.errorCode = 'keyring_locked';
        await expectLater(s.keys(), throwsA(isA<KeyringLockedException>()));
      },
    );
  });

  group('LinuxSecretAccess validation', () {
    test('custom rejects a reserved profile prefix', () {
      expect(
        () => LinuxSecretAccess.custom(prefix: 'oubliette_only_unlocked_'),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('custom rejects a prefix nesting a reserved one', () {
      // `oubliette_authenticated_` is a reserved prefix; a nesting custom
      // prefix is rejected conservatively.
      expect(
        () => LinuxSecretAccess.custom(prefix: 'oubliette_'),
        throwsA(isA<ArgumentError>()),
      );
    });

    test('custom rejects a prefix containing the slot separator', () {
      expect(
        () => LinuxSecretAccess.custom(prefix: 'a${slotSeparator}b'),
        throwsA(isA<ArgumentError>()),
      );
    });
  });
}
