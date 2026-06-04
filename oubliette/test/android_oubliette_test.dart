import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:keystore/keystore.dart';
import 'package:oubliette/android_oubliette.dart';
import 'package:oubliette/oubliette.dart';
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
      case 'encrypt':
        final pt = args['plaintext'] as Uint8List;
        return <String, dynamic>{
          'version': 1,
          'nonce': Uint8List.fromList(List.filled(12, 7)),
          'ciphertext': Uint8List.fromList(pt),
        };
      case 'decrypt':
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
        access: access ??
            const AndroidSecretAccess.onlyUnlocked(strongBox: false),
      );

  group('round-trip & lazy key-ensure', () {
    test('store generates the key lazily, then fetch returns it', () async {
      final s = storage();
      expect(mock.aliases, isEmpty);

      await s.store('seed', Uint8List.fromList([1, 2, 3]));
      expect(mock.aliases, contains('oubliette_only_unlocked'),
          reason: 'store() must lazily generate the key (N6)');

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

  group('decrypt trust boundary (#5 / M1)', () {
    test('fetch decrypts with the slot-derived aad and alias, not the blob',
        () async {
      final s = storage();
      await s.store('k', Uint8List.fromList([4, 5, 6]));
      await s.fetch('k');

      expect(mock.decryptCalls, hasLength(1));
      final call = mock.decryptCalls.single;
      expect(call['aad'], 'oubliette_only_unlocked_k',
          reason: 'aad must be recomputed from prefix+key');
      expect(call['alias'], 'oubliette_only_unlocked',
          reason: 'alias must come from the live profile');
    });

    test('fetch throws PayloadTamperException on a relocated aad', () async {
      final s = storage();
      await s.store('k', Uint8List.fromList([1]));

      // Forge a blob whose aad/alias point at a different (weaker) slot.
      final tampered = EncryptedPayload(
        version: 1,
        nonce: Uint8List.fromList(List.filled(12, 0)),
        ciphertext: Uint8List.fromList([1]),
        aad: 'oubliette_even_locked_k',
        keyAlias: 'oubliette_even_locked',
      );
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString('oubliette_only_unlocked_k', tampered.toJson());

      expect(
        () => s.fetch('k'),
        throwsA(isA<PayloadTamperException>()),
      );
    });
  });

  group('idempotent init (N2)', () {
    test('two concurrent init() calls both resolve without throwing',
        () async {
      final s = storage();
      await Future.wait([s.init(), s.init()]);
      expect(mock.aliases, contains('oubliette_only_unlocked'));
    });

    test('init is a no-op when the key already exists', () async {
      final s = storage();
      await s.init();
      final callsAfterFirst = mock.generateKeyCalls;
      await s.init();
      expect(mock.generateKeyCalls, callsAfterFirst,
          reason: 'second init must not regenerate');
    });
  });

  group('per-key store lock (A4)', () {
    test('two concurrent stores of the same absent key: exactly one wins',
        () async {
      final s = storage();
      final results = await Future.wait([
        s.store('race', Uint8List.fromList([1])).then((_) => 'ok').catchError((e) => 'err:$e'),
        s.store('race', Uint8List.fromList([2])).then((_) => 'ok').catchError((e) => 'err:$e'),
      ]);
      final oks = results.where((r) => r == 'ok').length;
      expect(oks, 1, reason: 'exactly one concurrent first-write may succeed');
    });

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
}
