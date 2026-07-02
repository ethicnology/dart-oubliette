import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:keystore/keystore.dart';

/// The facade picks the native method by whether a prompt was supplied:
/// a prompt MUST route to the authenticating channel method, never the plain
/// one — otherwise a profile that asked for per-use auth would silently skip
/// it. Also covers the null/invalid-response error mapping.
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  const channel = MethodChannel('keystore');
  String? lastMethod;
  Map<Object?, Object?>? lastArgs;
  late Object? Function(MethodCall) responder;

  setUp(() {
    lastMethod = null;
    lastArgs = null;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          lastMethod = call.method;
          lastArgs = call.arguments as Map<Object?, Object?>?;
          return responder(call);
        });
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  final ks = Keystore();
  final plaintext = Uint8List.fromList([1, 2, 3]);

  Map<String, Object?> validEncryptResponse() => {
    'version': 1,
    'nonce': Uint8List.fromList(List.filled(12, 0)),
    'ciphertext': Uint8List.fromList([9, 9, 9]),
  };

  group('encrypt method routing', () {
    test('routes to authenticateEncrypt when a promptTitle is given', () async {
      responder = (_) => validEncryptResponse();
      await ks.encrypt(
        alias: 'a',
        plaintext: plaintext,
        aad: 'aad',
        promptTitle: 'Unlock',
      );
      expect(lastMethod, 'authenticateEncrypt');
    });

    test('routes to plain encrypt when no promptTitle', () async {
      responder = (_) => validEncryptResponse();
      await ks.encrypt(alias: 'a', plaintext: plaintext, aad: 'aad');
      expect(lastMethod, 'encrypt');
    });

    // No prompt means no auth metadata leaks onto the plain encrypt call. The
    // authenticator set is fixed by the key's KeyInfo, never passed by the
    // caller (the advisory biometricOnly flag was removed).
    test('omits prompt args on plain encrypt', () async {
      responder = (_) => validEncryptResponse();
      await ks.encrypt(alias: 'a', plaintext: plaintext, aad: 'aad');
      expect(lastArgs!.containsKey('promptTitle'), isFalse);
      expect(lastArgs!.containsKey('promptSubtitle'), isFalse);
    });
  });

  group('decrypt method routing', () {
    test('routes to authenticateDecrypt when a promptTitle is given', () async {
      responder = (_) => plaintext;
      await ks.decrypt(
        version: 1,
        alias: 'a',
        ciphertext: Uint8List.fromList([9]),
        nonce: Uint8List(12),
        aad: 'aad',
        promptTitle: 'Unlock',
      );
      expect(lastMethod, 'authenticateDecrypt');
    });

    test('routes to plain decrypt when no promptTitle', () async {
      responder = (_) => plaintext;
      await ks.decrypt(
        version: 1,
        alias: 'a',
        ciphertext: Uint8List.fromList([9]),
        nonce: Uint8List(12),
        aad: 'aad',
      );
      expect(lastMethod, 'decrypt');
    });

    // The on-disk scheme version MUST cross the wire untouched: it selects the
    // decrypting scheme in the native append-only registry. Dropping or
    // rewriting it would route the blob to the wrong scheme.
    test('forwards the scheme version on decrypt', () async {
      responder = (_) => plaintext;
      await ks.decrypt(
        version: 7,
        alias: 'a',
        ciphertext: Uint8List.fromList([9]),
        nonce: Uint8List(12),
        aad: 'aad',
      );
      expect(lastArgs!['version'], 7);
    });
  });

  group('generateKey wire contract', () {
    // Every security-critical flag is a required parameter (no fail-open
    // defaults — L-5) AND must cross the wire explicitly: the Kotlin side
    // errors with bad_args on a missing flag rather than defaulting it, so a
    // facade that dropped one would break every key generation. Pins all six.
    test('sends every security flag explicitly', () async {
      responder = (_) => null;
      await ks.generateKey(
        alias: 'a',
        unlockedDeviceRequired: true,
        strongBox: false,
        userAuthenticationRequired: true,
        invalidatedByBiometricEnrollment: false,
        requireHardwareBacking: true,
      );
      expect(lastMethod, 'generateKey');
      expect(lastArgs!['alias'], 'a');
      expect(lastArgs!['unlockedDeviceRequired'], true);
      expect(lastArgs!['strongBox'], false);
      expect(lastArgs!['userAuthenticationRequired'], true);
      expect(lastArgs!['invalidatedByBiometricEnrollment'], false);
      expect(lastArgs!['requireHardwareBacking'], true);
    });
  });

  group('native error codes propagate as PlatformException', () {
    // The native layer now derives the prompt's authenticators from the key's
    // own KeyInfo and fails closed with `key_auth_type_unknown` when it can't
    // (unreadable type, or a non-auth key on the authenticating path). The
    // facade must surface that code untouched so the oubliette layer can map it
    // — never swallow it into a generic encrypt/decrypt failure.
    test('encrypt surfaces key_auth_type_unknown from the auth path', () async {
      responder = (_) => throw PlatformException(code: 'key_auth_type_unknown');
      await expectLater(
        ks.encrypt(
          alias: 'a',
          plaintext: plaintext,
          aad: 'aad',
          promptTitle: 'Unlock',
        ),
        throwsA(
          isA<PlatformException>().having(
            (e) => e.code,
            'code',
            'key_auth_type_unknown',
          ),
        ),
      );
    });

    // The two recoverable codes added for the transient-vs-fatal taxonomy
    // (M-5 decrypt_interrupted, L-8 unsupported_version) must also cross the
    // facade untouched — the oubliette layer maps both to a recoverable
    // exception; swallowing either into a generic failure would re-create the
    // purge-a-healthy-profile hazard they exist to prevent.
    test('decrypt surfaces decrypt_interrupted from the auth path', () async {
      responder = (_) => throw PlatformException(code: 'decrypt_interrupted');
      await expectLater(
        ks.decrypt(
          version: 1,
          alias: 'a',
          ciphertext: Uint8List.fromList([9]),
          nonce: Uint8List(12),
          aad: 'aad',
          promptTitle: 'Unlock',
        ),
        throwsA(
          isA<PlatformException>().having(
            (e) => e.code,
            'code',
            'decrypt_interrupted',
          ),
        ),
      );
    });

    test('decrypt surfaces unsupported_version for future blobs', () async {
      responder = (_) => throw PlatformException(code: 'unsupported_version');
      await expectLater(
        ks.decrypt(
          version: 99,
          alias: 'a',
          ciphertext: Uint8List.fromList([9]),
          nonce: Uint8List(12),
          aad: 'aad',
        ),
        throwsA(
          isA<PlatformException>().having(
            (e) => e.code,
            'code',
            'unsupported_version',
          ),
        ),
      );
    });

    test('decrypt surfaces key_auth_type_unknown from the auth path', () async {
      responder = (_) => throw PlatformException(code: 'key_auth_type_unknown');
      await expectLater(
        ks.decrypt(
          version: 1,
          alias: 'a',
          ciphertext: Uint8List.fromList([9]),
          nonce: Uint8List(12),
          aad: 'aad',
          promptTitle: 'Unlock',
        ),
        throwsA(
          isA<PlatformException>().having(
            (e) => e.code,
            'code',
            'key_auth_type_unknown',
          ),
        ),
      );
    });
  });

  group('response error mapping', () {
    test('encrypt with null native response throws encrypt_failed', () async {
      responder = (_) => null;
      await expectLater(
        ks.encrypt(alias: 'a', plaintext: plaintext, aad: 'aad'),
        throwsA(
          isA<PlatformException>().having(
            (e) => e.code,
            'code',
            'encrypt_failed',
          ),
        ),
      );
    });

    test('encrypt with missing fields throws encrypt_failed', () async {
      responder = (_) => {'version': 1}; // nonce/ciphertext absent
      await expectLater(
        ks.encrypt(alias: 'a', plaintext: plaintext, aad: 'aad'),
        throwsA(
          isA<PlatformException>().having(
            (e) => e.code,
            'code',
            'encrypt_failed',
          ),
        ),
      );
    });

    // A misbehaving platform returning wrong-typed fields must surface as the
    // documented PlatformException(encrypt_failed), never as a raw TypeError
    // escaping the caller's error taxonomy (the typed-exception mapping in the
    // oubliette layer only catches PlatformException).
    test('encrypt with wrong-typed fields throws encrypt_failed', () async {
      responder = (_) => {
        'version': 'one', // String, not int
        'nonce': Uint8List(12),
        'ciphertext': Uint8List.fromList([9]),
      };
      await expectLater(
        ks.encrypt(alias: 'a', plaintext: plaintext, aad: 'aad'),
        throwsA(
          isA<PlatformException>().having(
            (e) => e.code,
            'code',
            'encrypt_failed',
          ),
        ),
      );
    });

    test('decrypt with null native plaintext throws decrypt_failed', () async {
      responder = (_) => null;
      await expectLater(
        ks.decrypt(
          version: 1,
          alias: 'a',
          ciphertext: Uint8List.fromList([9]),
          nonce: Uint8List(12),
          aad: 'aad',
        ),
        throwsA(
          isA<PlatformException>().having(
            (e) => e.code,
            'code',
            'decrypt_failed',
          ),
        ),
      );
    });
  });

  group('encrypt response carries the live aad and alias', () {
    test('payload aad/keyAlias come from the call, not the wire', () async {
      responder = (_) => validEncryptResponse();
      final ep = await ks.encrypt(
        alias: 'my_alias',
        plaintext: plaintext,
        aad: 'my_aad',
      );
      expect(ep.aad, 'my_aad');
      expect(ep.keyAlias, 'my_alias');
      expect(ep.version, 1);
    });
  });
}
