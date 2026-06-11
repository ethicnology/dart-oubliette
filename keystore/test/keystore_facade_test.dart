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

    // The biometricOnly flag MUST cross the wire on the authenticating path so
    // the native prompt's allowed authenticators match a biometric-only key.
    // Dropping it would offer a device-credential fallback the key cannot honor.
    test('forwards biometricOnly to authenticateEncrypt', () async {
      responder = (_) => validEncryptResponse();
      await ks.encrypt(
        alias: 'a',
        plaintext: plaintext,
        aad: 'aad',
        promptTitle: 'Unlock',
        biometricOnly: true,
      );
      expect(lastArgs!['biometricOnly'], true);
    });

    // No prompt means no auth metadata leaks onto the plain encrypt call.
    test('omits prompt/biometricOnly args on plain encrypt', () async {
      responder = (_) => validEncryptResponse();
      await ks.encrypt(alias: 'a', plaintext: plaintext, aad: 'aad');
      expect(lastArgs!.containsKey('biometricOnly'), isFalse);
      expect(lastArgs!.containsKey('promptTitle'), isFalse);
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

    test('forwards biometricOnly to authenticateDecrypt', () async {
      responder = (_) => plaintext;
      await ks.decrypt(
        version: 1,
        alias: 'a',
        ciphertext: Uint8List.fromList([9]),
        nonce: Uint8List(12),
        aad: 'aad',
        promptTitle: 'Unlock',
        biometricOnly: true,
      );
      expect(lastArgs!['biometricOnly'], true);
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
