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
  late Object? Function(MethodCall) responder;

  setUp(() {
    lastMethod = null;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
      lastMethod = call.method;
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
  });

  group('response error mapping', () {
    test('encrypt with null native response throws encrypt_failed', () async {
      responder = (_) => null;
      await expectLater(
        ks.encrypt(alias: 'a', plaintext: plaintext, aad: 'aad'),
        throwsA(isA<PlatformException>()
            .having((e) => e.code, 'code', 'encrypt_failed')),
      );
    });

    test('encrypt with missing fields throws encrypt_failed', () async {
      responder = (_) => {'version': 1}; // nonce/ciphertext absent
      await expectLater(
        ks.encrypt(alias: 'a', plaintext: plaintext, aad: 'aad'),
        throwsA(isA<PlatformException>()
            .having((e) => e.code, 'code', 'encrypt_failed')),
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
        throwsA(isA<PlatformException>()
            .having((e) => e.code, 'code', 'decrypt_failed')),
      );
    });
  });

  group('encrypt response carries the live aad and alias', () {
    test('payload aad/keyAlias come from the call, not the wire', () async {
      responder = (_) => validEncryptResponse();
      final ep = await ks.encrypt(alias: 'my_alias', plaintext: plaintext, aad: 'my_aad');
      expect(ep.aad, 'my_aad');
      expect(ep.keyAlias, 'my_alias');
      expect(ep.version, 1);
    });
  });
}
