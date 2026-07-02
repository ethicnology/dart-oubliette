import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:secret_service/secret_service.dart';

/// In-memory stand-in for the native `secret_service` MethodChannel. Keys items
/// by the `slot` attribute, mirroring the per-slot item model. Stores the
/// base64 string verbatim (as the native simple API would).
class _MockSecretService {
  final Map<String, String> items = {};
  String? errorCode;

  /// When true, `contains` replies null (a protocol violation the facade must
  /// fail closed on, never read as "absent").
  bool nullContainsReply = false;

  /// Mirrors the native deleteByPrefix/listByPrefix guard: a missing, empty,
  /// or non-U+001D-terminated prefix is rejected (`bad_args`) — the separator's
  /// position encodes the prefix length, so ownership is exact only with it
  /// (see the nested-prefix rationale in secret_service_plugin.cc). The mock
  /// must enforce this so a facade regression that passes a contract-invalid
  /// prefix fails in CI rather than only against the real backend.
  static void _rejectBadPrefix(String prefix) {
    if (prefix.isEmpty || !prefix.endsWith('\u001d')) {
      throw PlatformException(
        code: 'bad_args',
        message: 'Prefix must end at the reserved slot separator.',
      );
    }
  }

  Future<Object?> handle(MethodCall call) async {
    if (errorCode != null) {
      throw PlatformException(code: errorCode!, message: 'forced');
    }
    if (nullContainsReply && call.method == 'contains') return null;
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
        _rejectBadPrefix(prefix);
        items.removeWhere((slot, _) => slot.startsWith(prefix));
        return null;
      case 'listByPrefix':
        final prefix = args['prefix'] as String;
        _rejectBadPrefix(prefix);
        // Native returns the matching slot strings as a list (never null).
        return items.keys.where((slot) => slot.startsWith(prefix)).toList();
      default:
        return null;
    }
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late _MockSecretService mock;
  const channel = MethodChannel('secret_service');
  final service = SecretService();

  setUp(() {
    mock = _MockSecretService();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, mock.handle);
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, null);
  });

  test('add then get round-trips bytes (base64 over the wire)', () async {
    final data = Uint8List.fromList([0, 1, 2, 255, 13, 29]);
    await service.add('slot1', data);
    // Stored as base64 on the wire.
    expect(mock.items['slot1'], base64Encode(data));
    expect(await service.get('slot1'), data);
  });

  test('get returns null for an absent slot', () async {
    expect(await service.get('missing'), isNull);
  });

  test('contains tracks add and delete', () async {
    expect(await service.contains('s'), false);
    await service.add('s', Uint8List.fromList([1]));
    expect(await service.contains('s'), true);
    await service.delete('s');
    expect(await service.contains('s'), false);
  });

  test('add fails closed on a duplicate slot', () async {
    await service.add('dup', Uint8List.fromList([1]));
    await expectLater(
      service.add('dup', Uint8List.fromList([2])),
      throwsA(
        isA<PlatformException>().having(
          (e) => e.code,
          'code',
          'already_exists',
        ),
      ),
    );
  });

  // Prefix tests use `profile + U+001D` prefixes, the only shape the native
  // handler accepts (the reserved separator must be the final byte -- see the
  // nested-prefix guard in secret_service_plugin.cc, which the mock mirrors).
  test('deleteByPrefix removes only matching slots', () async {
    await service.add('p\u001da', Uint8List.fromList([1]));
    await service.add('p\u001db', Uint8List.fromList([2]));
    await service.add('other\u001dc', Uint8List.fromList([3]));
    await service.deleteByPrefix('p\u001d');
    expect(await service.contains('p\u001da'), false);
    expect(await service.contains('p\u001db'), false);
    expect(await service.contains('other\u001dc'), true);
  });

  test('deleteByPrefix without the trailing separator is rejected as bad_args '
      '(native contract, mirrored by the mock)', () async {
    await service.add('p\u001da', Uint8List.fromList([1]));
    // 'p' byte-prefix-matches the slot but lacks the separator that makes
    // ownership exact -- the backend must reject it, never cross-wipe.
    await expectLater(
      service.deleteByPrefix('p'),
      throwsA(
        isA<PlatformException>().having((e) => e.code, 'code', 'bad_args'),
      ),
    );
    expect(await service.contains('p\u001da'), true);
  });

  test(
    'listByPrefix returns only matching slots without touching them',
    () async {
      await service.add('p\u001da', Uint8List.fromList([1]));
      await service.add('p\u001db', Uint8List.fromList([2]));
      await service.add('other\u001dc', Uint8List.fromList([3]));
      expect(
        await service.listByPrefix('p\u001d'),
        unorderedEquals(['p\u001da', 'p\u001db']),
      );
      // Non-destructive: everything is still there.
      expect(await service.contains('p\u001da'), true);
      expect(await service.contains('other\u001dc'), true);
    },
  );

  test('listByPrefix returns an empty list for an unmatched prefix', () async {
    await service.add('p\u001da', Uint8List.fromList([1]));
    expect(await service.listByPrefix('q\u001d'), isEmpty);
  });

  test('listByPrefix without the trailing separator is rejected as bad_args '
      '(native contract, mirrored by the mock)', () async {
    await expectLater(
      service.listByPrefix('p'),
      throwsA(
        isA<PlatformException>().having((e) => e.code, 'code', 'bad_args'),
      ),
    );
  });

  // An embedded NUL would silently truncate the slot/prefix at the native
  // C-string boundary, defeating the byte-exact scoping. The facade guard is
  // the authoritative and ONLY enforcement — the native layer cannot re-check,
  // because the string reaches it already NUL-truncated (see the plugin's
  // embedded-NUL comment) — so the value must never reach the wire. No native
  // call is made.
  group('embedded NUL is rejected before the channel', () {
    test('add', () {
      expect(
        () => service.add('a\u0000b', Uint8List.fromList([1])),
        throwsA(isA<ArgumentError>()),
      );
      expect(mock.items, isEmpty);
    });

    test('get', () {
      expect(() => service.get('a\u0000b'), throwsA(isA<ArgumentError>()));
    });

    test('contains', () {
      expect(() => service.contains('a\u0000b'), throwsA(isA<ArgumentError>()));
    });

    test('delete', () {
      expect(() => service.delete('a\u0000b'), throwsA(isA<ArgumentError>()));
    });

    test('deleteByPrefix', () {
      expect(
        () => service.deleteByPrefix('a\u0000'),
        throwsA(isA<ArgumentError>()),
      );
    });
  });

  test('backend errors propagate as PlatformException', () async {
    mock.errorCode = 'backend_unavailable';
    await expectLater(
      service.get('x'),
      throwsA(
        isA<PlatformException>().having(
          (e) => e.code,
          'code',
          'backend_unavailable',
        ),
      ),
    );
  });

  test('get on a tampered (non-base64) value throws payload_corrupt '
      'without leaking the stored value', () async {
    // An attacker flips one byte: the value is invalid base64 but still
    // carries (almost all of) the secret material.
    const tampered = 'c2VjcmV0LW1hdGVyaWFsLWhlcmU.'; // '.' is not base64
    mock.items['t'] = tampered;
    await expectLater(
      service.get('t'),
      throwsA(
        isA<PlatformException>()
            .having((e) => e.code, 'code', 'payload_corrupt')
            // The slot may appear; the stored value must not (a raw
            // FormatException would embed a snippet of it).
            .having(
              (e) => e.toString().contains('c2VjcmV0'),
              'leaks stored value',
              false,
            ),
      ),
    );
  });

  test('contains fails closed on a null protocol reply', () async {
    mock.nullContainsReply = true;
    await expectLater(
      service.contains('x'),
      throwsA(
        isA<PlatformException>().having(
          (e) => e.code,
          'code',
          'secret_service_error',
        ),
      ),
    );
  });

  test('listByPrefix fails closed on a null protocol reply', () async {
    // A separate, deliberately protocol-violating mock: the real native
    // handler always returns a list (possibly empty), so a null reply is a
    // malformed-host signal the facade must surface -- never read as "no
    // keys", which would report a profile that actually holds secrets as
    // empty (inviting a caller to re-onboard over live data).
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async => null);
    await expectLater(
      service.listByPrefix('p\u001d'),
      throwsA(
        isA<PlatformException>().having(
          (e) => e.code,
          'code',
          'secret_service_error',
        ),
      ),
    );
  });

  // A locked/erroring keyring must surface its distinct code (never read as
  // "absent") so the Dart layer can raise the right typed exception. These two
  // codes are emitted by the native warmup's unlock path.
  for (final code in ['keyring_locked', 'auth_cancelled']) {
    test('$code propagates rather than reading as absent', () async {
      mock.errorCode = code;
      await expectLater(
        service.contains('x'),
        throwsA(isA<PlatformException>().having((e) => e.code, 'code', code)),
      );
    });
  }
}
