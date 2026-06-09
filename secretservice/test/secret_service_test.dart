import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:secretservice/secretservice.dart';

/// In-memory stand-in for the native `secretservice` MethodChannel. Keys items
/// by the `slot` attribute, mirroring the per-slot item model. Stores the
/// base64 string verbatim (as the native simple API would).
class _MockSecretService {
  final Map<String, String> items = {};
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
      default:
        return null;
    }
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late _MockSecretService mock;
  const channel = MethodChannel('secretservice');
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

  test('deleteByPrefix removes only matching slots', () async {
    await service.add('pa', Uint8List.fromList([1]));
    await service.add('pb', Uint8List.fromList([2]));
    await service.add('otherc', Uint8List.fromList([3]));
    await service.deleteByPrefix('p');
    expect(await service.contains('pa'), false);
    expect(await service.contains('pb'), false);
    expect(await service.contains('otherc'), true);
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
}
