import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:oubliette/oubliette.dart';

class _FakeOubliette extends Oubliette {
  _FakeOubliette() : super.internal();

  final Map<String, Uint8List> _store = {};

  @override
  Future<void> store(String key, Uint8List value) async {
    _store[key] = Uint8List.fromList(value);
  }

  @override
  Future<Uint8List?> fetch(String key) async {
    final data = _store[key];
    return data != null ? Uint8List.fromList(data) : null;
  }

  @override
  Future<void> trash(String key) async {
    _store.remove(key);
  }

  @override
  Future<void> purge() async {
    _store.clear();
  }

  @override
  Future<void> init() async {}

  @override
  Future<bool> exists(String key) async => _store.containsKey(key);

  @override
  Future<List<String>> keys() async => _store.keys.toList(growable: false);
}

void main() {
  late _FakeOubliette storage;

  setUp(() {
    storage = _FakeOubliette();
  });

  test('returns action result and zeroes buffer', () async {
    await storage.store('k', Uint8List.fromList([1, 2, 3]));

    late Uint8List captured;
    final result = await storage.useAndForget<String>('k', (bytes) async {
      captured = bytes;
      expect(captured, equals(Uint8List.fromList([1, 2, 3])));
      return 'done';
    });

    expect(result, 'done');
    expect(captured.every((b) => b == 0), isTrue);
  });

  test('returns null when key does not exist', () async {
    final result = await storage.useAndForget<String>('missing', (bytes) async {
      fail('action should not be called');
    });

    expect(result, isNull);
  });

  test('zeroes buffer even when action throws', () async {
    await storage.store('k', Uint8List.fromList([10, 20, 30]));

    late Uint8List captured;
    try {
      await storage.useAndForget<void>('k', (bytes) async {
        captured = bytes;
        throw Exception('boom');
      });
    } catch (_) {}

    expect(captured.every((b) => b == 0), isTrue);
  });

  test('buffer contains original data inside action', () async {
    final original = Uint8List.fromList([42, 43, 44]);
    await storage.store('k', original);

    await storage.useAndForget<void>('k', (bytes) async {
      expect(bytes, equals(original));
    });
  });
}
