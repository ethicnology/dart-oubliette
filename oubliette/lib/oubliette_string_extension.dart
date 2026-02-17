import 'dart:convert';
import 'dart:typed_data';

import 'package:oubliette/oubliette.dart';

extension OublietteStringExtension on Oubliette {
  Future<void> storeString(String key, String value) =>
      store(key, Uint8List.fromList(utf8.encode(value)));

  Future<T?> useStringAndForget<T>(String key, Future<T> Function(String value) action) =>
      useAndForget(key, (bytes) => action(utf8.decode(bytes)));
}
