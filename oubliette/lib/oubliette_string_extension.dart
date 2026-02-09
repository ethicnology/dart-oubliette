import 'dart:convert';
import 'dart:typed_data';

import 'package:oubliette/oubliette_interface.dart';

extension OublietteStringExtension on Oubliette {
  Future<void> storeString(String key, String value) =>
      store(key, Uint8List.fromList(utf8.encode(value)));

  Future<String?> fetchString(String key) async {
    final bytes = await fetch(key);
    return bytes != null ? utf8.decode(bytes) : null;
  }
}
