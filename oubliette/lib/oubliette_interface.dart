import 'dart:typed_data';

const String defaultPrefix = 'oubliette';
const String defaultKeyAlias = 'default_key';

class AndroidOptions {
  const AndroidOptions({
    this.prefix = defaultPrefix,
    this.keyAlias = defaultKeyAlias,
  });
  final String prefix;
  final String keyAlias;
}

class IosOptions {
  const IosOptions({this.prefix = defaultPrefix});
  final String prefix;
}

abstract class Oubliette {
  Oubliette.internal();

  Future<void> store(String key, Uint8List value);
  Future<Uint8List?> fetch(String key);
  Future<void> trash(String key);
  Future<bool> exists(String key);
}
