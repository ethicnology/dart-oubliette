import 'package:flutter_test/flutter_test.dart';
import 'package:secure_storage/secure_storage.dart';
import 'package:secure_storage/secure_storage_platform_interface.dart';
import 'package:secure_storage/secure_storage_method_channel.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

class MockSecureStoragePlatform
    with MockPlatformInterfaceMixin
    implements SecureStoragePlatform {

  @override
  Future<String?> getPlatformVersion() => Future.value('42');
}

void main() {
  final SecureStoragePlatform initialPlatform = SecureStoragePlatform.instance;

  test('$MethodChannelSecureStorage is the default instance', () {
    expect(initialPlatform, isInstanceOf<MethodChannelSecureStorage>());
  });

  test('getPlatformVersion', () async {
    SecureStorage secureStoragePlugin = SecureStorage();
    MockSecureStoragePlatform fakePlatform = MockSecureStoragePlatform();
    SecureStoragePlatform.instance = fakePlatform;

    expect(await secureStoragePlugin.getPlatformVersion(), '42');
  });
}
