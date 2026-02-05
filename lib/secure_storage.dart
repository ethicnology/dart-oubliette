
import 'secure_storage_platform_interface.dart';

class SecureStorage {
  Future<String?> getPlatformVersion() {
    return SecureStoragePlatform.instance.getPlatformVersion();
  }
}
