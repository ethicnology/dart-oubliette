import 'package:flutter/services.dart';

import 'package:secure_storage/android_keystore/encrypted_payload.dart';

class KeystoreFacade {
  final MethodChannel _channel = const MethodChannel('secure_storage');

  /// Returns whether the Android Keystore contains an entry for [alias] (KeyStore.containsAlias).
  Future<bool> containsAlias(String alias) async {
    final result = await _channel.invokeMethod<bool>('containsAlias', {
      'alias': alias,
    });
    return result ?? false;
  }

  /// Generates a non-exportable AES-256-GCM key in the Keystore under [alias] (KeyGenerator + KeyGenParameterSpec).
  /// Idempotent: if the alias already exists, no-op.
  /// [unlockedDeviceRequired]: when true, the key can only be used when the device is unlocked.
  Future<void> generateKey({
    required String alias,
    required bool unlockedDeviceRequired,
  }) async {
    await _channel.invokeMethod<void>('generateKey', {
      'alias': alias,
      'unlockedDeviceRequired': unlockedDeviceRequired,
    });
  }

  /// Removes the entry for [alias] from the Keystore (KeyStore.deleteEntry).
  ///
  /// See: https://developer.android.com/reference/java/security/KeyStore#deleteEntry(java.lang.String)
  Future<void> deleteEntry(String alias) async {
    await _channel.invokeMethod<void>('deleteEntry', {'alias': alias});
  }

  /// Encrypts [plaintext] with the key for [alias] using AES-GCM and [aad] (Cipher in ENCRYPT_MODE).
  /// Key material never leaves the Keystore; encryption runs in the system process.
  ///
  /// See: https://developer.android.com/reference/javax/crypto/Cipher
  Future<EncryptedPayload> encrypt({
    required String alias,
    required Uint8List plaintext,
    required String aad,
  }) async {
    final response = await _channel.invokeMethod<Map>('encrypt', {
      'plaintext': plaintext,
      'aad': aad,
      'alias': alias,
    });

    if (response == null) {
      throw PlatformException(
        code: 'encrypt_failed',
        message: 'Native encryption returned null response.',
      );
    }

    final version = response['version'] as int?;
    final nonce = response['nonce'] as Uint8List?;
    final ciphertext = response['ciphertext'] as Uint8List?;

    if (version == null || nonce == null || ciphertext == null) {
      throw PlatformException(
        code: 'encrypt_failed',
        message: 'Native encryption returned invalid fields.',
      );
    }

    return EncryptedPayload(
      version: version,
      nonce: nonce,
      ciphertext: ciphertext,
      aad: aad,
      alias: alias,
    );
  }

  /// Decrypts [ciphertext] with the key for [alias] using the given [nonce] and [aad] (Cipher in DECRYPT_MODE).
  ///
  /// See: https://developer.android.com/reference/javax/crypto/Cipher
  Future<Uint8List> decrypt({
    required int version,
    required String alias,
    required Uint8List ciphertext,
    required Uint8List nonce,
    required String aad,
  }) async {
    final plaintext = await _channel.invokeMethod<Uint8List>('decrypt', {
      'version': version,
      'ciphertext': ciphertext,
      'nonce': nonce,
      'aad': aad,
      'alias': alias,
    });
    if (plaintext != null) return plaintext;

    throw PlatformException(
      code: 'decrypt_failed',
      message: 'Native decryption returned null plaintext.',
    );
  }

  /// Returns whether the device supports StrongBox (PackageManager.FEATURE_STRONGBOX_KEYSTORE).
  /// When false, key generation with setIsStrongBoxBacked(true) is skipped and keys use TEE only.
  /// Throws [PlatformException] if the platform returns null (indicates an error).
  Future<bool> isStrongBoxAvailable() async {
    final result = await _channel.invokeMethod<bool>('isStrongBoxAvailable');
    if (result != null) return result;
    throw PlatformException(
      code: 'is_strongbox_available_failed',
      message: 'Native StrongBox availability returned null.',
    );
  }
}
