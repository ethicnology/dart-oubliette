import 'package:flutter/services.dart';

import 'package:keystore/src/encrypted_payload.dart';

final class Keystore {
  final MethodChannel _channel = const MethodChannel('keystore');

  Future<bool> containsAlias(String alias) async {
    final result = await _channel.invokeMethod<bool>('containsAlias', {
      'alias': alias,
    });
    return result ?? false;
  }

  Future<void> generateKey({
    required String alias,
    required bool unlockedDeviceRequired,
    required bool strongBox,
    bool userAuthenticationRequired = false,
    bool invalidatedByBiometricEnrollment = true,
  }) async {
    await _channel.invokeMethod<void>('generateKey', {
      'alias': alias,
      'unlockedDeviceRequired': unlockedDeviceRequired,
      'strongBox': strongBox,
      'userAuthenticationRequired': userAuthenticationRequired,
      'invalidatedByBiometricEnrollment': invalidatedByBiometricEnrollment,
    });
  }

  Future<void> deleteEntry(String alias) async {
    await _channel.invokeMethod<void>('deleteEntry', {'alias': alias});
  }

  Future<EncryptedPayload> encrypt({
    required String alias,
    required Uint8List plaintext,
    required String aad,
    String? promptTitle,
    String? promptSubtitle,
  }) async {
    final authenticate = promptTitle != null;
    final args = <String, dynamic>{
      'plaintext': plaintext,
      'aad': aad,
      'alias': alias,
      if (authenticate) 'promptTitle': promptTitle,
      if (authenticate) 'promptSubtitle': promptSubtitle ?? 'Confirm your identity',
    };
    return _parseEncryptResponse(
      await _channel.invokeMethod<Map>(
        authenticate ? 'authenticateEncrypt' : 'encrypt',
        args,
      ),
      aad,
      alias,
    );
  }

  Future<Uint8List> decrypt({
    required int version,
    required String alias,
    required Uint8List ciphertext,
    required Uint8List nonce,
    required String aad,
    String? promptTitle,
    String? promptSubtitle,
  }) async {
    final authenticate = promptTitle != null;
    final args = <String, dynamic>{
      'version': version,
      'ciphertext': ciphertext,
      'nonce': nonce,
      'aad': aad,
      'alias': alias,
      if (authenticate) 'promptTitle': promptTitle,
      if (authenticate) 'promptSubtitle': promptSubtitle ?? 'Confirm your identity',
    };
    final plaintext = await _channel.invokeMethod<Uint8List>(
      authenticate ? 'authenticateDecrypt' : 'decrypt',
      args,
    );
    if (plaintext != null) return plaintext;

    throw PlatformException(
      code: 'decrypt_failed',
      message: 'Native decryption returned null plaintext.',
    );
  }

  Future<bool> isStrongBoxAvailable() async {
    final result = await _channel.invokeMethod<bool>('isStrongBoxAvailable');
    if (result != null) return result;
    throw PlatformException(
      code: 'is_strongbox_available_failed',
      message: 'Native StrongBox availability returned null.',
    );
  }

  EncryptedPayload _parseEncryptResponse(
    Map<dynamic, dynamic>? response,
    String aad,
    String alias,
  ) {
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
}
