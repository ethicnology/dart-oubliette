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

  /// When [userAuthenticationRequired] is `true`,
  /// [invalidatedByBiometricEnrollment] also selects the key's authenticator
  /// set: `true` makes the key **biometric-only** (`AUTH_BIOMETRIC_STRONG`,
  /// no PIN/pattern/password) — keymaster only enforces enrollment
  /// invalidation for biometric-only keys, so a credential fallback would
  /// silently void it. Biometric-only keygen requires biometric hardware and
  /// at least one enrolled biometric. `false` keeps the credential fallback
  /// (`AUTH_DEVICE_CREDENTIAL | AUTH_BIOMETRIC_STRONG`). The [encrypt]/[decrypt]
  /// prompt no longer needs to be told which: the native layer reads the key's
  /// own `KeyInfo` and restricts the prompt to match (see [encrypt]).
  Future<void> generateKey({
    required String alias,
    required bool unlockedDeviceRequired,
    required bool strongBox,
    bool userAuthenticationRequired = false,
    bool invalidatedByBiometricEnrollment = true,
    required bool requireHardwareBacking,
  }) async {
    await _channel.invokeMethod<void>('generateKey', {
      'alias': alias,
      'unlockedDeviceRequired': unlockedDeviceRequired,
      'strongBox': strongBox,
      'userAuthenticationRequired': userAuthenticationRequired,
      'invalidatedByBiometricEnrollment': invalidatedByBiometricEnrollment,
      'requireHardwareBacking': requireHardwareBacking,
    });
  }

  Future<void> deleteEntry(String alias) async {
    await _channel.invokeMethod<void>('deleteEntry', {'alias': alias});
  }

  /// Encrypts [plaintext] using the key identified by [alias].
  ///
  /// Throws [PlatformException] with code:
  /// - `"key_not_found"` if the alias does not exist in the Android Keystore.
  /// - `"key_invalidated"` if the key was permanently invalidated
  ///   (e.g. biometric enrollment changed).
  /// - `"encrypt_failed"` for other encryption errors.
  /// - `"key_auth_type_unknown"` if a prompt was requested but the key's
  ///   accepted authenticator set could not be read from its `KeyInfo`, or the
  ///   key is not auth-bound (fail-closed: the prompt is refused rather than
  ///   shown with a guessed authenticator set).
  ///
  /// [biometricOnly] is now **advisory only**: the native layer derives the
  /// prompt's allowed authenticators authoritatively from the key's own
  /// `KeyInfo` (`getUserAuthenticationType()`), so a biometric-only key always
  /// gets a `BIOMETRIC_STRONG`-only prompt and a credential-capable key gets the
  /// `DEVICE_CREDENTIAL` fallback — the two can no longer disagree. The flag is
  /// retained for source compatibility; it does not influence the prompt.
  Future<EncryptedPayload> encrypt({
    required String alias,
    required Uint8List plaintext,
    required String aad,
    String? promptTitle,
    String? promptSubtitle,
    bool biometricOnly = false,
  }) async {
    final authenticate = promptTitle != null;
    final args = <String, dynamic>{
      'plaintext': plaintext,
      'aad': aad,
      'alias': alias,
      if (authenticate) 'promptTitle': promptTitle,
      if (authenticate)
        'promptSubtitle': promptSubtitle ?? 'Confirm your identity',
      if (authenticate) 'biometricOnly': biometricOnly,
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

  /// Decrypts [ciphertext] using the key identified by [alias].
  ///
  /// Throws [PlatformException] with code:
  /// - `"key_not_found"` if the alias does not exist in the Android Keystore.
  /// - `"key_invalidated"` if the key was permanently invalidated
  ///   (e.g. biometric enrollment changed).
  /// - `"decrypt_failed"` for other decryption errors.
  /// - `"key_auth_type_unknown"` — see [encrypt].
  /// See [encrypt] for the (advisory) [biometricOnly] contract.
  Future<Uint8List> decrypt({
    required int version,
    required String alias,
    required Uint8List ciphertext,
    required Uint8List nonce,
    required String aad,
    String? promptTitle,
    String? promptSubtitle,
    bool biometricOnly = false,
  }) async {
    final authenticate = promptTitle != null;
    final args = <String, dynamic>{
      'version': version,
      'ciphertext': ciphertext,
      'nonce': nonce,
      'aad': aad,
      'alias': alias,
      if (authenticate) 'promptTitle': promptTitle,
      if (authenticate)
        'promptSubtitle': promptSubtitle ?? 'Confirm your identity',
      if (authenticate) 'biometricOnly': biometricOnly,
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
    final version = response['version'];
    final nonce = response['nonce'];
    final ciphertext = response['ciphertext'];
    // `is!` checks, not `as` casts: a wrong-typed field from a misbehaving
    // platform must surface as the documented PlatformException(encrypt_failed)
    // — never as a raw TypeError that bypasses the caller's error taxonomy.
    if (version is! int || nonce is! Uint8List || ciphertext is! Uint8List) {
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
      keyAlias: alias,
    );
  }
}
