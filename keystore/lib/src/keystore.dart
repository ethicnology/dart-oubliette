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

  /// Every security-critical flag is `required` with **no default** — this
  /// facade is documented as usable standalone, so a hidden default would be a
  /// fail-open trap: [userAuthenticationRequired] silently defaulting to
  /// `false` would mint a no-auth key for a caller who merely forgot the flag,
  /// and a defaulted [invalidatedByBiometricEnrollment] would silently pick the
  /// key's authenticator set (see below). The Kotlin side already errors on a
  /// missing flag rather than defaulting it (`bad_args`); requiring them here
  /// moves that refusal to compile time.
  ///
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
    required bool userAuthenticationRequired,
    required bool invalidatedByBiometricEnrollment,
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
  /// When a [promptTitle] is supplied the authenticating path may additionally
  /// throw `"auth_cancelled"` (user cancelled), `"auth_error"`, `"auth_failed"`,
  /// `"detached"`, or `"decrypt_interrupted"` (the keymaster operation opened
  /// before the prompt was pruned while it waited on the user — transient;
  /// retry, never purge). See the README "Native error-code surface" table for
  /// the full stable contract.
  ///
  /// The prompt's allowed authenticators are derived authoritatively by the
  /// native layer from the key's own `KeyInfo` (`getUserAuthenticationType()`):
  /// a biometric-only key always gets a `BIOMETRIC_STRONG`-only prompt and a
  /// credential-capable key gets the `DEVICE_CREDENTIAL` fallback. The caller
  /// does not (and cannot) choose the authenticator set — it is fixed at key
  /// generation, so the prompt and the key can never disagree.
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
      if (authenticate)
        'promptSubtitle': promptSubtitle ?? 'Confirm your identity',
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
  /// - `"unsupported_version"` if the blob's scheme [version] is newer than
  ///   this reader (app rollback/downgrade). The data is intact and readable
  ///   by the release that wrote it — upgrade the app; never purge.
  /// - `"key_auth_type_unknown"` — see [encrypt].
  /// When a [promptTitle] is supplied, the auth-path codes listed in [encrypt]
  /// (`auth_cancelled`, `auth_error`, `auth_failed`, `detached`,
  /// `decrypt_interrupted`) apply too. The prompt's authenticator set is fixed
  /// by the key's `KeyInfo` (see [encrypt]).
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
      if (authenticate)
        'promptSubtitle': promptSubtitle ?? 'Confirm your identity',
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
