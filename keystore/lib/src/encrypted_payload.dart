import 'dart:convert';
import 'dart:typed_data';

/// A versioned, self-describing encrypted blob produced by an
/// [EncryptionScheme] and persisted in `SharedPreferences`.
///
/// JSON shape (stable, versioned):
/// ```json
/// {
///   "version": 1,
///   "nonce": "base64...",
///   "ciphertext": "base64...",
///   "aad": "oubliette_my_key",
///   "key_alias": "oubliette_only_unlocked"
/// }
/// ```
///
/// ### Trust boundary
///
/// Only [version] is authoritative on decrypt — it selects the scheme that
/// can read the blob. [aad] and [keyAlias] are persisted for diagnostics and
/// for a *verify-only* check: the caller recomputes the expected values from
/// the live `(profile, key)` pair and rejects the payload if they disagree
/// (see `AndroidOubliette.fetch`). They must never be used to *choose* how the
/// blob is decrypted, because the blob lives in attacker-writable storage.
final class EncryptedPayload {
  final int version;
  final Uint8List nonce;
  final Uint8List ciphertext;
  final String aad;
  final String keyAlias;

  const EncryptedPayload({
    required this.version,
    required this.nonce,
    required this.ciphertext,
    required this.aad,
    required this.keyAlias,
  });

  Map<String, dynamic> toMap() => {
        'version': version,
        'nonce': base64Encode(nonce),
        'ciphertext': base64Encode(ciphertext),
        'aad': aad,
        'key_alias': keyAlias,
      };

  String toJson() => jsonEncode(toMap());

  factory EncryptedPayload.fromMap(Map<String, dynamic> map) {
    final version = map['version'];
    final nonce = map['nonce'];
    final ciphertext = map['ciphertext'];
    final aad = map['aad'];
    final keyAlias = map['key_alias'];
    if (version is! int ||
        nonce is! String ||
        ciphertext is! String ||
        aad is! String ||
        keyAlias is! String) {
      throw FormatException('Malformed EncryptedPayload: $map');
    }
    return EncryptedPayload(
      version: version,
      nonce: Uint8List.fromList(base64Decode(nonce)),
      ciphertext: Uint8List.fromList(base64Decode(ciphertext)),
      aad: aad,
      keyAlias: keyAlias,
    );
  }

  factory EncryptedPayload.fromJson(String json) {
    final decoded = jsonDecode(json);
    if (decoded is! Map<String, dynamic>) {
      throw FormatException('EncryptedPayload JSON is not an object: $json');
    }
    return EncryptedPayload.fromMap(decoded);
  }
}
