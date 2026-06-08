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
///
/// ### Format stability (upgrade contract)
///
/// This JSON envelope is **format v1** and frozen: data written by any 1.x
/// release is readable by every later 1.x. [fromMap] validates the known
/// fields and **ignores unknown ones**, so a future release may add envelope
/// fields without breaking older readers. Committed golden test vectors fail
/// CI if any change would make the current code unable to read a v1 blob. The
/// per-blob [version] selects the crypto scheme from an append-only registry; a
/// shipped scheme version is never removed, so old blobs always decrypt.
/// See `SECURITY.md` → *Stability & upgrade contract*.
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
      throw FormatException(
        'Malformed EncryptedPayload: missing or wrong-typed field(s) in $map',
      );
    }
    // A version below the first shipped scheme can never be decrypted. Reject
    // it here with a clear signal rather than letting it reach the scheme
    // registry as an opaque lookup miss.
    if (version < 1) {
      throw FormatException('EncryptedPayload version must be >= 1, got $version');
    }
    final Uint8List nonceBytes;
    final Uint8List ciphertextBytes;
    try {
      nonceBytes = base64Decode(nonce);
      ciphertextBytes = base64Decode(ciphertext);
    } on FormatException catch (e) {
      throw FormatException('EncryptedPayload has non-base64 nonce/ciphertext: $e');
    }
    // Structural integrity only — exact nonce/tag sizes are the scheme's
    // concern (and are enforced natively). Empty values cannot be a valid
    // GCM nonce or ciphertext, and surface here as clear corruption rather
    // than a downstream `decrypt_failed`.
    if (nonceBytes.isEmpty) {
      throw const FormatException('EncryptedPayload nonce is empty');
    }
    if (ciphertextBytes.isEmpty) {
      throw const FormatException('EncryptedPayload ciphertext is empty');
    }
    return EncryptedPayload(
      version: version,
      nonce: nonceBytes,
      ciphertext: ciphertextBytes,
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
