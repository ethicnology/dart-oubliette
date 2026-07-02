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
///
/// ### Size limit (write/read symmetric)
///
/// Every field is capped — [maxFieldBytes] (~48 KiB) per binary field at
/// construction, [maxFieldChars] base64/string chars at [fromMap]. The two caps
/// are the same limit in different units and share one constant, so a payload
/// that can be constructed (and therefore stored) is always readable back:
/// an oversized secret fails loudly at write time with an [ArgumentError]
/// instead of stranding data that parses as corruption on every later read.
final class EncryptedPayload {
  /// Per-field size ceiling in base64/string characters, enforced on the READ
  /// path ([fromMap]) as defense-in-depth against a pathological blob in
  /// attacker-writable storage. Shared with the write-side byte cap
  /// ([maxFieldBytes]) so the two paths can never drift apart: anything the
  /// constructor accepts serialises within this cap, and anything within this
  /// cap deserialises without hitting the constructor's guard.
  static const int maxFieldChars = 64 * 1024;

  /// Decoded-bytes equivalent of [maxFieldChars], enforced on the WRITE path
  /// (the constructor): base64 emits 4 chars per 3 bytes, so 48 KiB of bytes
  /// encodes to exactly the 64 Ki-char read cap. Without this symmetric guard
  /// an oversized secret would store successfully and then fail EVERY
  /// subsequent read as corruption — permanently stranded data, the silent-loss
  /// failure the SECURITY.md upgrade contract pledges away. Failing the write
  /// up front, with the limit in the message, keeps the invariant "whatever was
  /// stored can be read back".
  static const int maxFieldBytes = maxFieldChars ~/ 4 * 3; // 48 KiB

  final int version;
  final Uint8List nonce;
  final Uint8List ciphertext;
  final String aad;
  final String keyAlias;

  EncryptedPayload({
    required this.version,
    required this.nonce,
    required this.ciphertext,
    required this.aad,
    required this.keyAlias,
  }) {
    // Write-side mirror of the [fromMap] read caps (see [maxFieldBytes]).
    // ArgumentError, not FormatException: this is invalid caller input at
    // construction time, not a parse of untrusted stored bytes. The messages
    // state sizes and limits only — never field content, which includes the
    // ciphertext and a possibly tenant-identifying aad/alias (the same
    // diagnostic-hygiene rule as [fromMap]).
    if (nonce.length > maxFieldBytes || ciphertext.length > maxFieldBytes) {
      throw ArgumentError(
        'EncryptedPayload nonce/ciphertext exceeds $maxFieldBytes bytes '
        '(~48 KiB): storing it would succeed but every subsequent read would '
        'reject it as corrupt, permanently stranding the data '
        '(nonce: ${nonce.length} B, ciphertext: ${ciphertext.length} B)',
      );
    }
    if (aad.length > maxFieldChars || keyAlias.length > maxFieldChars) {
      throw ArgumentError(
        'EncryptedPayload aad/keyAlias exceeds $maxFieldChars characters: '
        'storing it would succeed but every subsequent read would reject it '
        'as corrupt, permanently stranding the data '
        '(aad: ${aad.length}, keyAlias: ${keyAlias.length})',
      );
    }
  }

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
      // Deliberately does NOT interpolate the map: it carries the key alias,
      // the AAD slot string, and ciphertext — folding them into the message
      // would leak them through PayloadCorruptException.toString() into logs
      // and crash reporters (see the diagnostic-hygiene doctrine in
      // oubliette's errors.dart).
      throw const FormatException(
        'Malformed EncryptedPayload: missing or wrong-typed field(s)',
      );
    }
    // A version below the first shipped scheme can never be decrypted. Reject
    // it here with a clear signal rather than letting it reach the scheme
    // registry as an opaque lookup miss.
    if (version < 1) {
      throw FormatException(
        'EncryptedPayload version must be >= 1, got $version',
      );
    }
    // Defense-in-depth upper bounds on attacker-writable fields. The blob lives
    // in MODE_PRIVATE SharedPreferences — reaching it needs root or a tampered
    // backup, and the framework already loads the whole prefs file into memory
    // at getInstance — so these are belt-and-suspenders against a pathological /
    // oversized entry, not a primary control. The limits are generous:
    // oubliette stores small secrets (mnemonics, tokens), never multi-MB blobs.
    // [maxFieldChars] is the shared constant the constructor enforces
    // symmetrically at write time (as [maxFieldBytes] decoded bytes), so a
    // payload this library wrote can never be rejected here.
    const maxVersion = 1 << 20; // far above any realistic shipped scheme count
    if (version > maxVersion) {
      throw FormatException(
        'EncryptedPayload version is implausibly large: $version',
      );
    }
    // Applied to every attacker-writable string, including the verify-only
    // aad/key_alias (oversized values would only fail the live tamper check
    // downstream, but capping here is cheap symmetry).
    if (nonce.length > maxFieldChars ||
        ciphertext.length > maxFieldChars ||
        aad.length > maxFieldChars ||
        keyAlias.length > maxFieldChars) {
      throw const FormatException(
        'EncryptedPayload field exceeds the maximum allowed size',
      );
    }
    final Uint8List nonceBytes;
    final Uint8List ciphertextBytes;
    try {
      nonceBytes = base64Decode(nonce);
      ciphertextBytes = base64Decode(ciphertext);
    } on FormatException {
      // The cause is not chained: base64Decode's FormatException embeds the
      // offending source string, which is blob content (same hygiene rule).
      throw const FormatException(
        'EncryptedPayload has non-base64 nonce/ciphertext',
      );
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
      // No `$json` interpolation — same hygiene rationale as in [fromMap].
      throw const FormatException('EncryptedPayload JSON is not an object');
    }
    return EncryptedPayload.fromMap(decoded);
  }
}
