/// Thrown when a stored [EncryptedPayload] does not match the slot it was
/// fetched from.
///
/// On Android the `aad` and `key_alias` fields are recomputed live from the
/// `(profile, key)` pair and compared against the values embedded in the
/// on-disk blob. A mismatch means the blob was relocated between storage slots
/// or its decrypting key was downgraded — an attacker with write access to
/// `SharedPreferences` attempting to make a payload decrypt under a different
/// (weaker, or differently-bound) key. The library refuses to decrypt rather
/// than trust attacker-controlled routing metadata.
class PayloadTamperException implements Exception {
  /// The logical key the caller asked for.
  final String key;

  /// The AAD the slot should carry (derived from the live profile + key).
  final String expectedAad;

  /// The AAD actually found in the stored blob.
  final String actualAad;

  /// The key alias the live profile mandates.
  final String expectedAlias;

  /// The key alias actually found in the stored blob.
  final String actualAlias;

  const PayloadTamperException({
    required this.key,
    required this.expectedAad,
    required this.actualAad,
    required this.expectedAlias,
    required this.actualAlias,
  });

  @override
  String toString() =>
      'PayloadTamperException: stored payload for key "$key" does not match '
      'its slot (expected aad="$expectedAad" alias="$expectedAlias", '
      'found aad="$actualAad" alias="$actualAlias"). '
      'Refusing to decrypt attacker-relocatable data.';
}
