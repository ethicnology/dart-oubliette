/// FROZEN ON-DISK CONSTANT — changing it orphans every stored secret.
///
/// Group Separator (U+001D), placed between a profile's `prefix` and the
/// logical key to form a storage slot:
///
/// ```text
/// slot = prefix + slotSeparator + key
/// ```
///
/// It is a control character that does not occur in normal keys or prefixes, so
/// it forms an unambiguous boundary. Because the separator's *position* encodes
/// the prefix length, two distinct prefixes can never produce colliding slots,
/// and `purge()` ownership is exact: a slot belongs to a profile **iff** it
/// begins with `prefix + slotSeparator`.
///
/// This is what makes a profile whose prefix nests under another's safe — the
/// built-in `authenticated_` ⊂ `authenticated_fatal_`, or two sibling custom
/// profiles like `app_` ⊂ `app_admin_`. Purging one can never wipe the other,
/// because e.g. the slot `app_admin_␝k` does not start with `app_␝`.
///
/// On Android the slot string is also used verbatim as the AES-GCM AAD.
const String slotSeparator = '\u001D';

/// Builds the storage slot for [key] under [prefix].
///
/// Rejects a [key] containing the reserved [slotSeparator]: allowing it would
/// let a crafted key shift the apparent prefix boundary and forge another
/// profile's slot (e.g. key `"x"` under prefix `"a"` would otherwise
/// collide with prefix `"a"`).
String buildSlot(String prefix, String key) {
  // Reject the separator on either side. A `custom` prefix is validated up front
  // by validateSlotPrefix, but a named constructor's `prefix` override is `const`
  // and cannot run validation — this re-check keeps the invariant airtight
  // however the prefix was set. A separator in a key could forge another slot.
  if (prefix.contains(slotSeparator)) {
    throw ArgumentError.value(
      prefix,
      'prefix',
      'must not contain the reserved slot separator (U+001D)',
    );
  }
  if (key.contains(slotSeparator)) {
    throw ArgumentError.value(
      key,
      'key',
      'must not contain the reserved slot separator (U+001D)',
    );
  }
  // Reject malformed UTF-16. Every backend (method channel, Keychain account,
  // SharedPreferences key, Secret Service attribute — and the vault's AAD)
  // sees the slot as UTF-8, where every unpaired surrogate encodes to the same
  // U+FFFD replacement bytes. Two *distinct* Dart strings differing only in
  // their lone surrogate would therefore collide into one native slot — a
  // slot-isolation hole (fetch of one key could return and cleanly decrypt the
  // other's secret). Well-formed strings round-trip injectively; only
  // malformed ones are rejected.
  if (!_isWellFormedUtf16(prefix)) {
    throw ArgumentError.value(
      prefix,
      'prefix',
      'contains an unpaired surrogate (malformed UTF-16)',
    );
  }
  if (!_isWellFormedUtf16(key)) {
    throw ArgumentError.value(
      key,
      'key',
      'contains an unpaired surrogate (malformed UTF-16)',
    );
  }
  return '$prefix$slotSeparator$key';
}

bool _isWellFormedUtf16(String s) {
  for (var i = 0; i < s.length; i++) {
    final c = s.codeUnitAt(i);
    if (c >= 0xD800 && c <= 0xDBFF) {
      // High surrogate must be followed by a low surrogate.
      if (i + 1 >= s.length) return false;
      final next = s.codeUnitAt(i + 1);
      if (next < 0xDC00 || next > 0xDFFF) return false;
      i++;
    } else if (c >= 0xDC00 && c <= 0xDFFF) {
      // Lone low surrogate.
      return false;
    }
  }
  return true;
}

/// Validates a custom profile [prefix]: non-empty and free of the reserved
/// [slotSeparator]. Called from the `custom` constructors; the named-profile
/// constructors use known-valid built-in prefixes.
void validateSlotPrefix(String prefix) {
  if (prefix.isEmpty) {
    throw ArgumentError.value(prefix, 'prefix', 'must not be empty');
  }
  if (prefix.contains(slotSeparator)) {
    throw ArgumentError.value(
      prefix,
      'prefix',
      'must not contain the reserved slot separator (U+001D)',
    );
  }
  if (!_isWellFormedUtf16(prefix)) {
    throw ArgumentError.value(
      prefix,
      'prefix',
      'contains an unpaired surrogate (malformed UTF-16)',
    );
  }
}
