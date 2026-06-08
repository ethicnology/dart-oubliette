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
  return '$prefix$slotSeparator$key';
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
}
