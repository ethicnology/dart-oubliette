## Unreleased

- `get` no longer rethrows the raw `FormatException` for a tampered/corrupt
  (non-base64) stored value — its message embeds a snippet of the source
  string, leaking stored secret material into error logs. It now raises
  `PlatformException(payload_corrupt)` naming only the slot.
- `contains` fails closed on a null protocol reply (previously read as
  "absent") — a malformed reply can no longer make a present item look empty.
- Purge: guard against a malformed/hostile provider returning an item with no
  readable attributes (`secret_item_get_attributes` → NULL); previously this
  hit GLib criticals (an abort under `G_DEBUG=fatal-criticals`) and the item
  silently escaped the partial-failure count. Such items are now left in place
  and counted, so the purge reports partial instead of lying.
- README: documented second-pass residual limits — plaintext copies in
  codec/Dart heap are not zeroized, the unlock watchdog covers only the
  warmup (re-lock / non-default-collection prompts race past it), and the
  duplicate-slot guard is per-process (no atomic put-if-absent).
- Distinguish a dismissed unlock prompt (`auth_cancelled`) from a generic
  locked/timed-out collection (`keyring_locked`) in the native warmup, matching
  the codes the Dart facade documents and `linux_oubliette` maps.
- Reject malformed method-channel arguments defensively: non-string args no
  longer reach `fl_value_get_string` (which would abort the host process), and
  an empty `deleteByPrefix` prefix is refused so it cannot cross-profile-wipe.
- README: documented the software-tier threat model — no hardware backing, no
  per-item AAD (attributes are in the clear and unbound), and that libsecret's
  sync calls block the platform thread.

## 1.0.0

- Initial release. Linux Secret Service (libsecret) plugin with a typed Dart
  facade. Stores each secret as a distinct Secret Service item keyed by its
  `slot` attribute (no shared blob), fails closed on a missing/locked keyring,
  and exposes `contains` / `add` (fail-if-exists) / `get` / `delete` /
  `deleteByPrefix`.
