## Unreleased

- Bound EVERY interactive-unlock-capable sync call with the ~20 s watchdog, not
  just the warmup unlock. The per-operation `lookup`/`store`/`clear`/`search`/
  per-item `delete` calls previously passed a `nullptr` `GCancellable`, so a
  keyring that re-locked (daemon restart) between the warmup and the operation —
  or an item in another locked collection reached via `SECRET_SEARCH_UNLOCK` —
  could re-prompt and hang the platform (GTK main) thread forever. A reusable
  `armed_timeout_cancellable()` (the warmup's detached-timer pattern, extracted)
  now backs all of them; a timed-out call fails closed (`secret_service_error`),
  never blocks indefinitely, and is never read as empty/absent.
- Clarified the threat model on heap zeroization: the native plugin already wipes
  every secret buffer it owns (`secret_password_free` over secure memory) — this
  was not a residual gap. The un-wiped copies are the method-channel transit ones
  (engine codec, `FlValue`, Dart `String`/`Uint8List`), which the native layer
  cannot control and Dart's GC cannot reliably zero. README updated to credit the
  native wiping and pin the boundary precisely rather than implying nothing is
  wiped.
- Scope per-slot lookups to this app's items. `contains`/`read`/`write`'s
  duplicate check and `delete` now match BOTH the `slot` and `fmt=v1`
  attributes (previously `slot` alone). Because the schema is
  `SECRET_SCHEMA_NONE` (libsecret does not match the `xdg:schema` name), a
  foreign item that merely reused an attribute named `slot` could otherwise be
  read as — or deleted as — one of ours. All items this plugin ever stored
  carry `fmt=v1`, so this matches every legitimate item (no orphaning) and
  closes the cross-app collision/clobber gap. Corrected the stale comment that
  claimed `SECRET_SCHEMA_NONE` matches the schema name (it does the opposite).
- README: documented the transport session honestly (DH-encrypted when the
  provider supports it, `plain` fallback otherwise; neither protects against the
  daemon or same-uid processes) and that app scoping is carried by the `fmt`
  attribute rather than the schema name.
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
