## Unreleased

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
