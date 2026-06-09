## 1.0.0

- Initial release. Linux Secret Service (libsecret) plugin with a typed Dart
  facade. Stores each secret as a distinct Secret Service item keyed by its
  `slot` attribute (no shared blob), fails closed on a missing/locked keyring,
  and exposes `contains` / `add` (fail-if-exists) / `get` / `delete` /
  `deleteByPrefix`.
