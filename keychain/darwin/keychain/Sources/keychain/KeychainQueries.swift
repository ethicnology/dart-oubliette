import Foundation
import Security

/// PROCESS-GLOBAL (file-scope `let`, not a plugin-instance property): every
/// Flutter engine in the process — add-to-app, multi-window macOS — funnels
/// through this one queue, so an exists-probe and an add can never interleave
/// across engines. Two limits remain: (1) a read that raises an auth prompt
/// holds the queue until the user responds — every other keychain op in the
/// process waits behind the dialog (deliberate: nothing may mutate state mid
/// auth); (2) the queue cannot serialize against *other processes* (an app
/// extension sharing an access group) — that residual race is inherent to the
/// keychain API and is why writes fail closed on `errSecDuplicateItem`.
let serialQueue = DispatchQueue(label: "com.oubliette.keychain", qos: .userInitiated)

extension Data {
  /// Best-effort in-place zeroing of the backing bytes.
  ///
  /// IMPORTANT: this only scrubs the secret when the receiver *uniquely* owns
  /// its storage. `withUnsafeMutableBytes` is `mutating`, so on a `Data` whose
  /// buffer is shared, Swift copy-on-write hands it a fresh copy and zeroes
  /// *that* — leaving the shared original intact. A buffer becomes shared the
  /// moment it is bridged into a query dictionary (`kSecValueData`) or into a
  /// `FlutterStandardTypedData` (whose `initWithData:` does `[data copy]`, a
  /// retain for immutable `NSData`). So wiping *after* handing the bytes to
  /// SecItemAdd or to Flutter is effectively a no-op for the copy that
  /// survives. Wiping a not-yet-shared, uniquely-owned buffer (e.g. an
  /// intermediate before it reaches a query) does work. This matches the
  /// "zeroing is best-effort; method-channel copies persist" stance in
  /// SECURITY.md — do not treat post-handoff wipes as a guarantee.
  mutating func wipe() {
    withUnsafeMutableBytes { ptr in
      if let base = ptr.baseAddress {
        base.initializeMemory(as: UInt8.self, repeating: 0, count: ptr.count)
      }
    }
  }
}

// `@unchecked Sendable`: an immutable (all-`let`) value type carried into the
// `serialQueue.async` workers. Every stored field is Sendable except
// `accessibility`, a `CFString` that is always one of the immutable,
// process-global `kSecAttrAccessible*` constants (thread-safe to share). Swift 6
// strict concurrency cannot prove that for CFString, so we assert it here.
struct KeychainParams: @unchecked Sendable {
  let alias: String
  let service: String?
  let accessibility: CFString
  let useDataProtection: Bool
  let authenticationRequired: Bool
  let biometryCurrentSetOnly: Bool
  let authenticationPrompt: String?
  let secureEnclave: Bool
  let accessGroup: String?

  /// The subset of scoping inputs that identify the Secure Enclave key.
  var enclaveParams: EnclaveParams {
    EnclaveParams(
      service: service,
      accessibility: accessibility,
      accessGroup: accessGroup,
      useDataProtection: useDataProtection
    )
  }

  static func from(_ args: [String: Any]) -> KeychainParams? {
    guard let alias = args["alias"] as? String,
          let accessibility = SecAccessibility.fromDart(args["accessibility"] as? String) else {
      return nil
    }
    return KeychainParams(
      alias: alias,
      service: args["service"] as? String,
      accessibility: accessibility,
      useDataProtection: args["useDataProtection"] as? Bool ?? false,
      authenticationRequired: args["authenticationRequired"] as? Bool ?? false,
      biometryCurrentSetOnly: args["biometryCurrentSetOnly"] as? Bool ?? false,
      authenticationPrompt: args["authenticationPrompt"] as? String,
      secureEnclave: args["secureEnclave"] as? Bool ?? false,
      accessGroup: args["accessGroup"] as? String
    )
  }
}

enum SecAccessibility {
  /// `nil` input (argument omitted) keeps the strict default; an *unknown*
  /// string returns `nil` so the caller fails with `bad_args` instead of the
  /// plugin silently picking an accessibility class on the caller's behalf.
  static func fromDart(_ value: String?) -> CFString? {
    switch value {
    case "whenUnlocked": return kSecAttrAccessibleWhenUnlocked
    case "afterFirstUnlock": return kSecAttrAccessibleAfterFirstUnlock
    case "afterFirstUnlockThisDeviceOnly": return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    case "whenPasscodeSetThisDeviceOnly": return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
    case "whenUnlockedThisDeviceOnly", nil: return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    default: return nil
    }
  }

  /// The accessibility classes compatible with a Secure Enclave key: the key
  /// is hardware-bound to this device, so pairing it with a syncable /
  /// backup-restorable item class is incoherent (and SE key generation would
  /// fail with an opaque errSecParam anyway).
  static let secureEnclaveCompatible: Set<String> = [
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String,
    kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String,
    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly as String,
  ]
}

/// Human-readable status for error messages (numeric code kept for matching).
func secErrorMessage(_ status: OSStatus) -> String {
  if let message = SecCopyErrorMessageString(status, nil) as String? {
    return "\(status): \(message)"
  }
  return String(status)
}


func keychainQuery(params: KeychainParams) -> [String: Any] {
  var query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: params.alias,
    // Deliberately disable iCloud Keychain sync. Secrets (e.g. mnemonic
    // phrases) must remain device-local to prevent cloud-based exfiltration.
    // This also ensures items are not silently migrated across devices during
    // iCloud restore.
    kSecAttrSynchronizable as String: kCFBooleanFalse as Any
  ]
  if let service = params.service {
    query[kSecAttrService as String] = service
  }
  if let group = params.accessGroup {
    query[kSecAttrAccessGroup as String] = group
  }
  #if os(macOS)
  if params.useDataProtection {
    query[kSecUseDataProtectionKeychain as String] = true
  }
  #endif
  return query
}

func keychainReadQuery(params: KeychainParams, returnData: Bool) -> [String: Any] {
  var query = keychainQuery(params: params)
  query[kSecMatchLimit as String] = kSecMatchLimitOne
  query[kSecReturnData as String] = returnData
  return query
}

/// Existence probe. Returns the raw status so the caller can distinguish
/// "absent" (errSecItemNotFound) from an *error* (entitlement, locked
/// keychain, …) — collapsing every non-success status to "not present" would
/// silently misreport a failing keychain as an empty one.
/// `kSecUseAuthenticationUIFail` guarantees the probe can never raise an auth
/// prompt for an access-controlled item.
///
/// DEPRECATION NOTE: `kSecUseAuthenticationUIFail` is deprecated (iOS 14 /
/// macOS 11) in favor of `kSecUseAuthenticationContext` with
/// `LAContext.interactionNotAllowed = true`. It is retained deliberately: the
/// replacement attaches an LAContext to the query, whose behavior on the
/// legacy file-based macOS keychain (this probe also runs for profiles with
/// `useDataProtection: false`) is not documented, while the deprecated
/// constant remains functional and well-defined on both keychains. Do NOT
/// "modernize" to `kSecUseAuthenticationUISkip` — that silently *excludes*
/// auth-protected items from matching, turning an existing secret into a
/// false "not present" (the exact misreport this tri-state probe exists to
/// prevent). Revisit only if the constant is removed from the SDK.
func secItemExistsStatus(params: KeychainParams) -> OSStatus {
  var query = keychainReadQuery(params: params, returnData: false)
  query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUIFail
  return Security.SecItemCopyMatching(query as CFDictionary, nil)
}

/// Builds the `SecAccessControl` for an authenticated item.
///
/// `.biometryCurrentSet` invalidates the item when the biometric enrollment
/// changes (the "fatal" profile); `.userPresence` accepts biometry OR the
/// device passcode and survives enrollment changes. The accessibility class is
/// paired in by the caller via `params.accessibility`.
///
/// Note the "fatal" (`biometryCurrentSetOnly`) path is biometry-ONLY: it rejects
/// the device passcode as a fallback. If biometry later becomes unavailable
/// (no enrolled faces/fingers, hardware disabled), the item is permanently
/// unreadable. This is the intended fatal semantic — it couples biometry-only
/// presence with enrollment invalidation into a single profile.
///
/// Returns `nil` on failure (the caller fails closed). We key off the returned
/// optional — not merely a set error — because the result is the authoritative
/// success signal, and we drain `error` so the CFError is never leaked.
func createAccessControl(params: KeychainParams) -> SecAccessControl? {
  let flags: SecAccessControlCreateFlags = params.biometryCurrentSetOnly
    ? .biometryCurrentSet
    : .userPresence
  var error: Unmanaged<CFError>?
  let accessControl = SecAccessControlCreateWithFlags(
    nil,
    params.accessibility,
    flags,
    &error
  )
  guard let accessControl = accessControl else {
    if let error = error?.takeRetainedValue() {
      NSLog("KeychainPlugin: Error creating access control: \(error.localizedDescription)")
    }
    return nil
  }
  return accessControl
}

/// Outcome of a write. The Secure-Enclave and access-control preparation steps
/// have their own failure cases so the caller can report a distinct, actionable
/// error instead of collapsing every failure to a bare `errSecParam` (-50) —
/// which would conflate "SE encryption failed" with "malformed keychain query".
/// This mirrors the read path's granular `se_*` codes.
enum SecItemAddResult {
  /// The keychain `SecItemAdd` ran; `status` is its raw OSStatus (which the
  /// caller maps, e.g. `errSecDuplicateItem` → `already_exists`).
  case completed(OSStatus)
  /// The Secure Enclave key could not be fetched-or-created before encrypting.
  case enclaveKeyUnavailable
  /// Secure Enclave encryption of the plaintext failed.
  case enclaveEncryptFailed
  /// `authenticationRequired` was set but the `SecAccessControl` could not be
  /// created — never fall through to an un-gated item the caller believes is
  /// auth-protected.
  case accessControlFailed
}

/// Validates the cross-field coherence of an add request *before* anything is
/// stored. Returns a stable error code when the combination is incoherent
/// (fail-closed), or `nil` when the request may proceed.
///
/// `biometryCurrentSetOnly` selects the `.biometryCurrentSet` access-control
/// flag, but that flag is only ever applied when `authenticationRequired` is
/// also true (see `secItemAdd`: the access control is built only on the
/// authenticated branch). With `authenticationRequired == false` the item is
/// stored with a plain `kSecAttrAccessible` and **no** access control — silently
/// dropping the strict biometry-only gate the caller asked for. That is a
/// fail-OPEN against intent (the strictest-sounding flag yields the weakest
/// item), so reject it rather than store an unauthenticated item.
func secItemAddParamsError(_ params: KeychainParams) -> String? {
  if params.biometryCurrentSetOnly && !params.authenticationRequired {
    return "biometry_requires_authentication"
  }
  return nil
}

func secItemAdd(params: KeychainParams, data: Data) -> SecItemAddResult {
  // Own a mutable copy so we can zero it afterwards without mutating the
  // caller-owned (and possibly immutable) FlutterStandardTypedData buffer.
  var dataToStore = Data(data)
  if params.secureEnclave {
    guard let (_, publicKey) = ensureEnclaveKeyPair(params: params.enclaveParams) else {
      dataToStore.wipe()
      return .enclaveKeyUnavailable
    }
    guard let encrypted = enclaveEncrypt(data: dataToStore, publicKey: publicKey) else {
      dataToStore.wipe()
      return .enclaveEncryptFailed
    }
    dataToStore.wipe()        // drop the plaintext copy; store ciphertext
    dataToStore = encrypted
  }
  var query = keychainQuery(params: params)
  if params.authenticationRequired {
    // Fail closed: auth was requested but the access control could not be
    // created. Never fall through to a plain kSecAttrAccessible item that the
    // caller believes is auth-gated.
    guard let accessControl = createAccessControl(params: params) else {
      dataToStore.wipe()
      return .accessControlFailed
    }
    query[kSecAttrAccessControl as String] = accessControl
  } else {
    query[kSecAttrAccessible as String] = params.accessibility
  }
  query[kSecValueData as String] = dataToStore
  let status = Security.SecItemAdd(query as CFDictionary, nil)
  dataToStore.wipe()
  return .completed(status)
}

func secItemDelete(params: KeychainParams) -> OSStatus {
  let query = keychainQuery(params: params)
  return Security.SecItemDelete(query as CFDictionary)
}

/// The account-independent subset of a keychain query — used to enumerate a
/// whole profile (every account under a service/group), not a single item.
struct KeychainScope {
  let service: String?
  let accessGroup: String?
  let useDataProtection: Bool
}

/// Deletes every generic-password item in [scope] whose `kSecAttrAccount`
/// starts with [prefix] but with **none** of [excludePrefixes].
///
/// [excludePrefixes] is an optional belt-and-suspenders exclusion list. The
/// oubliette layer no longer needs it: it passes `prefix + U+001D` (the slot
/// separator), and since that separator can only appear at the prefix/key
/// boundary, ownership is already exact — wiping `authenticated_<sep>` cannot
/// match `authenticated_fatal_<sep>` items. The parameter is retained for
/// callers that want additional sibling exclusions.
///
/// Keychain has no prefix-match predicate, so we enumerate the accounts in
/// scope and delete the matching ones individually. Returns `errSecSuccess`
/// when at least one item was deleted, `errSecItemNotFound` when nothing
/// matched (a clean no-op for a wipe), or the first failing delete status.
func secItemDeleteByPrefix(
  scope: KeychainScope,
  prefix: String,
  excludePrefixes: [String] = []
) -> OSStatus {
  var listQuery: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
    kSecMatchLimit as String: kSecMatchLimitAll,
    kSecReturnAttributes as String: true
  ]
  if let service = scope.service {
    listQuery[kSecAttrService as String] = service
  }
  if let group = scope.accessGroup {
    listQuery[kSecAttrAccessGroup as String] = group
  }
  #if os(macOS)
  if scope.useDataProtection {
    listQuery[kSecUseDataProtectionKeychain as String] = true
  }
  #endif

  var items: CFTypeRef?
  let listStatus = Security.SecItemCopyMatching(listQuery as CFDictionary, &items)
  if listStatus == errSecItemNotFound { return errSecItemNotFound }
  guard listStatus == errSecSuccess, let entries = items as? [[String: Any]] else {
    return listStatus
  }

  var deletedAny = false
  for entry in entries {
    guard let account = entry[kSecAttrAccount as String] as? String,
          account.hasPrefix(prefix),
          !excludePrefixes.contains(where: { account.hasPrefix($0) }) else { continue }
    var deleteQuery: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrAccount as String: account,
      kSecAttrSynchronizable as String: kCFBooleanFalse as Any
    ]
    if let service = scope.service {
      deleteQuery[kSecAttrService as String] = service
    }
    if let group = scope.accessGroup {
      deleteQuery[kSecAttrAccessGroup as String] = group
    }
    #if os(macOS)
    if scope.useDataProtection {
      deleteQuery[kSecUseDataProtectionKeychain as String] = true
    }
    #endif
    let status = Security.SecItemDelete(deleteQuery as CFDictionary)
    if status != errSecSuccess && status != errSecItemNotFound {
      return status
    }
    deletedAny = true
  }
  return deletedAny ? errSecSuccess : errSecItemNotFound
}

/// Lists the `kSecAttrAccount` of every generic-password item in [scope] whose
/// account starts with [prefix] but with **none** of [excludePrefixes].
///
/// The non-destructive twin of `secItemDeleteByPrefix`: identical enumeration
/// query (`kSecMatchLimitAll` + `kSecReturnAttributes`), but it collects the
/// matching account names instead of deleting them. Returns only account names
/// (the storage keys) — never `kSecReturnData`, so no item value is read or
/// decrypted. Returns `(errSecSuccess, accounts)` on a hit, `(errSecItemNotFound,
/// [])` when nothing matched, or `(status, [])` when the enumeration failed.
func secItemListByPrefix(
  scope: KeychainScope,
  prefix: String,
  excludePrefixes: [String] = []
) -> (OSStatus, [String]) {
  var listQuery: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
    kSecMatchLimit as String: kSecMatchLimitAll,
    kSecReturnAttributes as String: true
  ]
  if let service = scope.service {
    listQuery[kSecAttrService as String] = service
  }
  if let group = scope.accessGroup {
    listQuery[kSecAttrAccessGroup as String] = group
  }
  #if os(macOS)
  if scope.useDataProtection {
    listQuery[kSecUseDataProtectionKeychain as String] = true
  }
  #endif

  var items: CFTypeRef?
  let listStatus = Security.SecItemCopyMatching(listQuery as CFDictionary, &items)
  if listStatus == errSecItemNotFound { return (errSecItemNotFound, []) }
  guard listStatus == errSecSuccess, let entries = items as? [[String: Any]] else {
    return (listStatus, [])
  }

  var accounts: [String] = []
  for entry in entries {
    guard let account = entry[kSecAttrAccount as String] as? String,
          account.hasPrefix(prefix),
          !excludePrefixes.contains(where: { account.hasPrefix($0) }) else { continue }
    accounts.append(account)
  }
  return (errSecSuccess, accounts)
}
