import Foundation
import Security

// ECIES with a per-message variable IV — the variant Apple recommends for new
// code (the fixed-IV `…CofactorX963SHA256AESGCM` is now "legacy"). One shared
// constant drives both encrypt and decrypt, so the choice is symmetric. (The
// fixed-IV variant was not exploitable here — ECIES derives a fresh ephemeral
// key per message — but this is the current-recommended primitive.)
let enclaveAlgorithm = SecKeyAlgorithm.eciesEncryptionCofactorVariableIVX963SHA256AESGCM

/// Everything that scopes a Secure Enclave key. Two keys with different
/// scoping must never share a tag, and changing any field must regenerate the
/// key rather than silently reuse an old policy.
///
/// `useDataProtection` is deliberately NOT part of the key identity (it is
/// excluded from `enclaveKeyTag`): it selects which macOS keychain *domain* the
/// SE-key SecItem queries target so they match the item's domain (the item path
/// sets `kSecUseDataProtectionKeychain` on macOS) — it is not a scoping input.
/// It defaults to `false` so the SE tag-regression tests can omit it.
struct EnclaveParams {
  let service: String?
  let accessibility: CFString
  let accessGroup: String?
  let useDataProtection: Bool

  init(
    service: String?,
    accessibility: CFString,
    accessGroup: String?,
    useDataProtection: Bool = false
  ) {
    self.service = service
    self.accessibility = accessibility
    self.accessGroup = accessGroup
    self.useDataProtection = useDataProtection
  }
}

/// On macOS, target the same keychain domain as the generic-password item (the
/// item path sets `kSecUseDataProtectionKeychain` when the profile asks for the
/// data-protection keychain). Without this, an SE-key query relies on the
/// SecItem shim's default routing, which can diverge from where the item lives
/// — Apple's TN3137 guidance is to target the data-protection keychain
/// explicitly. No-op on iOS (always the data-protection keychain there).
func applyEnclaveDataProtection(_ query: inout [String: Any], _ params: EnclaveParams) {
  #if os(macOS)
  if params.useDataProtection, #available(macOS 10.15, *) {
    query[kSecUseDataProtectionKeychain as String] = true
  }
  #endif
}

/// Builds a collision-free application tag from every scoping input.
///
/// Components are length-prefixed so no value can forge another's boundary,
/// and `nil` is encoded distinctly from `""` and from `"default"` — the old
/// `service ?? "default"` form conflated `service=nil` with `service="default"`.
/// Accessibility is included so a profile that changes its accessibility gets a
/// fresh key instead of reusing the previous (possibly weaker) policy.
func enclaveKeyTag(params: EnclaveParams) -> Data? {
  func part(_ label: String, _ value: String?) -> String {
    guard let value = value else { return "\(label):-" }
    return "\(label):\(value.count):\(value)"
  }
  let components = [
    "v1",
    part("s", params.service),
    "a:\(params.accessibility as String)",
    part("g", params.accessGroup),
  ]
  return ("com.oubliette.enclave." + components.joined(separator: "|")).data(using: .utf8)
}

/// Outcome of looking up the profile's Secure Enclave key. `missing` and
/// `failure` are deliberately distinct: "the key does not exist" leads the
/// Dart layer to a data-destroying recovery (purge + re-entry), while a fetch
/// *error* (entitlement, keychain-domain misrouting, transient ref failure)
/// must never be reported as key loss — the key may be perfectly intact.
enum EnclaveKeyFetch {
  case found(SecKey, SecKey)
  case missing
  case failure(OSStatus)
}

/// Fetches the EXISTING Secure Enclave key pair for [params]. It NEVER creates
/// a key.
///
/// The read path uses this (not `ensureEnclaveKeyPair`) so that a missing SE
/// key — e.g. after a restore/migration that carried the ciphertext item but
/// not the non-exportable, non-migratable SE key — surfaces as a clear
/// "key missing" signal instead of silently minting a fresh key that cannot
/// decrypt the existing ciphertext (which would only fail later, opaquely, as a
/// decrypt error). No-silent-fallback: regenerating a key on read is a data
/// decision the library must not make.
func fetchEnclaveKeyPair(params: EnclaveParams) -> EnclaveKeyFetch {
  guard let tag = enclaveKeyTag(params: params) else { return .failure(errSecParam) }
  var fetchQuery: [String: Any] = [
    kSecClass as String: kSecClassKey,
    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrApplicationTag as String: tag,
    kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
    kSecReturnRef as String: true
  ]
  if let group = params.accessGroup {
    fetchQuery[kSecAttrAccessGroup as String] = group
  }
  applyEnclaveDataProtection(&fetchQuery, params)
  var item: CFTypeRef?
  let fetchStatus = SecItemCopyMatching(fetchQuery as CFDictionary, &item)
  switch fetchStatus {
  case errSecSuccess:
    // `as?` not `as!`: a success status with a ref of an unexpected type is a
    // backend anomaly, not key loss — report it as a fetch *failure* (which the
    // Dart layer treats as recoverable) rather than trapping the process.
    guard let item = item, CFGetTypeID(item) == SecKeyGetTypeID() else {
      return .failure(errSecInvalidKeyRef)
    }
    let privateKey = item as! SecKey
    guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
      // Key present but the public-key ref could not be derived — an error,
      // not key loss.
      return .failure(errSecInvalidKeyRef)
    }
    return .found(privateKey, publicKey)
  case errSecItemNotFound:
    return .missing
  default:
    return .failure(fetchStatus)
  }
}

func ensureEnclaveKeyPair(params: EnclaveParams) -> (SecKey, SecKey)? {
  // Fetch-or-create. Only init()/store() (the write paths) reach the create
  // branch; the read path uses `fetchEnclaveKeyPair` and never creates.
  switch fetchEnclaveKeyPair(params: params) {
  case .found(let privateKey, let publicKey):
    return (privateKey, publicKey)
  case .failure(let status):
    // Create ONLY when the key is verifiably absent. Creating on a *failed*
    // fetch could mint a second permanent key under the same tag (after which
    // fetch order between the two is unspecified) and strand existing
    // ciphertext — the same hazard the read path is hardened against.
    NSLog("KeychainPlugin: SE key fetch failed (\(secErrorMessage(status))); refusing to create")
    return nil
  case .missing:
    return createEnclaveKeyPair(params: params)
  }
}

/// Generates a NEW permanent Secure Enclave key pair for [params].
///
/// Callers must have already established the key is verifiably absent (a
/// `.missing` from `fetchEnclaveKeyPair`) — creating over an existing tag
/// mints a second permanent key with unspecified fetch order between the two
/// (see `ensureEnclaveKeyPair`). All callers run on `serialQueue`, so the
/// absence check and the create are atomic within this process.
func createEnclaveKeyPair(params: EnclaveParams) -> (SecKey, SecKey)? {
  guard let tag = enclaveKeyTag(params: params) else { return nil }

  var error: Unmanaged<CFError>?
  guard let access = SecAccessControlCreateWithFlags(
    nil,
    params.accessibility,
    .privateKeyUsage,
    &error
  ) else {
    if let err = error?.takeRetainedValue() {
      NSLog("KeychainPlugin: SE access control creation failed: \(err.localizedDescription)")
    }
    return nil
  }

  var privateKeyAttrs: [String: Any] = [
    kSecAttrIsPermanent as String: true,
    kSecAttrApplicationTag as String: tag,
    kSecAttrAccessControl as String: access
  ]
  if let group = params.accessGroup {
    privateKeyAttrs[kSecAttrAccessGroup as String] = group
  }
  var attributes: [String: Any] = [
    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrKeySizeInBits as String: 256,
    kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
    kSecPrivateKeyAttrs as String: privateKeyAttrs as [String: Any]
  ]
  // Generate into the same keychain domain the fetch/read uses (macOS).
  applyEnclaveDataProtection(&attributes, params)
  guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
    if let err = error?.takeRetainedValue() {
      NSLog("KeychainPlugin: SE key generation failed: \(err.localizedDescription)")
    }
    return nil
  }
  guard let publicKey = SecKeyCopyPublicKey(privateKey) else { return nil }
  return (privateKey, publicKey)
}

func enclaveEncrypt(data: Data, publicKey: SecKey) -> Data? {
  var error: Unmanaged<CFError>?
  guard let ciphertext = SecKeyCreateEncryptedData(publicKey, enclaveAlgorithm, data as CFData, &error) else {
    if let err = error?.takeRetainedValue() {
      NSLog("KeychainPlugin: SE encrypt failed: \(err.localizedDescription)")
    }
    return nil
  }
  return ciphertext as Data
}

func enclaveDecrypt(data: Data, privateKey: SecKey) -> Data? {
  var error: Unmanaged<CFError>?
  guard let plaintext = SecKeyCreateDecryptedData(privateKey, enclaveAlgorithm, data as CFData, &error) else {
    if let err = error?.takeRetainedValue() {
      NSLog("KeychainPlugin: SE decrypt failed: \(err.localizedDescription)")
    }
    return nil
  }
  return plaintext as Data
}
