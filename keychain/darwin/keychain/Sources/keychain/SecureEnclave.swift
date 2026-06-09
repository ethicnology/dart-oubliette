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

/// Fetches the EXISTING Secure Enclave key pair for [params], or returns nil if
/// none exists. It NEVER creates a key.
///
/// The read path uses this (not `ensureEnclaveKeyPair`) so that a missing SE
/// key — e.g. after a restore/migration that carried the ciphertext item but
/// not the non-exportable, non-migratable SE key — surfaces as a clear
/// "key missing" signal instead of silently minting a fresh key that cannot
/// decrypt the existing ciphertext (which would only fail later, opaquely, as a
/// decrypt error). No-silent-fallback: regenerating a key on read is a data
/// decision the library must not make.
func fetchEnclaveKeyPair(params: EnclaveParams) -> (SecKey, SecKey)? {
  guard let tag = enclaveKeyTag(params: params) else { return nil }
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
  if fetchStatus == errSecSuccess, let ref = item {
    let privateKey = ref as! SecKey
    guard let publicKey = SecKeyCopyPublicKey(privateKey) else { return nil }
    return (privateKey, publicKey)
  }
  return nil
}

func ensureEnclaveKeyPair(params: EnclaveParams) -> (SecKey, SecKey)? {
  // Fetch-or-create. Only init()/store() (the write paths) reach the create
  // branch; the read path uses `fetchEnclaveKeyPair` and never creates.
  if let existing = fetchEnclaveKeyPair(params: params) { return existing }

  guard let tag = enclaveKeyTag(params: params) else { return nil }

  var error: Unmanaged<CFError>?
  guard let access = SecAccessControlCreateWithFlags(
    nil,
    params.accessibility,
    .privateKeyUsage,
    &error
  ) else { return nil }

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

/// Returns `true` if a Secure Enclave key with this scoping already exists.
func enclaveKeyExists(params: EnclaveParams) -> Bool {
  guard let tag = enclaveKeyTag(params: params) else { return false }
  var fetchQuery: [String: Any] = [
    kSecClass as String: kSecClassKey,
    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrApplicationTag as String: tag,
    kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
    kSecReturnRef as String: false
  ]
  if let group = params.accessGroup {
    fetchQuery[kSecAttrAccessGroup as String] = group
  }
  applyEnclaveDataProtection(&fetchQuery, params)
  return SecItemCopyMatching(fetchQuery as CFDictionary, nil) == errSecSuccess
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
