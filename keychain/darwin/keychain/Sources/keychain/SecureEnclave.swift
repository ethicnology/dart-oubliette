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
struct EnclaveParams {
  let service: String?
  let accessibility: CFString
  let accessGroup: String?
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

func ensureEnclaveKeyPair(params: EnclaveParams) -> (SecKey, SecKey)? {
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
  var item: CFTypeRef?
  let fetchStatus = SecItemCopyMatching(fetchQuery as CFDictionary, &item)
  if fetchStatus == errSecSuccess, let ref = item {
    let privateKey = ref as! SecKey
    guard let publicKey = SecKeyCopyPublicKey(privateKey) else { return nil }
    return (privateKey, publicKey)
  }

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
  let attributes: [String: Any] = [
    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrKeySizeInBits as String: 256,
    kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
    kSecPrivateKeyAttrs as String: privateKeyAttrs as [String: Any]
  ]
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
