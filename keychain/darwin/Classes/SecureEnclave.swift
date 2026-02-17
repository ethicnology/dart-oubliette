import Security

let enclaveAlgorithm = SecKeyAlgorithm.eciesEncryptionCofactorX963SHA256AESGCM

func enclaveKeyTag(service: String?) -> Data? {
  let tag = "com.oubliette.se.\(service ?? "default")"
  return tag.data(using: .utf8)
}

func ensureEnclaveKeyPair(service: String?) -> (SecKey, SecKey)? {
  guard let tag = enclaveKeyTag(service: service) else { return nil }

  let fetchQuery: [String: Any] = [
    kSecClass as String: kSecClassKey,
    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrApplicationTag as String: tag,
    kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
    kSecReturnRef as String: true
  ]
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
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    .privateKeyUsage,
    &error
  ) else { return nil }

  let attributes: [String: Any] = [
    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrKeySizeInBits as String: 256,
    kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
    kSecPrivateKeyAttrs as String: [
      kSecAttrIsPermanent as String: true,
      kSecAttrApplicationTag as String: tag,
      kSecAttrAccessControl as String: access
    ] as [String: Any]
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
