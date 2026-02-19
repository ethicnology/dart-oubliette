import Security

let serialQueue = DispatchQueue(label: "com.oubliette.keychain", qos: .userInitiated)

struct KeychainParams {
  let alias: String
  let service: String?
  let accessibility: CFString
  let useDataProtection: Bool
  let authenticationRequired: Bool
  let biometryCurrentSetOnly: Bool
  let authenticationPrompt: String?
  let secureEnclave: Bool
  let accessGroup: String?

  static func from(_ args: [String: Any]) -> KeychainParams? {
    guard let alias = args["alias"] as? String else { return nil }
    return KeychainParams(
      alias: alias,
      service: args["service"] as? String,
      accessibility: SecAccessibility.fromDart(args["accessibility"] as? String),
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
  static func fromDart(_ value: String?) -> CFString {
    switch value {
    case "whenUnlocked": return kSecAttrAccessibleWhenUnlocked
    case "afterFirstUnlock": return kSecAttrAccessibleAfterFirstUnlock
    case "afterFirstUnlockThisDeviceOnly": return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    case "whenPasscodeSetThisDeviceOnly": return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
    case "whenUnlockedThisDeviceOnly", nil: return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    default: return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    }
  }
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
  if params.useDataProtection, #available(macOS 10.15, *) {
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

func secItemExists(params: KeychainParams) -> Bool {
  let query = keychainReadQuery(params: params, returnData: false)
  let status = Security.SecItemCopyMatching(query as CFDictionary, nil)
  return status == errSecSuccess
}

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
  if let error = error?.takeRetainedValue() {
    NSLog("KeychainPlugin: Error creating access control: \(error.localizedDescription)")
    return nil
  }
  return accessControl
}

func secItemAdd(params: KeychainParams, data: Data) -> OSStatus {
  var dataToStore = data
  if params.secureEnclave {
    guard let (_, publicKey) = ensureEnclaveKeyPair(service: params.service) else {
      return errSecParam
    }
    guard let encrypted = enclaveEncrypt(data: data, publicKey: publicKey) else {
      return errSecParam
    }
    dataToStore = encrypted
  }
  var query = keychainQuery(params: params)
  if params.authenticationRequired, let accessControl = createAccessControl(params: params) {
    query[kSecAttrAccessControl as String] = accessControl
  } else {
    query[kSecAttrAccessible as String] = params.accessibility
  }
  query[kSecValueData as String] = dataToStore
  return Security.SecItemAdd(query as CFDictionary, nil)
}

func secItemDelete(params: KeychainParams) -> OSStatus {
  let query = keychainQuery(params: params)
  return Security.SecItemDelete(query as CFDictionary)
}
