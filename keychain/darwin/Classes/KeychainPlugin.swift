#if os(iOS)
import Flutter
#else
import FlutterMacOS
#endif
import Security

public class KeychainPlugin: NSObject, FlutterPlugin {
  public static func register(with registrar: FlutterPluginRegistrar) {
    #if os(iOS)
    let channel = FlutterMethodChannel(name: "keychain", binaryMessenger: registrar.messenger())
    #else
    let channel = FlutterMethodChannel(name: "keychain", binaryMessenger: registrar.messenger)
    #endif
    let instance = KeychainPlugin()
    registrar.addMethodCallDelegate(instance, channel: channel)
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    switch call.method {
    case "secItemAdd":
      handleSecItemAdd(call, result: result)
    case "secItemCopyMatching":
      handleSecItemCopyMatching(call, result: result)
    case "secItemDelete":
      handleSecItemDelete(call, result: result)
    case "keychainContains":
      handleKeychainContains(call, result: result)
    default:
      result(FlutterMethodNotImplemented)
    }
  }

  private func handleSecItemAdd(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    guard let args = call.arguments as? [String: Any],
          let alias = args["alias"] as? String,
          let data = args["data"] as? FlutterStandardTypedData else {
      result(FlutterError(code: "bad_args", message: "Missing alias or data.", details: nil))
      return
    }
    let service = args["service"] as? String
    let useDP = args["useDataProtection"] as? Bool ?? false
    let accessibility = SecAccessibility.fromDart(args["accessibility"] as? String)
    let status = SecItemAdd(alias: alias, service: service, useDataProtection: useDP, data: data.data, accessibility: accessibility)
    guard status == errSecSuccess else {
      result(FlutterError(code: "sec_item_add_failed", message: String(status), details: nil))
      return
    }
    result(nil)
  }

  private func handleKeychainContains(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    guard let args = call.arguments as? [String: Any],
          let alias = args["alias"] as? String else {
      result(FlutterError(code: "bad_args", message: "Missing alias.", details: nil))
      return
    }
    let service = args["service"] as? String
    let useDP = args["useDataProtection"] as? Bool ?? false
    result(SecItemExists(alias: alias, service: service, useDataProtection: useDP))
  }

  private func handleSecItemCopyMatching(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    guard let args = call.arguments as? [String: Any],
          let alias = args["alias"] as? String else {
      result(FlutterError(code: "bad_args", message: "Missing alias.", details: nil))
      return
    }
    let service = args["service"] as? String
    let useDP = args["useDataProtection"] as? Bool ?? false
    if let keyData = SecItemCopyMatching(alias: alias, service: service, useDataProtection: useDP) {
      result(FlutterStandardTypedData(bytes: keyData))
    } else {
      result(nil)
    }
  }

  private func handleSecItemDelete(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    guard let args = call.arguments as? [String: Any],
          let alias = args["alias"] as? String else {
      result(FlutterError(code: "bad_args", message: "Missing alias.", details: nil))
      return
    }
    let service = args["service"] as? String
    let useDP = args["useDataProtection"] as? Bool ?? false
    let status = SecItemDelete(alias: alias, service: service, useDataProtection: useDP)
    if status == errSecSuccess || status == errSecItemNotFound {
      result(nil)
    } else {
      result(FlutterError(code: "sec_item_delete_failed", message: String(status), details: nil))
    }
  }
}

private func keychainQuery(alias: String, service: String?, useDataProtection: Bool = false) -> [String: Any] {
  var query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccount as String: alias,
    kSecAttrSynchronizable as String: kCFBooleanFalse as Any
  ]
  if let service = service {
    query[kSecAttrService as String] = service
  }
  #if os(macOS)
  if useDataProtection, #available(macOS 10.15, *) {
    query[kSecUseDataProtectionKeychain as String] = true
  }
  #endif
  return query
}

private func keychainReadQuery(alias: String, service: String?, useDataProtection: Bool = false, returnData: Bool) -> [String: Any] {
  var query = keychainQuery(alias: alias, service: service, useDataProtection: useDataProtection)
  query[kSecMatchLimit as String] = kSecMatchLimitOne
  query[kSecReturnData as String] = returnData
  return query
}

private func SecItemCopyMatching(alias: String, service: String?, useDataProtection: Bool = false) -> Data? {
  let query = keychainReadQuery(alias: alias, service: service, useDataProtection: useDataProtection, returnData: true)
  var item: CFTypeRef?
  let status = Security.SecItemCopyMatching(query as CFDictionary, &item)
  guard status == errSecSuccess else { return nil }
  return item as? Data
}

private func SecItemExists(alias: String, service: String?, useDataProtection: Bool = false) -> Bool {
  let query = keychainReadQuery(alias: alias, service: service, useDataProtection: useDataProtection, returnData: false)
  let status = Security.SecItemCopyMatching(query as CFDictionary, nil)
  return status == errSecSuccess
}

private enum SecAccessibility {
  case whenUnlocked
  case whenUnlockedThisDeviceOnly
  case afterFirstUnlock
  case afterFirstUnlockThisDeviceOnly
  case whenPasscodeSetThisDeviceOnly

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

private func SecItemAdd(alias: String, service: String?, useDataProtection: Bool = false, data: Data, accessibility: CFString = kSecAttrAccessibleWhenUnlockedThisDeviceOnly) -> OSStatus {
  var matchQuery = keychainQuery(alias: alias, service: service, useDataProtection: useDataProtection)
  let attributes: [String: Any] = [kSecValueData as String: data]
  if SecItemExists(alias: alias, service: service, useDataProtection: useDataProtection) {
    return Security.SecItemUpdate(matchQuery as CFDictionary, attributes as CFDictionary)
  }
  matchQuery[kSecAttrAccessible as String] = accessibility
  matchQuery[kSecValueData as String] = data
  return Security.SecItemAdd(matchQuery as CFDictionary, nil)
}

private func SecItemDelete(alias: String, service: String?, useDataProtection: Bool = false) -> OSStatus {
  let query = keychainQuery(alias: alias, service: service, useDataProtection: useDataProtection)
  return Security.SecItemDelete(query as CFDictionary)
}
