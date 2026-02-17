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
          let params = KeychainParams.from(args),
          let data = args["data"] as? FlutterStandardTypedData else {
      result(FlutterError(code: "bad_args", message: "Missing alias or data.", details: nil))
      return
    }
    serialQueue.async {
      let status = secItemAdd(params: params, data: data.data)
      DispatchQueue.main.async {
        guard status == errSecSuccess else {
          result(FlutterError(code: "sec_item_add_failed", message: String(status), details: nil))
          return
        }
        result(nil)
      }
    }
  }

  private func handleKeychainContains(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    guard let args = call.arguments as? [String: Any],
          let params = KeychainParams.from(args) else {
      result(FlutterError(code: "bad_args", message: "Missing alias.", details: nil))
      return
    }
    serialQueue.async {
      let exists = secItemExists(params: params)
      DispatchQueue.main.async {
        result(exists)
      }
    }
  }

  private func handleSecItemCopyMatching(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    guard let args = call.arguments as? [String: Any],
          let params = KeychainParams.from(args) else {
      result(FlutterError(code: "bad_args", message: "Missing alias.", details: nil))
      return
    }
    serialQueue.async {
      var query = keychainReadQuery(params: params, returnData: true)
      if let prompt = params.authenticationPrompt {
        query[kSecUseOperationPrompt as String] = prompt
      }
      var item: CFTypeRef?
      let status = Security.SecItemCopyMatching(query as CFDictionary, &item)
      DispatchQueue.main.async {
        switch status {
        case errSecSuccess:
          guard var rawData = item as? Data else {
            result(nil)
            return
          }
          if params.secureEnclave {
            guard let (privateKey, _) = ensureEnclaveKeyPair(service: params.service),
                  var plaintext = enclaveDecrypt(data: rawData, privateKey: privateKey) else {
              rawData.withUnsafeMutableBytes { ptr in
                if let base = ptr.baseAddress {
                  base.initializeMemory(as: UInt8.self, repeating: 0, count: ptr.count)
                }
              }
              result(FlutterError(code: "se_decrypt_failed", message: "Secure Enclave decryption failed.", details: nil))
              return
            }
            rawData.withUnsafeMutableBytes { ptr in
              if let base = ptr.baseAddress {
                base.initializeMemory(as: UInt8.self, repeating: 0, count: ptr.count)
              }
            }
            result(FlutterStandardTypedData(bytes: plaintext))
            plaintext.withUnsafeMutableBytes { ptr in
              if let base = ptr.baseAddress {
                base.initializeMemory(as: UInt8.self, repeating: 0, count: ptr.count)
              }
            }
          } else {
            result(FlutterStandardTypedData(bytes: rawData))
            rawData.withUnsafeMutableBytes { ptr in
              if let base = ptr.baseAddress {
                base.initializeMemory(as: UInt8.self, repeating: 0, count: ptr.count)
              }
            }
          }
        case errSecItemNotFound:
          result(nil)
        case errSecUserCanceled:
          result(FlutterError(code: "auth_cancelled", message: "User cancelled authentication.", details: nil))
        case errSecAuthFailed:
          result(FlutterError(code: "auth_failed", message: "Authentication failed.", details: nil))
        case errSecInteractionNotAllowed:
          result(FlutterError(code: "interaction_not_allowed", message: "Keychain interaction not allowed (device locked?).", details: nil))
        default:
          result(FlutterError(code: "sec_item_copy_failed", message: String(status), details: nil))
        }
      }
    }
  }

  private func handleSecItemDelete(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    guard let args = call.arguments as? [String: Any],
          let params = KeychainParams.from(args) else {
      result(FlutterError(code: "bad_args", message: "Missing alias.", details: nil))
      return
    }
    serialQueue.async {
      let status = secItemDelete(params: params)
      DispatchQueue.main.async {
        if status == errSecSuccess || status == errSecItemNotFound {
          result(nil)
        } else {
          result(FlutterError(code: "sec_item_delete_failed", message: String(status), details: nil))
        }
      }
    }
  }
}
