#if os(iOS)
import Flutter
#else
import FlutterMacOS
#endif
import Foundation
import LocalAuthentication
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
    case "secItemDeleteByPrefix":
      handleSecItemDeleteByPrefix(call, result: result)
    case "keychainContains":
      handleKeychainContains(call, result: result)
    case "ensureEnclaveKeyPair":
      handleEnsureEnclaveKeyPair(call, result: result)
    default:
      result(FlutterError(code: "not_implemented", message: "\(call.method) is not implemented.", details: nil))
    }
  }

  private func handleSecItemAdd(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    guard let args = call.arguments as? [String: Any],
          let params = KeychainParams.from(args),
          let data = args["data"] as? FlutterStandardTypedData else {
      result(FlutterError(code: "bad_args", message: "Missing alias/data or unknown accessibility.", details: nil))
      return
    }
    // A Secure Enclave key is hardware-bound to this device; pairing it with a
    // syncable / backup-restorable item class is incoherent and SE access
    // control creation would fail as an opaque -50. Reject with a clear code.
    if params.secureEnclave,
       !SecAccessibility.secureEnclaveCompatible.contains(params.accessibility as String) {
      result(FlutterError(
        code: "se_requires_device_only_accessibility",
        message: "secureEnclave requires a *ThisDeviceOnly accessibility class.",
        details: nil))
      return
    }
    #if os(macOS)
    // The legacy file-based macOS keychain rejects kSecAttrAccessControl
    // (SecItemAdd → errSecParam). Surface an actionable error instead of a bare
    // "-50". Authentication on macOS requires the data-protection keychain.
    if params.authenticationRequired && !params.useDataProtection {
      result(FlutterError(
        code: "macos_auth_requires_data_protection",
        message: "On macOS, authenticationRequired needs useDataProtection: true "
          + "(the data-protection keychain) plus code signing and the "
          + "keychain-access-groups entitlement. The legacy file-based keychain "
          + "cannot enforce access control.",
        details: nil))
      return
    }
    #endif
    serialQueue.async {
      let outcome = secItemAdd(params: params, data: data.data)
      DispatchQueue.main.async {
        switch outcome {
        case .completed(let status) where status == errSecSuccess:
          result(nil)
        case .completed(let status) where status == errSecDuplicateItem:
          result(FlutterError(code: "already_exists", message: "A value already exists for this key.", details: nil))
        case .completed(let status):
          result(FlutterError(code: "sec_item_add_failed", message: secErrorMessage(status), details: nil))
        case .enclaveKeyUnavailable:
          // Distinct from a keychain error: the SE key could not be
          // fetched-or-created, so nothing was stored.
          result(FlutterError(code: "se_key_gen_failed", message: "Could not ensure the Secure Enclave key pair.", details: nil))
        case .enclaveEncryptFailed:
          result(FlutterError(code: "se_encrypt_failed", message: "Secure Enclave encryption failed.", details: nil))
        case .accessControlFailed:
          result(FlutterError(code: "access_control_failed", message: "Could not create the access control policy for an authenticated item.", details: nil))
        }
      }
    }
  }

  private func handleKeychainContains(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    guard let args = call.arguments as? [String: Any],
          let params = KeychainParams.from(args) else {
      result(FlutterError(code: "bad_args", message: "Missing alias or unknown accessibility.", details: nil))
      return
    }
    serialQueue.async {
      let status = secItemExistsStatus(params: params)
      DispatchQueue.main.async {
        // Tri-state: only a definite present/absent answers the question.
        // Anything else (locked keychain, missing entitlement, …) is an error
        // — answering "false" there would tell the caller a stored secret does
        // not exist and typically trigger a re-prompt/overwrite flow.
        switch status {
        case errSecSuccess:
          result(true)
        case errSecItemNotFound:
          result(false)
        case errSecInteractionNotAllowed:
          result(FlutterError(code: "interaction_not_allowed", message: "Keychain interaction not allowed (device locked?).", details: nil))
        default:
          result(FlutterError(code: "sec_item_copy_failed", message: secErrorMessage(status), details: nil))
        }
      }
    }
  }

  private func handleSecItemCopyMatching(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    guard let args = call.arguments as? [String: Any],
          let params = KeychainParams.from(args) else {
      result(FlutterError(code: "bad_args", message: "Missing alias or unknown accessibility.", details: nil))
      return
    }
    serialQueue.async {
      var query = keychainReadQuery(params: params, returnData: true)
      if let prompt = params.authenticationPrompt {
        let context = LAContext()
        context.localizedReason = prompt
        query[kSecUseAuthenticationContext as String] = context
      }
      var item: CFTypeRef?
      let status = Security.SecItemCopyMatching(query as CFDictionary, &item)

      switch status {
      case errSecSuccess:
        guard var rawData = item as? Data else {
          // A success status without Data is corruption, not absence — never
          // report it as a clean "not found".
          DispatchQueue.main.async {
            result(FlutterError(code: "sec_item_copy_failed", message: "Keychain returned success without data.", details: nil))
          }
          return
        }
        if params.secureEnclave {
          // READ PATH: fetch-only, never create. Regenerating a missing SE key
          // here would mint a key that cannot decrypt this ciphertext (and
          // pollute SE state) — surface a distinct, fail-closed "key missing"
          // instead, so the Dart layer can report it as KeyNotFound rather than
          // an opaque decrypt failure. A fetch *error* is reported as its own
          // code: KeyNotFound's documented recovery (purge + re-entry) destroys
          // data, so a transient failure must never masquerade as key loss.
          let privateKey: SecKey
          switch fetchEnclaveKeyPair(params: params.enclaveParams) {
          case .found(let key, _):
            privateKey = key
          case .missing:
            rawData.wipe()
            DispatchQueue.main.async {
              result(FlutterError(code: "se_key_missing", message: "Secure Enclave key not found for this profile.", details: nil))
            }
            return
          case .failure(let fetchStatus):
            rawData.wipe()
            DispatchQueue.main.async {
              result(FlutterError(code: "se_key_fetch_failed", message: secErrorMessage(fetchStatus), details: nil))
            }
            return
          }
          guard var plaintext = enclaveDecrypt(data: rawData, privateKey: privateKey) else {
            rawData.wipe()
            DispatchQueue.main.async {
              result(FlutterError(code: "se_decrypt_failed", message: "Secure Enclave decryption failed.", details: nil))
            }
            return
          }
          rawData.wipe()
          let typedData = FlutterStandardTypedData(bytes: plaintext)
          plaintext.wipe()
          DispatchQueue.main.async { result(typedData) }
        } else {
          let typedData = FlutterStandardTypedData(bytes: rawData)
          rawData.wipe()
          DispatchQueue.main.async { result(typedData) }
        }
      case errSecItemNotFound:
        DispatchQueue.main.async { result(nil) }
      case errSecUserCanceled:
        DispatchQueue.main.async {
          result(FlutterError(code: "auth_cancelled", message: "User cancelled authentication.", details: nil))
        }
      case errSecAuthFailed:
        DispatchQueue.main.async {
          result(FlutterError(code: "auth_failed", message: "Authentication failed.", details: nil))
        }
      case errSecInteractionNotAllowed:
        DispatchQueue.main.async {
          result(FlutterError(code: "interaction_not_allowed", message: "Keychain interaction not allowed (device locked?).", details: nil))
        }
      default:
        DispatchQueue.main.async {
          result(FlutterError(code: "sec_item_copy_failed", message: secErrorMessage(status), details: nil))
        }
      }
    }
  }

  private func handleEnsureEnclaveKeyPair(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    let args = (call.arguments as? [String: Any]) ?? [:]
    guard let accessibility = SecAccessibility.fromDart(args["accessibility"] as? String) else {
      result(FlutterError(code: "bad_args", message: "Unknown accessibility.", details: nil))
      return
    }
    guard SecAccessibility.secureEnclaveCompatible.contains(accessibility as String) else {
      result(FlutterError(
        code: "se_requires_device_only_accessibility",
        message: "secureEnclave requires a *ThisDeviceOnly accessibility class.",
        details: nil))
      return
    }
    let enclaveParams = EnclaveParams(
      service: args["service"] as? String,
      accessibility: accessibility,
      accessGroup: args["accessGroup"] as? String,
      useDataProtection: args["useDataProtection"] as? Bool ?? false
    )
    serialQueue.async {
      let alreadyExisted = enclaveKeyExists(params: enclaveParams)
      guard ensureEnclaveKeyPair(params: enclaveParams) != nil else {
        DispatchQueue.main.async {
          result(FlutterError(code: "se_key_gen_failed", message: "Could not ensure SE key pair.", details: nil))
        }
        return
      }
      DispatchQueue.main.async { result(alreadyExisted) }
    }
  }

  private func handleSecItemDelete(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    guard let args = call.arguments as? [String: Any],
          let params = KeychainParams.from(args) else {
      result(FlutterError(code: "bad_args", message: "Missing alias or unknown accessibility.", details: nil))
      return
    }
    serialQueue.async {
      let status = secItemDelete(params: params)
      DispatchQueue.main.async {
        if status == errSecSuccess || status == errSecItemNotFound {
          result(nil)
        } else {
          result(FlutterError(code: "sec_item_delete_failed", message: secErrorMessage(status), details: nil))
        }
      }
    }
  }

  private func handleSecItemDeleteByPrefix(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    // No alias here (we match by prefix, not a single account), so parse the
    // scoping fields directly rather than via KeychainParams.from.
    guard let args = call.arguments as? [String: Any],
          let prefix = args["prefix"] as? String else {
      result(FlutterError(code: "bad_args", message: "Missing prefix.", details: nil))
      return
    }
    let scope = KeychainScope(
      service: args["service"] as? String,
      accessGroup: args["accessGroup"] as? String,
      useDataProtection: args["useDataProtection"] as? Bool ?? false
    )
    let excludePrefixes = (args["excludePrefixes"] as? [String]) ?? []
    serialQueue.async {
      let status = secItemDeleteByPrefix(scope: scope, prefix: prefix, excludePrefixes: excludePrefixes)
      DispatchQueue.main.async {
        // errSecItemNotFound means nothing matched — a clean no-op for a wipe.
        if status == errSecSuccess || status == errSecItemNotFound {
          result(nil)
        } else {
          result(FlutterError(code: "sec_item_delete_failed", message: secErrorMessage(status), details: nil))
        }
      }
    }
  }

}
