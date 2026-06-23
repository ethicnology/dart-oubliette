#if os(iOS)
import Flutter
#else
import FlutterMacOS
#endif
import Foundation
import LocalAuthentication
import Security

/// Sendable carrier for a `@escaping FlutterResult`.
///
/// `FlutterResult` is an Objective-C block (`void (^)(id)`) and therefore
/// non-`Sendable`; capturing it directly across the `serialQueue.async` →
/// `DispatchQueue.main.async` hops trips Swift 6 strict-concurrency. The
/// runtime contract is unchanged and enforced *by construction* here: the
/// boxed result is delivered through `deliver(_:)`, which always hops to the
/// main thread, and the call sites still invoke it exactly once per request.
/// `@unchecked Sendable` is sound because the box is only ever read (the block
/// is invoked, never mutated) and every invocation is funnelled onto the main
/// thread.
private struct SendableResult: @unchecked Sendable {
  private let result: FlutterResult
  init(_ result: @escaping FlutterResult) { self.result = result }

  /// Delivers [value] to the Flutter result on the main thread.
  func deliver(_ value: Any?) {
    DispatchQueue.main.async { self.result(value) }
  }
}

/// Maps a raw OSStatus to a FlutterError for the generic fallback branches.
///
/// Two statuses get their own stable codes everywhere (not just on reads):
/// - `errSecMissingEntitlement` (-34018): a build/configuration defect (code
///   signing, the `keychain-access-groups` entitlement, or an `accessGroup`
///   the app is not entitled to) — actionable by the developer, never by
///   retrying — and must not be conflated with runtime keychain state under a
///   catch-all `sec_item_*_failed` code.
/// - `errSecInteractionNotAllowed`: the locked-device status. Writes and
///   deletes hit it too (e.g. store() while locked with a `whenUnlocked`
///   class); collapsing it into a generic failure would hide the one error
///   whose remedy is simply "retry when unlocked".
private func statusFlutterError(_ status: OSStatus, fallbackCode: String) -> FlutterError {
  switch status {
  case errSecMissingEntitlement:
    return FlutterError(
      code: "missing_entitlement",
      message: "Missing keychain entitlement (\(secErrorMessage(status))). "
        + "Check code signing and the keychain-access-groups entitlement "
        + "for the requested accessGroup.",
      details: nil)
  case errSecInteractionNotAllowed:
    return FlutterError(
      code: "interaction_not_allowed",
      message: "Keychain interaction not allowed (device locked?).",
      details: nil)
  default:
    return FlutterError(code: fallbackCode, message: secErrorMessage(status), details: nil)
  }
}

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
    let box = SendableResult(result)
    // Extract the payload bytes (a `Data`, which is Sendable) before hopping to
    // the worker queue, so the non-Sendable `FlutterStandardTypedData` is not
    // captured by the @Sendable closure (Swift 6 strict concurrency).
    let payload = data.data
    serialQueue.async {
      // Deterministically drain any autoreleased bridging copies made while
      // plaintext was in flight — GCD's implicit pool drains at an unspecified
      // time, which would leave secret-bearing CF/NSData copies alive.
      let outcome = autoreleasepool { secItemAdd(params: params, data: payload) }
      switch outcome {
      case .completed(let status) where status == errSecSuccess:
        box.deliver(nil)
      case .completed(let status) where status == errSecDuplicateItem:
        box.deliver(FlutterError(code: "already_exists", message: "A value already exists for this key.", details: nil))
      case .completed(let status):
        box.deliver(statusFlutterError(status, fallbackCode: "sec_item_add_failed"))
      case .enclaveKeyUnavailable:
        // Distinct from a keychain error: the SE key could not be
        // fetched-or-created, so nothing was stored.
        box.deliver(FlutterError(code: "se_key_gen_failed", message: "Could not ensure the Secure Enclave key pair.", details: nil))
      case .enclaveEncryptFailed:
        box.deliver(FlutterError(code: "se_encrypt_failed", message: "Secure Enclave encryption failed.", details: nil))
      case .accessControlFailed:
        box.deliver(FlutterError(code: "access_control_failed", message: "Could not create the access control policy for an authenticated item.", details: nil))
      }
    }
  }

  private func handleKeychainContains(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    guard let args = call.arguments as? [String: Any],
          let params = KeychainParams.from(args) else {
      result(FlutterError(code: "bad_args", message: "Missing alias or unknown accessibility.", details: nil))
      return
    }
    let box = SendableResult(result)
    serialQueue.async {
      let status = secItemExistsStatus(params: params)
      // Tri-state: only a definite present/absent answers the question.
      // Anything else (locked keychain, missing entitlement, …) is an error
      // — answering "false" there would tell the caller a stored secret does
      // not exist and typically trigger a re-prompt/overwrite flow.
      switch status {
      case errSecSuccess:
        box.deliver(true)
      case errSecItemNotFound:
        box.deliver(false)
      case errSecInteractionNotAllowed:
        box.deliver(FlutterError(code: "interaction_not_allowed", message: "Keychain interaction not allowed (device locked?).", details: nil))
      default:
        box.deliver(statusFlutterError(status, fallbackCode: "sec_item_copy_failed"))
      }
    }
  }

  private func handleSecItemCopyMatching(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    guard let args = call.arguments as? [String: Any],
          let params = KeychainParams.from(args) else {
      result(FlutterError(code: "bad_args", message: "Missing alias or unknown accessibility.", details: nil))
      return
    }
    let box = SendableResult(result)
    serialQueue.async {
    // Deterministically drain autoreleased bridging copies of the secret (see
    // handleSecItemAdd). Kept at the same indent as the queue closure so the
    // long body below stays diff-flat.
    autoreleasepool {
      var query = keychainReadQuery(params: params, returnData: true)
      var authContext: LAContext?
      if let prompt = params.authenticationPrompt {
        let context = LAContext()
        context.localizedReason = prompt
        // Freeze the zero-reuse intent: a successful evaluation must never
        // pre-authorize a *later* operation. The default is already 0, but
        // pinning it here guards against a future SDK widening that silent
        // re-authorization window (paired with the explicit invalidate() below).
        context.touchIDAuthenticationAllowableReuseDuration = 0
        query[kSecUseAuthenticationContext as String] = context
        authContext = context
      }
      var item: CFTypeRef?
      let status = Security.SecItemCopyMatching(query as CFDictionary, &item)
      // Close the authentication window deterministically: a context that has
      // just satisfied an ACL stays pre-authorized while alive and could
      // silently satisfy a *subsequent* keychain operation without UI. ARC
      // would release it eventually; invalidate() is immediate and explicit.
      authContext?.invalidate()

      switch status {
      case errSecSuccess:
        guard var rawData = item as? Data else {
          // A success status without Data is corruption, not absence — never
          // report it as a clean "not found".
          box.deliver(FlutterError(code: "sec_item_copy_failed", message: "Keychain returned success without data.", details: nil))
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
            box.deliver(FlutterError(code: "se_key_missing", message: "Secure Enclave key not found for this profile.", details: nil))
            return
          case .failure(let fetchStatus):
            rawData.wipe()
            box.deliver(FlutterError(code: "se_key_fetch_failed", message: secErrorMessage(fetchStatus), details: nil))
            return
          }
          guard var plaintext = enclaveDecrypt(data: rawData, privateKey: privateKey) else {
            rawData.wipe()
            box.deliver(FlutterError(code: "se_decrypt_failed", message: "Secure Enclave decryption failed.", details: nil))
            return
          }
          rawData.wipe()
          let typedData = FlutterStandardTypedData(bytes: plaintext)
          plaintext.wipe()
          box.deliver(typedData)
        } else {
          let typedData = FlutterStandardTypedData(bytes: rawData)
          rawData.wipe()
          box.deliver(typedData)
        }
      case errSecItemNotFound:
        box.deliver(nil)
      case errSecUserCanceled:
        box.deliver(FlutterError(code: "auth_cancelled", message: "User cancelled authentication.", details: nil))
      case errSecAuthFailed:
        // Biometry *lockout* (too many failed Touch/Face ID attempts; clearing
        // it requires a passcode unlock of the device) also surfaces here as
        // `errSecAuthFailed` — SecItemCopyMatching does not expose the
        // underlying LAError, so it cannot be told from a single mismatched
        // attempt by OSStatus alone. Probe a fresh LAContext to distinguish:
        // when biometry is locked out, `canEvaluatePolicy` fails with
        // `LAError.biometryLockout`. Both map to AuthenticationFailedException
        // (recoverable, never purge), but the distinct `biometry_lockout` code
        // lets the caller show the right hint ("unlock with your passcode to
        // re-enable biometrics") instead of "try again".
        //
        // Only meaningful for a biometry-ONLY item (the fatal
        // `biometryCurrentSetOnly` profile). A `.userPresence` item accepts the
        // device passcode as a fallback, so a biometry lockout does NOT block its
        // access — reporting `biometry_lockout` there would wrongly tell the user
        // biometrics are their only path. Probe only when the item is
        // biometry-only; otherwise the failure is an ordinary `auth_failed`.
        if params.biometryCurrentSetOnly {
          let probe = LAContext()
          var probeError: NSError?
          let biometryUsable = probe.canEvaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics, error: &probeError)
          probe.invalidate()
          if !biometryUsable, probeError?.code == LAError.biometryLockout.rawValue {
            box.deliver(FlutterError(code: "biometry_lockout", message: "Biometry is locked out; unlock the device with the passcode to re-enable it.", details: nil))
            return
          }
        }
        box.deliver(FlutterError(code: "auth_failed", message: "Authentication failed.", details: nil))
      case errSecInteractionNotAllowed:
        box.deliver(FlutterError(code: "interaction_not_allowed", message: "Keychain interaction not allowed (device locked?).", details: nil))
      default:
        box.deliver(statusFlutterError(status, fallbackCode: "sec_item_copy_failed"))
      }
    }
    }
  }

  private func handleEnsureEnclaveKeyPair(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    guard let args = call.arguments as? [String: Any] else {
      result(FlutterError(code: "bad_args", message: "Expected an arguments map.", details: nil))
      return
    }
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
    let box = SendableResult(result)
    serialQueue.async {
      autoreleasepool {
        // The returned Bool ("key already existed") is the caller's
        // restore-detection signal: `false` means a FRESH key that cannot
        // decrypt any pre-existing ciphertext. A fetch *error* (locked
        // keychain, entitlement, domain misrouting) must therefore surface as
        // an error — collapsing it to `false` would report an intact key as
        // newly created, and refusing to create on a failed fetch (see
        // `ensureEnclaveKeyPair`) keeps a second key from ever being minted
        // under the same tag.
        switch fetchEnclaveKeyPair(params: enclaveParams) {
        case .found:
          box.deliver(true)
        case .failure(let status):
          box.deliver(FlutterError(code: "se_key_fetch_failed", message: secErrorMessage(status), details: nil))
        case .missing:
          guard createEnclaveKeyPair(params: enclaveParams) != nil else {
            box.deliver(FlutterError(code: "se_key_gen_failed", message: "Could not ensure SE key pair.", details: nil))
            return
          }
          box.deliver(false)
        }
      }
    }
  }

  private func handleSecItemDelete(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    guard let args = call.arguments as? [String: Any],
          let params = KeychainParams.from(args) else {
      result(FlutterError(code: "bad_args", message: "Missing alias or unknown accessibility.", details: nil))
      return
    }
    let box = SendableResult(result)
    serialQueue.async {
      let status = secItemDelete(params: params)
      if status == errSecSuccess || status == errSecItemNotFound {
        box.deliver(nil)
      } else {
        box.deliver(statusFlutterError(status, fallbackCode: "sec_item_delete_failed"))
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
    let box = SendableResult(result)
    serialQueue.async {
      let status = secItemDeleteByPrefix(scope: scope, prefix: prefix, excludePrefixes: excludePrefixes)
      // errSecItemNotFound means nothing matched — a clean no-op for a wipe.
      if status == errSecSuccess || status == errSecItemNotFound {
        box.deliver(nil)
      } else {
        box.deliver(statusFlutterError(status, fallbackCode: "sec_item_delete_failed"))
      }
    }
  }

}
