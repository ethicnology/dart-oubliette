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
  ///
  /// [value] is `sending`: ownership is transferred into the main-queue closure
  /// so Swift 6 strict concurrency can prove nothing else retains it (an `Any?`
  /// is not `Sendable`). Every call site passes a freshly built, non-reused
  /// value (`nil` / `Bool` / `FlutterStandardTypedData` / `FlutterError` /
  /// `[String]`), so the transfer is always satisfiable.
  func deliver(_ value: sending Any?) {
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

/// Classifies the authentication-related read statuses into their stable
/// codes, or returns `nil` when [status] is not authentication-related (the
/// caller falls through to its own fallback). This is THE classification for
/// auth-class failures on the read path — shared by the item read (the
/// OSStatus from `SecItemCopyMatching`) and the Secure Enclave decrypt (the
/// OSStatus carried inside `SecKeyCreateDecryptedData`'s CFError, see
/// `enclaveDecryptFlutterError`) — so both stages of one read classify
/// identically. A transient auth condition surfacing at either stage must
/// never masquerade as permanent data loss: every code returned here maps to
/// a *recoverable* Dart exception whose remedy is retry/authenticate, never
/// `purge()`.
private func authStatusFlutterError(_ status: OSStatus, params: KeychainParams) -> FlutterError? {
  switch status {
  case errSecUserCanceled:
    return FlutterError(code: "auth_cancelled", message: "User cancelled authentication.", details: nil)
  case errSecAuthFailed:
    // Biometry *lockout* (too many failed Touch/Face ID attempts; clearing
    // it requires a passcode unlock of the device) also surfaces as
    // `errSecAuthFailed` — the OSStatus does not expose the underlying
    // LAError, so it cannot be told from a single mismatched attempt by
    // status alone. Probe a fresh LAContext to distinguish: when biometry is
    // locked out, `canEvaluatePolicy` fails with `LAError.biometryLockout`.
    // Both map to AuthenticationFailedException (recoverable, never purge),
    // but the distinct `biometry_lockout` code lets the caller show the right
    // hint ("unlock with your passcode to re-enable biometrics") instead of
    // "try again".
    //
    // Only meaningful for a biometry-ONLY item (the fatal
    // `biometryCurrentSetOnly` profile). A `.userPresence` item accepts the
    // device passcode as a fallback, so a biometry lockout does NOT block its
    // access — reporting `biometry_lockout` there would wrongly tell the user
    // biometrics are their only path. Probe only when the item is
    // biometry-only; otherwise the failure is an ordinary `auth_failed`.
    // Gate on BOTH flags: `.biometryCurrentSet` is only ever applied to an
    // authenticated item (see createAccessControl / secItemAdd), so a probe
    // with biometryCurrentSetOnly but no authenticationRequired could never
    // describe how the item was actually stored.
    if params.authenticationRequired && params.biometryCurrentSetOnly {
      let probe = LAContext()
      var probeError: NSError?
      let biometryUsable = probe.canEvaluatePolicy(
        .deviceOwnerAuthenticationWithBiometrics, error: &probeError)
      probe.invalidate()
      if !biometryUsable, probeError?.code == LAError.biometryLockout.rawValue {
        return FlutterError(code: "biometry_lockout", message: "Biometry is locked out; unlock the device with the passcode to re-enable it.", details: nil)
      }
    }
    return FlutterError(code: "auth_failed", message: "Authentication failed.", details: nil)
  case errSecInteractionNotAllowed:
    return FlutterError(code: "interaction_not_allowed", message: "Keychain interaction not allowed (device locked?).", details: nil)
  default:
    return nil
  }
}

/// Maps the `CFError` from a failed Secure Enclave decrypt to a FlutterError.
///
/// `se_decrypt_failed` maps in Dart to `DecryptionFailedException`
/// (recoverable: false, documented remedy "overwrite or purge()"), so it is
/// reserved for GENUINE decryption failures — corrupt/foreign ciphertext, a
/// key/algorithm mismatch. Everything the auth layer can throw transiently
/// must be routed to the same recoverable codes the item-read path uses, or a
/// device that locks between the item read and the SE decrypt would steer a
/// compliant caller into destroying an intact secret. Two error shapes cover
/// the auth layer:
///
/// - `NSOSStatusErrorDomain`: Security-framework statuses. Reuses
///   `authStatusFlutterError` verbatim (`errSecInteractionNotAllowed` →
///   `interaction_not_allowed`, `errSecUserCanceled` → `auth_cancelled`,
///   `errSecAuthFailed` → `auth_failed` with the biometry-lockout probe) so
///   the two stages of one read cannot drift apart.
/// - `LAErrorDomain`: LocalAuthentication errors. ANY error in this domain
///   is by construction an authentication-layer outcome — the SEP never
///   evaluated (let alone rejected) the ciphertext — so none of them may land
///   in the fatal bucket: cancel-class codes → `auth_cancelled`,
///   `biometryLockout` → `biometry_lockout`, `notInteractive` (the LA analog
///   of interaction-not-allowed) → `interaction_not_allowed`, and every
///   remaining LA code → `auth_failed`.
///
/// A missing or unrecognized error falls through to `se_decrypt_failed`:
/// with no evidence of an auth-layer cause, reporting a recoverable code
/// would invite an infinite retry loop against genuinely bad ciphertext.
private func enclaveDecryptFlutterError(_ error: CFError?, params: KeychainParams) -> FlutterError {
  if let error = error {
    // CFError conforms to Swift.Error; bridge via Error → NSError for uniform
    // domain/code access (avoids relying on direct CF↔NS toll-free casts).
    let nsError = error as Error as NSError
    if nsError.domain == NSOSStatusErrorDomain,
       // `Int32(exactly:)` never traps: a code outside OSStatus range is not
       // a Security status and falls through to the fatal bucket below.
       let status = Int32(exactly: nsError.code),
       let authError = authStatusFlutterError(status, params: params) {
      return authError
    }
    if nsError.domain == LAErrorDomain {
      switch nsError.code {
      case LAError.userCancel.rawValue, LAError.appCancel.rawValue, LAError.systemCancel.rawValue:
        return FlutterError(code: "auth_cancelled", message: "User cancelled authentication.", details: nil)
      case LAError.biometryLockout.rawValue:
        return FlutterError(code: "biometry_lockout", message: "Biometry is locked out; unlock the device with the passcode to re-enable it.", details: nil)
      case LAError.notInteractive.rawValue:
        return FlutterError(code: "interaction_not_allowed", message: "Keychain interaction not allowed (device locked?).", details: nil)
      default:
        return FlutterError(code: "auth_failed", message: "Authentication failed.", details: nil)
      }
    }
  }
  return FlutterError(code: "se_decrypt_failed", message: "Secure Enclave decryption failed.", details: nil)
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
    case "secItemListByPrefix":
      handleSecItemListByPrefix(call, result: result)
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
    // Fail closed on an incoherent flag combination *before* storing anything:
    // biometryCurrentSetOnly without authenticationRequired would otherwise be
    // stored as an UN-gated item (the .biometryCurrentSet ACL is only applied on
    // the authenticated branch) — silently dropping the biometry gate the caller
    // requested. See secItemAddParamsError.
    if let code = secItemAddParamsError(params) {
      result(FlutterError(
        code: code,
        message: "biometryCurrentSetOnly requires authenticationRequired: true "
          + "(otherwise the item would be stored with no access control).",
        details: nil))
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
      // Gate the hardened context on `authenticationRequired` — the flag that
      // says an ACL evaluation will happen — with the prompt string merely
      // optional. Gating on the prompt (the previous shape) meant an
      // auth-required read WITHOUT a prompt got the system-managed implicit
      // context and silently lost BOTH hardening properties below; a cosmetic
      // omission must never weaken the auth posture. The prompt-only case
      // (`authenticationPrompt` set, `authenticationRequired` false) also
      // keeps the context: the read params may not match how the item was
      // actually stored, and if the item turns out to be ACL-gated the
      // caller's reason string — and the hardening — should still apply.
      if params.authenticationRequired || params.authenticationPrompt != nil {
        let context = LAContext()
        // Set the reason only when the caller provided a non-empty one.
        // LocalAuthentication rejects an EMPTY `localizedReason` (assertion at
        // evaluation time), while an *unset* reason is fine for a
        // keychain-ACL-driven prompt: the OS falls back to its default dialog
        // text — less specific, but safe. So absent/empty prompt ⇒ leave the
        // property untouched and let the OS default stand.
        if let prompt = params.authenticationPrompt, !prompt.isEmpty {
          context.localizedReason = prompt
        }
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
          // DECRYPT: classify, never collapse. `SecKeyCreateDecryptedData`
          // evaluates the access policy at call time, so it fails not only for
          // bad ciphertext but for transient auth-layer conditions (device
          // locked mid-read, prompt cancelled, biometry lockout). Those must
          // surface under the same recoverable codes the item read uses —
          // `se_decrypt_failed` is fatal in the Dart taxonomy (its documented
          // remedy destroys the item), so it is reserved for genuine
          // decryption failures. See `enclaveDecryptFlutterError`.
          var plaintext: Data
          switch enclaveDecrypt(data: rawData, privateKey: privateKey) {
          case .success(let decrypted):
            plaintext = decrypted
          case .failure(let decryptError):
            // Same wipe discipline as the se_key_missing / se_key_fetch_failed
            // branches above: the ciphertext copy is dropped before delivering.
            rawData.wipe()
            box.deliver(enclaveDecryptFlutterError(decryptError, params: params))
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
      default:
        // Auth-class statuses (`errSecUserCanceled`, `errSecAuthFailed` with
        // the biometry-lockout probe, `errSecInteractionNotAllowed`) are
        // classified by the shared helper — the SAME one the SE-decrypt error
        // path uses, so a transient auth condition maps to identical codes
        // whether it strikes at the item read or at the decrypt. See
        // `authStatusFlutterError` for the classification rationale.
        if let authError = authStatusFlutterError(status, params: params) {
          box.deliver(authError)
        } else {
          box.deliver(statusFlutterError(status, fallbackCode: "sec_item_copy_failed"))
        }
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

  private func handleSecItemListByPrefix(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    // No alias — we enumerate by prefix, so parse the scoping fields directly
    // (mirrors handleSecItemDeleteByPrefix).
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
      let (status, accounts) = secItemListByPrefix(scope: scope, prefix: prefix, excludePrefixes: excludePrefixes)
      // errSecItemNotFound means nothing matched — return an empty list, not an
      // error (an empty profile is a valid, non-failing state).
      if status == errSecSuccess || status == errSecItemNotFound {
        box.deliver(accounts)
      } else {
        box.deliver(statusFlutterError(status, fallbackCode: "sec_item_copy_failed"))
      }
    }
  }

}
