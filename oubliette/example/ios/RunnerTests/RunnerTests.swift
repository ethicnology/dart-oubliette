import Flutter
import Security
import UIKit
import XCTest

@testable import keychain

class RunnerTests: XCTestCase {
  let acc = kSecAttrAccessibleWhenUnlockedThisDeviceOnly

  // #2 — the Secure Enclave tag must distinguish service=nil from
  // service="default" (the old `service ?? "default"` form conflated them).
  func testEnclaveTagDistinguishesNilFromDefault() {
    let nilTag = enclaveKeyTag(params: EnclaveParams(service: nil, accessibility: acc, accessGroup: nil))
    let defaultTag = enclaveKeyTag(params: EnclaveParams(service: "default", accessibility: acc, accessGroup: nil))
    XCTAssertNotNil(nilTag)
    XCTAssertNotNil(defaultTag)
    XCTAssertNotEqual(nilTag, defaultTag)
  }

  func testEnclaveTagDistinguishesNilFromEmpty() {
    let nilTag = enclaveKeyTag(params: EnclaveParams(service: nil, accessibility: acc, accessGroup: nil))
    let emptyTag = enclaveKeyTag(params: EnclaveParams(service: "", accessibility: acc, accessGroup: nil))
    XCTAssertNotEqual(nilTag, emptyTag)
  }

  // #6 — accessibility is part of the key identity.
  func testAccessibilityChangesTag() {
    let unlocked = enclaveKeyTag(params: EnclaveParams(service: "s", accessibility: kSecAttrAccessibleWhenUnlockedThisDeviceOnly, accessGroup: nil))
    let afterFirst = enclaveKeyTag(params: EnclaveParams(service: "s", accessibility: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, accessGroup: nil))
    XCTAssertNotEqual(unlocked, afterFirst)
  }

  // A3 — access group scopes the key.
  func testAccessGroupChangesTag() {
    let none = enclaveKeyTag(params: EnclaveParams(service: "s", accessibility: acc, accessGroup: nil))
    let grouped = enclaveKeyTag(params: EnclaveParams(service: "s", accessibility: acc, accessGroup: "group.app"))
    XCTAssertNotEqual(none, grouped)
  }

  // Length-prefixed components mean no value can forge another's boundary.
  func testLengthPrefixPreventsForgery() {
    let real = enclaveKeyTag(params: EnclaveParams(service: "a", accessibility: acc, accessGroup: "b"))
    let forged = enclaveKeyTag(params: EnclaveParams(service: "a|g:1:b", accessibility: acc, accessGroup: nil))
    XCTAssertNotEqual(real, forged)
  }
}
