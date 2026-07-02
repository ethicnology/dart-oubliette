// swift-tools-version: 6.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "keychain",
    // Match the podspec (`s.swift_version = '6.0'`): build under the Swift 6
    // language mode (full strict concurrency) so SPM and CocoaPods diagnose the
    // same code rather than the SPM target silently defaulting to Swift 5.
    platforms: [
        .iOS("13.0"),
        .macOS("10.15")
    ],
    products: [
        .library(name: "keychain", targets: ["keychain"])
    ],
    dependencies: [
        .package(name: "FlutterFramework", path: "../FlutterFramework")
    ],
    targets: [
        .target(
            name: "keychain",
            dependencies: [
                .product(name: "FlutterFramework", package: "FlutterFramework")
            ],
            resources: [
                // Apple privacy manifest. The plugin collects no data and uses
                // no required-reason APIs, so the manifest declares exactly
                // that (all-empty / tracking false) — shipping the explicit
                // negative declaration is the compliance requirement; omitting
                // the file leaves the host app to answer for this SDK. Kept in
                // sync with the CocoaPods side via the podspec's
                // `resource_bundles`. See
                // https://developer.apple.com/documentation/bundleresources/privacy_manifest_files
                .process("PrivacyInfo.xcprivacy"),
            ],
            swiftSettings: [
                .swiftLanguageMode(.v6)
            ]
        )
    ]
)
