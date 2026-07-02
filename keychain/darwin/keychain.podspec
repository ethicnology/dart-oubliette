Pod::Spec.new do |s|
  s.name             = 'keychain'
  s.version          = '1.0.0'
  s.summary          = 'Flutter plugin exposing the iOS/macOS Keychain (SecItem API).'
  s.description      = <<-DESC
Flutter plugin that provides typed access to the iOS and macOS Keychain via the Security framework.
                       DESC
  s.homepage         = 'https://github.com/ethicnology/dart-oubliette'
  s.license          = { :file => '../../LICENSE' }
  s.author           = { 'ethicnology' => 'contact@ethicnology.com' }
  s.source           = { :path => '.' }
  # Swift sources only: the target directory also holds PrivacyInfo.xcprivacy,
  # which must ship as a *resource* (below), not be fed to the compiler.
  s.source_files = 'keychain/Sources/keychain/**/*.swift'
  # Apple privacy manifest (all-empty / tracking false — the plugin collects no
  # data and uses no required-reason APIs). Mirrors the SwiftPM `resources`
  # entry in keychain/Package.swift; keep the two in sync.
  s.resource_bundles = {
    'keychain_privacy' => ['keychain/Sources/keychain/PrivacyInfo.xcprivacy']
  }

  s.ios.dependency 'Flutter'
  s.osx.dependency 'FlutterMacOS'

  s.ios.deployment_target = '13.0'
  s.osx.deployment_target = '10.15'

  # Link the system frameworks the sources import explicitly rather than
  # relying on autolinking: Security (SecItem/SecKey/Secure Enclave) and
  # LocalAuthentication (LAContext hardening, biometry-lockout probe).
  s.frameworks = 'Security', 'LocalAuthentication'

  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
  s.swift_version = '6.0'
end
