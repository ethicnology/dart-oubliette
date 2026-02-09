Pod::Spec.new do |s|
  s.name             = 'keychain'
  s.version          = '0.0.1'
  s.summary          = 'Flutter plugin exposing the iOS/macOS Keychain (SecItem API).'
  s.description      = <<-DESC
Flutter plugin that provides typed access to the iOS and macOS Keychain via the Security framework.
                       DESC
  s.homepage         = 'http://example.com'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'Your Company' => 'email@example.com' }
  s.source           = { :path => '.' }
  s.source_files = 'Classes/**/*'

  s.ios.dependency 'Flutter'
  s.osx.dependency 'FlutterMacOS'

  s.ios.deployment_target = '13.0'
  s.osx.deployment_target = '10.15'

  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
  s.swift_version = '5.0'
end
