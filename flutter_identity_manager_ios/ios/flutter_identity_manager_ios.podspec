#
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html.
# Run `pod lib lint flutter_identity_manager_ios.podspec` to validate before publishing.
#
Pod::Spec.new do |s|
  s.name             = 'flutter_identity_manager_ios'
  s.version          = '0.0.1'
  s.summary          = 'Manages keys and certificates for flutter'
  s.description      = <<-DESC
A new flutter plugin project.
                       DESC
  s.homepage         = 'https://epnw.eu'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'Nils Wieler and Eric Prokop' => 'prokopwieler.hardundsoftware@gmail.com' }
  s.source           = { :path => '.' }
  s.source_files = 'Classes/**/*'
  s.dependency 'Flutter'
  s.platform = :ios, '9.0'
  s.ios.deployment_target = '9.0'

  s.dependency 'OpenSSL-Universal', '~> 1.1.180'
  # Flutter.framework does not contain a i386 slice.
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
  s.swift_version = '5.0'
end
