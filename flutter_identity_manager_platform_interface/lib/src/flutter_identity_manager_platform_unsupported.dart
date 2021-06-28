import 'dart:typed_data';

import 'flutter_identity_manager_platform_interface.dart';

const String _not_supported_text = 'This platform is not supported!';

/// An implementation of [FlutterIdentityManagerPlatform] that throws an [UnsupportedError] when attempting to call a method.
class FlutterIdentityManagerPlatformUnsupported
    extends FlutterIdentityManagerPlatform {
  @override
  Future<bool> deleteCert(String certName) {
    throw new UnsupportedError(_not_supported_text);
  }

  @override
  Future<bool> deleteKeyPair(String keypairName) {
    throw new UnsupportedError(_not_supported_text);
  }

  @override
  Future<Uint8List?> generateKeyPair(String keypairName, int size, {String? password}) {
    throw new UnsupportedError(_not_supported_text);
  }

  @override
  Future<IdentityDescription?> loadIdentity(
      String keypairName, String certName, String? password) {
    throw new UnsupportedError(_not_supported_text);
  }

  @override
  Future<Uint8List?> loadPublicKey(String keypairName, {String? password}) {
    throw new UnsupportedError(_not_supported_text);
  }

  @override
  Future<bool> saveCert(String certName, Uint8List derData) {
    throw new UnsupportedError(_not_supported_text);
  }
}
