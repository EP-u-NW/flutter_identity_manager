import 'dart:typed_data';

import 'package:flutter/services.dart';
import 'package:flutter_identity_manager_platform_interface/flutter_identity_manager_platform_interface.dart';
import 'package:pointycastle/asn1.dart';
import 'package:pointycastle/asn1/primitives/asn1_sequence.dart';

/// An implementation of [FlutterIdentityManagerPlatform] for iOS.
class FlutterIdentityManagerIOS extends FlutterIdentityManagerPlatform {
  static const MethodChannel _channel =
      const MethodChannel('eu.epnw.flutter_identity_manager');
  @override
  Future<bool> deleteCert(String certName) async {
    bool? result =
        await _channel.invokeMethod<bool>('deleteCert', {'label': certName});
    return result ?? false;
  }

  @override
  Future<bool> deleteKeyPair(String keypairName) async {
    bool? result =
        await _channel.invokeMethod<bool>('deleteKey', {'tag': keypairName});
    return result ?? false;
  }

  @override
  Future<Uint8List?> generateKeyPair(String keypairName, int size,
      {String? password}) async {
    // Under iOS the private key is saved in the keychain, so we
    // don't need an password to protect it
    Uint8List? publicKey = await _channel.invokeMethod<Uint8List>(
        'generateKey', {'tag': keypairName, 'size': size, 'permanent': true});
    return publicKey;
  }

  @override
  Future<IdentityDescription?> loadIdentity(
      String keypairName, String certName, String? password) async {
    // Under iOS the private key is saved in the keychain, so we
    // don't need an password to load it, instead we are using the
    // password to encrypt the p12 with it. But this means that we
    // have to make sure that there is a password.
    password = password ?? 'password';
    Uint8List? p12 = await _channel.invokeMethod<Uint8List>('loadIdentity',
        {'tag': keypairName, 'name': certName, 'password': password});
    if (p12 != null) {
      return new IdentityDescription(p12, p12, false, password);
    } else {
      return null;
    }
  }

  @override
  Future<Uint8List?> loadPublicKey(String keypairName,
      {String? password}) async {
    // For notes on password see generateKeyPair
    Uint8List? publicKey = await _channel
        .invokeMethod<Uint8List>('loadPublicKey', {'tag': keypairName});
    //On iOS, that public key is pkcs1, we need it pkcs8, so do some conversions
    if (publicKey != null) {
      return _pkcs8EncodeRSAPublicKey(publicKey);
    } else {
      return null;
    }
  }

  @override
  Future<bool> saveCert(String certName, Uint8List derData) async {
    bool? result = await _channel.invokeMethod<bool>(
        'createIdentity', {'data': derData, 'label': certName});
    return result ?? false;
  }
}

final ASN1ObjectIdentifier _rsaIdentifier =
    new ASN1ObjectIdentifier.fromIdentifierString('1.2.840.113549.1.1.1');

Uint8List _pkcs8EncodeRSAPublicKey(Uint8List pkcs1EncodedRSAPublicKey) =>
    new ASN1Sequence(elements: [
      _rsaIdentifier,
      new ASN1BitString(stringValues: pkcs1EncodedRSAPublicKey)
    ]).encode();
