import 'dart:typed_data';
import 'dart:convert';
import 'package:hive/hive.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_identity_manager_platform_interface/flutter_identity_manager_platform_interface.dart';
import 'package:path_provider/path_provider.dart';
import 'rsa_key_pair.dart';

/// An implementation of [FlutterIdentityManagerPlatform] for Android.
class FlutterIdentityManagerAndroid extends FlutterIdentityManagerPlatform {
  static const String _secureStorageKey =
      'flutter_identity_manager_android_key';
  static const String _hiveBoxName =
      'flutter_identity_manager_android_hive_box';
  static const String _privateKeySuffix = '_private';
  static const String _publicKeySuffix = '_public';

  bool _preparedStorage;
  late Box<Uint8List> _storage;

  FlutterIdentityManagerAndroid() : _preparedStorage = false;

  Future<void> _prepareStorageIfNeeded() async {
    if (!_preparedStorage) {
      Hive.init((await getApplicationDocumentsDirectory()).path);
      FlutterSecureStorage secureStorage = const FlutterSecureStorage();
      String? encryptionKeyBase64 =
          await secureStorage.read(key: _secureStorageKey);
      List<int>? encryptionKey;
      if (encryptionKeyBase64 == null) {
        encryptionKey = Hive.generateSecureKey();
        await secureStorage.write(
            key: _secureStorageKey, value: base64UrlEncode(encryptionKey));
      } else {
        encryptionKey = base64Url.decode(encryptionKeyBase64);
      }
      _storage = await Hive.openBox(_hiveBoxName,
          encryptionCipher: new HiveAesCipher(encryptionKey));
      _preparedStorage = true;
    }
  }

  @override
  Future<bool> deleteCert(String certName) async {
    await _prepareStorageIfNeeded();
    await _storage.delete(certName);
    return true;
  }

  @override
  Future<bool> deleteKeyPair(String keypairName) async {
    await _prepareStorageIfNeeded();
    await _storage.delete(keypairName + _privateKeySuffix);
    await _storage.delete(keypairName + _publicKeySuffix);
    return true;
  }

  @override
  Future<Uint8List?> generateKeyPair(String keypairName, int size,
      {String? password}) async {
    await _prepareStorageIfNeeded();
    // We are using hive to secure the keys so we can ignore
    // the password
    RSAKeyPair keyPair = new RSAKeyPairFactory(size).next();
    await _storage.put(
        keypairName + _privateKeySuffix, keyPair.pkcs8EncodeRSAPrivateKey());
    Uint8List publicKey = keyPair.pkcs1EncodeRSAPublicKey();
    await _storage.put(keypairName + _publicKeySuffix, publicKey);
    return publicKey;
  }

  @override
  Future<IdentityDescription?> loadIdentity(
      String keypairName, String certName, String? password) async {
    await _prepareStorageIfNeeded();
    Uint8List? privateKey = await _storage.get(keypairName + _privateKeySuffix);
    if (privateKey != null) {
      Uint8List? certBytes = await _storage.get(certName);
      if (certBytes != null) {
        return new IdentityDescription(certBytes, privateKey, true, null);
      } else {
        return null;
      }
    } else {
      return null;
    }
  }

  @override
  Future<Uint8List?> loadPublicKey(String keypairName,
      {String? password}) async {
    await _prepareStorageIfNeeded();
    return await _storage.get(keypairName + _publicKeySuffix);
  }

  @override
  Future<bool> saveCert(String certName, Uint8List derData) async {
    await _prepareStorageIfNeeded();
    await _storage.put(certName, derData);
    return true;
  }
}
