import 'dart:async';
import 'dart:collection';
import 'dart:isolate';
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

  bool _isolateWorkerSpawned;
  late SendPort _toIsolateWorker;
  bool _preparedStorage;
  late Box<Uint8List> _storage;
  Queue<Completer<ByteBuffer>> _isolateWorkCompleters;

  FlutterIdentityManagerAndroid()
      : _preparedStorage = false,
        _isolateWorkerSpawned = false,
        _isolateWorkCompleters = new Queue<Completer<ByteBuffer>>();

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

  Future<void> _spawnIsolateWorkerIfNeeded() async {
    if (!_isolateWorkerSpawned) {
      _isolateWorkerSpawned = true;
      Completer<SendPort> toIsolateSendPort = new Completer<SendPort>();
      ReceivePort fromWoker = new ReceivePort();
      bool first = true;
      fromWoker.listen((dynamic message) {
        if (first) {
          first = false;
          if (message != null && message is SendPort) {
            toIsolateSendPort.complete(message);
          } else {
            throw new ArgumentError('Unexpected message!');
          }
        } else {
          if (_isolateWorkCompleters.isNotEmpty &&
              message != null &&
              message is TransferableTypedData) {
            _isolateWorkCompleters
                .removeFirst()
                .complete(message.materialize());
          } else {
            throw new ArgumentError('Unexpected message!');
          }
        }
      });
      await Isolate.spawn(RSAKeyPairFactory.workIsolated, fromWoker.sendPort);
      _toIsolateWorker = await toIsolateSendPort.future;
    }
  }

  // We are using hive to secure the keys so we can ignore
  // the password
  @override
  Future<Uint8List?> generateKeyPair(String keypairName, int size,
      {String? password}) async {
    await _prepareStorageIfNeeded();
    // We are generating the keypair in an isolate
    await _spawnIsolateWorkerIfNeeded();
    Completer<ByteBuffer> keypairCompleter = new Completer<ByteBuffer>();
    _isolateWorkCompleters.add(keypairCompleter);
    _toIsolateWorker.send(size);
    ByteBuffer keypairData = await keypairCompleter.future;
    int privateKeyLength = keypairData.asByteData().getUint32(0);
    Uint8List privateKey = keypairData.asUint8List(4, privateKeyLength);
    Uint8List publicKey = keypairData.asUint8List(4 + privateKeyLength);
    await _storage.put(keypairName + _privateKeySuffix, privateKey);
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
