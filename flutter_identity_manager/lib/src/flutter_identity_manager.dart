import 'dart:typed_data';
import 'dart:convert';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:flutter_identity_manager_platform_interface/flutter_identity_manager_platform_interface.dart';
import 'flutter_identity_manager_init.dart' as Platforms;
import 'format_utils.dart';

/// An identity bundles a private key and a certificate.
/// It can be used set up a [SecurityContext].
class Identity {
  /// Loads the identity identified by name, or returns [null]
  /// if there is no matching identity.
  ///
  /// Depending on the platform, a password might be needed to load the identity,
  /// which is not necessarily the same password for using the private key
  /// using [privateKeyPassword], so even if you set `password` here,
  /// [privateKeyPassword] might be [null] if [privateKey] is not actually
  /// password protected on that platform.
  static Future<Identity?> load(String name, {String? password}) async {
    await _initalizeIndicesIfNeeded();
    if (_identities.has(name)) {
      IdentityDescription? description = await FlutterIdentityManagerPlatform
          .instance
          .loadIdentity(name + _keypairSubfix, name + _certSubfix, password);
      if (description != null) {
        if (description.isDERFormated) {
          Uint8List cert = ascii.encode(x509DerToPem(description.certBytes));
          Uint8List key =
              ascii.encode(privatePkcs8DerToPem(description.privateKeyBytes));
          return new Identity._(name, cert, key, description.neededPassword);
        } else {
          return new Identity._(name, description.certBytes,
              description.privateKeyBytes, description.neededPassword);
        }
      } else {
        throw new InconsistencyException();
      }
    } else {
      return null;
    }
  }

  /// Returns the names of all stored identities.
  static Future<Set<String>> allNames() async {
    await _initalizeIndicesIfNeeded();
    return _identities.all();
  }

  /// The name of the identity.
  final String name;

  bool _deleted;

  Identity._(
      this.name, this.certificate, this.privateKey, this.privateKeyPassword)
      : _deleted = false;

  /// Deletes the identity and all associated data.
  ///
  /// After deleting, all methods will throw [StateError]s!
  Future<bool> delete() async {
    _checkDeleted();
    if (await FlutterIdentityManagerPlatform.instance
            .deleteCert(name + _certSubfix) &&
        await FlutterIdentityManagerPlatform.instance
            .deleteKeyPair(name + _keypairSubfix)) {
      return _identities.remove(name);
    } else {
      return false;
    }
  }

  void _checkDeleted() {
    if (_deleted) {
      throw new StateError(
          'Can not perform this operation on a deleted object!');
    }
  }

  /// The associated certificate data in a format suitable for
  /// [SecurityContext.useCertificateChainBytes].
  final Uint8List certificate;

  /// The associated private key in a format suitable for
  /// [SecurityContext.usePrivateKeyBytes].
  final Uint8List privateKey;

  /// The password of the private key (or [null] if [privateKey]
  /// is not password protected] for use in [SecurityContext.usePrivateKeyBytes].
  final String? privateKeyPassword;
}

/// Used to build an [Identity].
class IdentityRequest {
  /// Creates a new identity request with the given [name].
  ///
  /// The associated private key will be of [size] length and
  /// secured with the given [password].
  ///
  /// If there already is an [Identity] or an ongoing request with
  /// this [name], a [StateError] will be thrown.
  static Future<IdentityRequest> create(String name,
      {String? password, int size = 4096}) async {
    await _initalizeIndicesIfNeeded();
    if (_requests.has(name)) {
      throw new StateError('A request with name $name already exists!');
    }
    if (_identities.has(name)) {
      throw new StateError('An identity with name $name already exists!');
    }
    Uint8List? publicKey = await FlutterIdentityManagerPlatform.instance
        .generateKeyPair(name + _keypairSubfix, size, password: password);
    if (publicKey != null) {
      _requests.add(name);
      return new IdentityRequest._(name, password, publicKey);
    } else {
      throw new InconsistencyException();
    }
  }

  /// Loads a curently ongoing request.
  ///
  /// The request is assumed to be secured by [password], but it is
  /// not guaranteed that it is actually checked if the [password]
  /// matches the request.
  ///
  /// If there is no ongoing request with this [name], [null] is returned.
  static Future<IdentityRequest?> load(String name, {String? password}) async {
    await _initalizeIndicesIfNeeded();
    if (_requests.has(name)) {
      Uint8List? publicKey = await FlutterIdentityManagerPlatform.instance
          .loadPublicKey(name + _keypairSubfix, password: password);
      if (publicKey != null) {
        return new IdentityRequest._(name, password, publicKey);
      } else {
        throw new InconsistencyException();
      }
    } else {
      return null;
    }
  }

  /// Returns the names of all ongoing requests.
  static Future<Set<String>> allNames() async {
    await _initalizeIndicesIfNeeded();
    return _requests.all();
  }

  /// The name of this request, which will also
  /// be the name of the identity once this request
  /// is [complete]d.
  final String name;

  final String? _password;
  bool _deleted;

  /// The DER encoded PKCS8 public key a certificate should
  /// be issued to to [complete] this request.
  final Uint8List publicKey;

  IdentityRequest._(this.name, this._password, Uint8List publicKeyPkcs8Der)
      : _deleted = false,
        publicKey = publicKeyPkcs8Der;

  /// Completes this request to an [Identity] by associating
  /// the private key with this pem encoded X509 certificate.
  ///
  /// The certificate must have been issued to the [publicKey].
  ///
  /// If this request was [create]d or [load]ed with a password,
  /// it will be passed on to the resulting identity.
  ///
  /// In the process of completion, this request will be [delete]d.
  Future<Identity> complete(String certificatePem) async {
    _checkDeleted();
    if (await FlutterIdentityManagerPlatform.instance
        .saveCert(name + _certSubfix, x509PemToDer(certificatePem))) {
      _requests.remove(name);
      _deleted = true;
      _identities.add(name);
      Identity? identity = await Identity.load(name, password: _password);
      if (identity != null) {
        return identity;
      } else {
        throw new InconsistencyException();
      }
    } else {
      throw new InconsistencyException();
    }
  }

  /// Deletes this request, so it can not be [load]ed again.
  ///
  /// After deleting, all methods will throw [StateError]s!
  Future<bool> delete() async {
    _checkDeleted();
    if (await FlutterIdentityManagerPlatform.instance
        .deleteKeyPair(name + _keypairSubfix)) {
      _deleted = true;
      return _requests.remove(name);
    } else {
      return false;
    }
  }

  void _checkDeleted() {
    if (_deleted) {
      throw new StateError(
          'Can not perform this operation on a deleted object!');
    }
  }
}

const String _keypairSubfix = 'Keypair';
const String _certSubfix = 'Certificate';

Future<void> _initalizeIndicesIfNeeded() async {
  if (!_hasIndices) {
    Platforms.init();
    _hasIndices = true;
    SharedPreferences preferences = await SharedPreferences.getInstance();
    _identities = new _Index('flutter_cert_manager_identities', preferences);
    _requests = new _Index('flutter_cert_manager_requests', preferences);
  }
}

bool _hasIndices = false;
late final _Index _identities;
late final _Index _requests;

class _Index {
  final String key;
  final Set<String> values;
  final SharedPreferences preferences;

  _Index(String key, SharedPreferences preferences)
      : key = key,
        preferences = preferences,
        values = new Set<String>.of(preferences.getStringList(key) ?? []);

  Set<String> all() {
    return new Set<String>.unmodifiable(values);
  }

  void add(String value) {
    if (values.add(value)) {
      _commit();
    }
  }

  void _commit() {
    preferences.setStringList(key, values.toList());
  }

  bool has(String value) {
    return values.contains(value);
  }

  bool remove(String value) {
    if (values.remove(value)) {
      _commit();
      return true;
    } else {
      return false;
    }
  }
}

/// Indicates that the actual data on the underlying platform
/// do not match the data in dart.
class InconsistencyException implements Exception {}
