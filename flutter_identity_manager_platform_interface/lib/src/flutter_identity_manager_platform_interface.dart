import 'dart:typed_data';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';
import 'flutter_identity_manager_platform_unsupported.dart';

/// The interface that implementations of flutter_identity_manager must implement.
///
/// Platform implementations should extend this class rather than implement it as `flutter_identity_manager`
/// does not consider newly added methods to be breaking changes. Extending this class
/// (using `extends`) ensures that the subclass will get the default implementation, while
/// platform implementations that `implements` this interface will be broken by newly added
/// [FlutterIdentityManagerPlatform] methods.
abstract class FlutterIdentityManagerPlatform extends PlatformInterface {
  /// Constructs a FlutterIdentityManagerPlatform.
  FlutterIdentityManagerPlatform() : super(token: _token);

  static final Object _token = Object();

  static FlutterIdentityManagerPlatform _instance =
      new FlutterIdentityManagerPlatformUnsupported();

  /// The default instance of [FlutterIdentityManagerPlatform] to use,
  /// defaults to [FlutterIdentityManagerPlatformUnsupported].
  static FlutterIdentityManagerPlatform get instance => _instance;

  /// Platform-specific plugins should set this with their own platform-specific
  /// class that extends [FlutterIdentityManagerPlatform] when they register themselves.
  static set instance(FlutterIdentityManagerPlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  /// Tries to generate a keypair with the given tag and size and returns
  /// the public key in DER PKCS1 format on success, or null otherwise.
  ///
  /// The private key of this keypair will be secured by password.
  Future<Uint8List?> generateKeyPair(String keypairName, int size, {String? password});

  /// Loads the public key associated with this keypair
  /// in DER PKCS1 format, or returns null if there is no
  /// public key associated with this keypair name.
  Future<Uint8List?> loadPublicKey(String keypairName, {String? password});

  /// Deletes a keypair, returns [true] if something was deleted,
  /// false otherwise.
  Future<bool> deleteKeyPair(String keypairName);

  /// Deletes a certificate, returns [true] if something was deleted,
  /// false otherwise.
  Future<bool> deleteCert(String certName);

  /// Saves the DER encoded X509 certificate under the given
  /// certName.
  Future<bool> saveCert(String certName, Uint8List derData);

  /// Loads all data needed to create an identity in a format
  /// suitable for the current platform.
  Future<IdentityDescription?> loadIdentity(
      String keypairName, String certName, String? password);
}

class IdentityDescription {
  /// The password the underlying platform needs to use this
  /// private key. Might not be the same as the password given
  /// to [loadIdentity] when this description was created.
  final String? neededPassword;

  /// If set to [true], [certBytes] and [privateKeyBytes] are
  /// assumed to be in proper DER formating, if set to false
  /// it is assumed that they are already preformated in a
  /// suitable format for a [SecurityContext] on the current
  /// platform.
  ///
  /// Proper DER formating for a certificate means a DER
  /// encoded X509 certificate, while for a private key
  /// it should be in DER pkcs8 format.
  final bool isDERFormated;
  final Uint8List certBytes;
  final Uint8List privateKeyBytes;

  IdentityDescription(this.certBytes, this.privateKeyBytes, this.isDERFormated,
      this.neededPassword);
}
