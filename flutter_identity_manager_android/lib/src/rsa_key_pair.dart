import 'dart:typed_data';
import 'dart:math';

import 'package:pointycastle/api.dart';
import 'package:pointycastle/asn1.dart';
import 'package:pointycastle/asn1/primitives/asn1_sequence.dart';
import 'package:pointycastle/export.dart';

class RSAKeyPairFactory {
  final RSAKeyGenerator _generator;

  RSAKeyPairFactory(int keySize) : _generator = _init(keySize);

  static RSAKeyGenerator _init(int keySize) {
    SecureRandom secureRandom = new FortunaRandom();
    Random seedSource = new Random.secure();
    Uint8List seed = new Uint8List(32);
    for (int i = 0; i < seed.length; i++) {
      seed[i] = seedSource.nextInt(256);
    }
    secureRandom.seed(new KeyParameter(seed));
    return RSAKeyGenerator()
      ..init(new ParametersWithRandom(
          new RSAKeyGeneratorParameters(BigInt.parse('65537'), keySize, 64),
          secureRandom));
  }

  RSAKeyPair next() {
    return new RSAKeyPair.cast(_generator.generateKeyPair());
  }
}

//https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem
class RSAKeyPair extends AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> {
  static final ASN1Object _rsaIdentifier = new ASN1Sequence(elements: [
    new ASN1ObjectIdentifier.fromIdentifierString('1.2.840.113549.1.1.1'),
    new ASN1Null()
  ]);
  static final ASN1Integer _pkcs1RsaPrivateKeyVersion =
      new ASN1Integer(new BigInt.from(0));
  static final ASN1Integer _pkcs8RsaPrivateKeyVersion =
      new ASN1Integer(new BigInt.from(0));

  static bool _sameKeys(RSAKeyPair a, RSAKeyPair b) {
    return a.publicKey.exponent == b.publicKey.exponent &&
        a.publicKey.modulus == b.publicKey.modulus &&
        a.privateKey.exponent == b.privateKey.exponent &&
        a.privateKey.modulus == b.privateKey.modulus;
  }

  RSAKeyPair(RSAPublicKey publicKey, RSAPrivateKey privateKey)
      : super(publicKey, privateKey);
  RSAKeyPair.cast(AsymmetricKeyPair<PublicKey, PrivateKey> generic)
      : this(generic.publicKey as RSAPublicKey,
            generic.privateKey as RSAPrivateKey);

  @override
  bool operator ==(Object other) {
    if (other is RSAKeyPair) {
      return _sameKeys(this, other);
    } else if (other is AsymmetricKeyPair) {
      return this == new RSAKeyPair.cast(other);
    } else {
      return false;
    }
  }

  Uint8List pkcs1EncodeRSAPublicKey() => new ASN1Sequence(elements: [
        new ASN1Integer(this.publicKey.modulus),
        new ASN1Integer(this.publicKey.exponent)
      ]).encode();

//https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.1.1
  Uint8List pkcs1EncodeRSAPrivateKey() => new ASN1Sequence(elements: [
        _pkcs1RsaPrivateKeyVersion,
        new ASN1Integer(this.privateKey.modulus),
        new ASN1Integer(this.privateKey.publicExponent),
        new ASN1Integer(this.privateKey.privateExponent),
        new ASN1Integer(this.privateKey.p),
        new ASN1Integer(this.privateKey.q),
        new ASN1Integer(_exponent1(this.privateKey)),
        new ASN1Integer(_exponent2(this.privateKey)),
        new ASN1Integer(_coefficient(this.privateKey)),
      ]).encode();

  static BigInt _exponent1(RSAPrivateKey key) =>
      key.privateExponent! % (key.p! - new BigInt.from(1));
  static BigInt _exponent2(RSAPrivateKey key) =>
      key.privateExponent! % (key.q! - new BigInt.from(1));
  static BigInt _coefficient(RSAPrivateKey key) => key.q!.modInverse(key.p!);

  Uint8List pkcs8EncodeRSAPublicKey() => new ASN1Sequence(elements: [
        _rsaIdentifier,
        new ASN1BitString(stringValues: pkcs1EncodeRSAPublicKey())
      ]).encode();

  Uint8List pkcs8EncodeRSAPrivateKey() => new ASN1Sequence(elements: [
        _pkcs8RsaPrivateKeyVersion,
        _rsaIdentifier,
        new ASN1OctetString(octets: pkcs1EncodeRSAPrivateKey())
      ]).encode();
}
