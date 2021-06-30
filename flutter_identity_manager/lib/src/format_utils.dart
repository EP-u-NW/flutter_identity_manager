import 'dart:typed_data';
import 'dart:convert';

String privatePkcs8DerToPem(Uint8List der) {
  return '-----BEGIN PRIVATE KEY-----\r\n' +
      _constarinLineLength(base64.encode(der), 64) +
      '\r\n-----END PRIVATE KEY-----';
}

const String _beginCertificate = '-----BEGIN CERTIFICATE-----';
const String _endCertificate = '-----END CERTIFICATE-----';

Uint8List x509PemToDer(String pem) {
  String der = pem
      .replaceFirst(_beginCertificate, '')
      .replaceFirst(_endCertificate, '')
      .replaceAll('\n', '')
      .trim();
  return base64.decode(der);
}

String x509DerToPem(Uint8List der) {
  return '$_beginCertificate\r\n' +
      _constarinLineLength(base64.encode(der), 64) +
      '\r\n$_endCertificate';
}

String _constarinLineLength(String input, [int maxLength = 64]) {
  List<String> lines = [];
  while (input.length > maxLength) {
    lines.add(input.substring(0, maxLength));
    input = input.substring(maxLength);
  }
  if (input.length != 0) {
    lines.add(input);
  }
  return lines.join('\r\n');
}
