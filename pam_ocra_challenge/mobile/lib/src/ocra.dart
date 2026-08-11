import 'dart:convert';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

const ocraSuite = 'OCRA-1:HOTP-SHA256-8:QN10';
const _base32Alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

Uint8List decodeBase32Secret(String value) {
  if (value.length != 52 || !RegExp(r'^[A-Z2-7]+$').hasMatch(value)) {
    throw const FormatException('Invalid OCRA secret');
  }

  final output = BytesBuilder(copy: false);
  var accumulator = 0;
  var bits = 0;
  for (final codeUnit in value.codeUnits) {
    final digit = _base32Alphabet.indexOf(String.fromCharCode(codeUnit));
    accumulator = (accumulator << 5) | digit;
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      output.addByte((accumulator >> bits) & 0xff);
      accumulator &= (1 << bits) - 1;
    }
  }
  final decoded = output.takeBytes();
  if (decoded.length != 32 || accumulator != 0) {
    throw const FormatException('Invalid OCRA secret');
  }
  return decoded;
}

String computeOcraResponse(Uint8List secret, String challenge) {
  if (secret.length != 32) {
    throw ArgumentError.value(secret.length, 'secret', 'must be 32 bytes');
  }
  if (!RegExp(r'^\d{10}$').hasMatch(challenge)) {
    throw const FormatException('Challenge must contain ten digits');
  }

  final suiteBytes = utf8.encode(ocraSuite);
  final message = Uint8List(suiteBytes.length + 1 + 128);
  message.setRange(0, suiteBytes.length, suiteBytes);

  var question = BigInt.parse(challenge);
  final encoded = <int>[];
  do {
    encoded.add((question & BigInt.from(0xff)).toInt());
    question >>= 8;
  } while (question != BigInt.zero);
  for (var index = 0; index < encoded.length; index++) {
    message[suiteBytes.length + 1 + index] =
        encoded[encoded.length - 1 - index];
  }

  final digest = Hmac(sha256, secret).convert(message).bytes;
  final offset = digest.last & 0x0f;
  final truncated =
      ((digest[offset] & 0x7f) << 24) |
      (digest[offset + 1] << 16) |
      (digest[offset + 2] << 8) |
      digest[offset + 3];
  return (truncated % 100000000).toString().padLeft(8, '0');
}
