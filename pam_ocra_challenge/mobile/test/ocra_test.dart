import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:ocra_client/src/ocra.dart';

void main() {
  group('OCRA-1:HOTP-SHA256-8:QN10', () {
    final secret = Uint8List.fromList(
      ascii.encode('12345678901234567890123456789012'),
    );

    test('matches independently verified server vectors', () {
      expect(computeOcraResponse(secret, '0123456789'), '51707911');
      expect(computeOcraResponse(secret, '1234567890'), '75619513');
    });

    test('rejects a challenge that is not exactly ten ASCII digits', () {
      for (final value in ['123456789', '12345678901', '123456789x']) {
        expect(() => computeOcraResponse(secret, value), throwsFormatException);
      }
    });

    test('rejects secrets that are not exactly 32 bytes', () {
      expect(
        () => computeOcraResponse(Uint8List(31), '1234567890'),
        throwsArgumentError,
      );
    });

    test('strictly decodes the 32-byte server Base32 format', () {
      final decoded = decodeBase32Secret(
        'AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPQ',
      );
      expect(decoded, orderedEquals(List<int>.generate(32, (index) => index)));
      expect(() => decodeBase32Secret('aaa'), throwsFormatException);
      expect(() => decodeBase32Secret('AAAA='), throwsFormatException);
    });
  });
}
