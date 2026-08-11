import 'package:flutter_test/flutter_test.dart';
import 'package:ocra_client/src/profile.dart';

const validEnrollmentUri =
    'pam-ocra://enroll?v=1&host=server.example&user=alice&service=sshd&'
    'suite=OCRA-1%3AHOTP-SHA256-8%3AQN10&key_id=0123456789abcdef&'
    'secret=AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPQ';

void main() {
  test('parses the complete versioned enrollment identity', () {
    final profile = OcraProfile.parseEnrollmentUri(validEnrollmentUri);
    expect(profile.host, 'server.example');
    expect(profile.user, 'alice');
    expect(profile.service, 'sshd');
    expect(profile.keyId, '0123456789abcdef');
    expect(profile.identity, 'alice@server.example/sshd');
  });

  test('rejects duplicate or missing enrollment fields', () {
    expect(
      () => OcraProfile.parseEnrollmentUri('$validEnrollmentUri&service=sudo'),
      throwsFormatException,
    );
    expect(
      () => OcraProfile.parseEnrollmentUri(
        validEnrollmentUri.replaceFirst('&host=server.example', ''),
      ),
      throwsFormatException,
    );
  });

  test('rejects an unknown suite, key id, or noncanonical secret', () {
    for (final uri in [
      validEnrollmentUri.replaceFirst('HOTP-SHA256', 'HOTP-SHA1'),
      validEnrollmentUri.replaceFirst('0123456789abcdef', 'xyz'),
      validEnrollmentUri.replaceFirst('AAAQE', 'aaaqe'),
    ]) {
      expect(() => OcraProfile.parseEnrollmentUri(uri), throwsFormatException);
    }
  });
}
