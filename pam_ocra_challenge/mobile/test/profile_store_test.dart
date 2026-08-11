import 'package:flutter_test/flutter_test.dart';
import 'package:ocra_client/src/profile.dart';
import 'package:ocra_client/src/profile_store.dart';

import 'profile_test.dart';

void main() {
  test('saving a rotated profile replaces the same logical identity', () async {
    final store = MemoryProfileStore();
    final original = OcraProfile.parseEnrollmentUri(validEnrollmentUri);
    final rotated = OcraProfile.parseEnrollmentUri(
      validEnrollmentUri.replaceFirst('0123456789abcdef', 'fedcba9876543210'),
    );

    await store.save(original);
    await store.save(rotated);

    final profiles = await store.list();
    expect(profiles, hasLength(1));
    expect(profiles.single.keyId, 'fedcba9876543210');
    await store.delete(rotated.identity);
    expect(await store.list(), isEmpty);
  });

  test('serializing a profile round-trips every validated field', () {
    final profile = OcraProfile.parseEnrollmentUri(validEnrollmentUri);
    expect(OcraProfile.fromJson(profile.toJson()), profile);
  });
}
