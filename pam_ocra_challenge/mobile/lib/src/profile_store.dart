import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'profile.dart';

abstract interface class ProfileStore {
  Future<List<OcraProfile>> list();
  Future<void> save(OcraProfile profile);
  Future<void> delete(String identity);
}

class MemoryProfileStore implements ProfileStore {
  final Map<String, OcraProfile> _profiles = {};

  @override
  Future<List<OcraProfile>> list() async {
    final result = _profiles.values.toList()
      ..sort((left, right) => left.identity.compareTo(right.identity));
    return result;
  }

  @override
  Future<void> save(OcraProfile profile) async {
    _profiles[profile.identity] = profile.validated();
  }

  @override
  Future<void> delete(String identity) async {
    _profiles.remove(identity);
  }
}

class SecureProfileStore implements ProfileStore {
  SecureProfileStore({FlutterSecureStorage? storage})
    : _storage =
          storage ??
          const FlutterSecureStorage(
            aOptions: AndroidOptions(
              resetOnError: false,
              migrateWithBackup: false,
            ),
          );

  static const _prefix = 'ocra-profile-v1:';
  final FlutterSecureStorage _storage;

  String _key(String identity) =>
      '$_prefix${base64UrlEncode(sha256.convert(utf8.encode(identity)).bytes)}';

  @override
  Future<List<OcraProfile>> list() async {
    final stored = await _storage.readAll();
    final profiles = <OcraProfile>[];
    for (final entry in stored.entries) {
      if (entry.key.startsWith(_prefix)) {
        profiles.add(OcraProfile.fromJson(entry.value));
      }
    }
    profiles.sort((left, right) => left.identity.compareTo(right.identity));
    return profiles;
  }

  @override
  Future<void> save(OcraProfile profile) => _storage.write(
    key: _key(profile.identity),
    value: profile.validated().toJson(),
  );

  @override
  Future<void> delete(String identity) => _storage.delete(key: _key(identity));
}
