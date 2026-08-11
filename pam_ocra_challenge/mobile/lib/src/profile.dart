import 'dart:convert';

import 'ocra.dart';

class OcraProfile {
  const OcraProfile({
    required this.host,
    required this.user,
    required this.service,
    required this.suite,
    required this.keyId,
    required this.secret,
  });

  factory OcraProfile.parseEnrollmentUri(String input) {
    final uri = Uri.tryParse(input);
    const requiredFields = {
      'v',
      'host',
      'user',
      'service',
      'suite',
      'key_id',
      'secret',
    };
    if (uri == null ||
        uri.scheme != 'pam-ocra' ||
        uri.host != 'enroll' ||
        uri.path.isNotEmpty ||
        uri.queryParametersAll.keys
            .toSet()
            .difference(requiredFields)
            .isNotEmpty ||
        requiredFields
            .difference(uri.queryParametersAll.keys.toSet())
            .isNotEmpty ||
        uri.queryParametersAll.values.any((values) => values.length != 1)) {
      throw const FormatException('Invalid enrollment QR');
    }
    String field(String name) => uri.queryParametersAll[name]!.single;
    if (field('v') != '1') {
      throw const FormatException('Unsupported enrollment version');
    }
    return OcraProfile(
      host: field('host'),
      user: field('user'),
      service: field('service'),
      suite: field('suite'),
      keyId: field('key_id'),
      secret: field('secret'),
    ).validated();
  }

  factory OcraProfile.fromJson(String encoded) {
    final value = jsonDecode(encoded);
    if (value is! Map<String, dynamic> ||
        value.keys.toSet().difference({
          'host',
          'user',
          'service',
          'suite',
          'key_id',
          'secret',
        }).isNotEmpty ||
        value.length != 6) {
      throw const FormatException('Invalid stored profile');
    }
    String field(String key) {
      final result = value[key];
      if (result is! String)
        throw const FormatException('Invalid stored profile');
      return result;
    }

    return OcraProfile(
      host: field('host'),
      user: field('user'),
      service: field('service'),
      suite: field('suite'),
      keyId: field('key_id'),
      secret: field('secret'),
    ).validated();
  }

  final String host;
  final String user;
  final String service;
  final String suite;
  final String keyId;
  final String secret;

  String get identity => '$user@$host/$service';

  OcraProfile validated() {
    if (!RegExp(r'^[A-Za-z0-9.-]{1,253}$').hasMatch(host) ||
        host.startsWith('.') ||
        host.endsWith('.') ||
        !RegExp(r'^[A-Za-z0-9._-]{1,64}$').hasMatch(user) ||
        !RegExp(r'^[A-Za-z0-9_-]{1,64}$').hasMatch(service) ||
        suite != ocraSuite ||
        !RegExp(r'^[0-9a-f]{16}$').hasMatch(keyId)) {
      throw const FormatException('Invalid OCRA profile');
    }
    decodeBase32Secret(secret);
    return this;
  }

  String toJson() => jsonEncode({
    'host': host,
    'user': user,
    'service': service,
    'suite': suite,
    'key_id': keyId,
    'secret': secret,
  });

  @override
  bool operator ==(Object other) =>
      other is OcraProfile &&
      host == other.host &&
      user == other.user &&
      service == other.service &&
      suite == other.suite &&
      keyId == other.keyId &&
      secret == other.secret;

  @override
  int get hashCode => Object.hash(host, user, service, suite, keyId, secret);
}
