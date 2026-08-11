import 'package:flutter/material.dart';

import 'profile.dart';
import 'profile_store.dart';
import 'response_page.dart';

class ProfileListPage extends StatefulWidget {
  const ProfileListPage({
    required this.store,
    required this.enrollmentPageBuilder,
    super.key,
  });

  final ProfileStore store;
  final WidgetBuilder enrollmentPageBuilder;

  @override
  State<ProfileListPage> createState() => _ProfileListPageState();
}

class _ProfileListPageState extends State<ProfileListPage> {
  List<OcraProfile>? _profiles;

  @override
  void initState() {
    super.initState();
    _reload();
  }

  Future<void> _reload() async {
    final profiles = await widget.store.list();
    if (mounted) setState(() => _profiles = profiles);
  }

  Future<void> _enroll() async {
    final raw = await Navigator.of(
      context,
    ).push<String>(MaterialPageRoute(builder: widget.enrollmentPageBuilder));
    if (raw == null || !mounted) return;
    try {
      final profile = OcraProfile.parseEnrollmentUri(raw);
      await widget.store.save(profile);
      await _reload();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Perfil enrolado de forma segura')),
        );
      }
    } on FormatException {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('El QR no es un perfil OCRA válido')),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final profiles = _profiles;
    return Scaffold(
      appBar: AppBar(title: const Text('OCRA Client')),
      body: profiles == null
          ? const Center(child: CircularProgressIndicator())
          : profiles.isEmpty
          ? const Center(child: Text('No hay perfiles enrolados'))
          : ListView.separated(
              padding: const EdgeInsets.all(12),
              itemCount: profiles.length,
              separatorBuilder: (_, _) => const SizedBox(height: 8),
              itemBuilder: (context, index) {
                final profile = profiles[index];
                return Card(
                  child: ListTile(
                    leading: const Icon(Icons.key),
                    title: Text(profile.identity),
                    subtitle: Text('Clave ${profile.keyId}'),
                    trailing: const Icon(Icons.chevron_right),
                    onTap: () => Navigator.of(context).push<void>(
                      MaterialPageRoute(
                        builder: (_) => ResponsePage(profile: profile),
                      ),
                    ),
                  ),
                );
              },
            ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _enroll,
        icon: const Icon(Icons.qr_code_scanner),
        label: const Text('Enrolar'),
      ),
    );
  }
}
