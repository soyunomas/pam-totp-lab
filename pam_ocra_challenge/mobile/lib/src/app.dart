import 'package:flutter/material.dart';

import 'enrollment_page.dart';
import 'profile_list_page.dart';
import 'profile_store.dart';

class OcraApp extends StatelessWidget {
  const OcraApp({required this.store, this.enrollmentPageBuilder, super.key});

  final ProfileStore store;
  final WidgetBuilder? enrollmentPageBuilder;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'OCRA Client',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xff315c49),
          brightness: Brightness.light,
        ),
        useMaterial3: true,
      ),
      darkTheme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xff71d6a8),
          brightness: Brightness.dark,
        ),
        useMaterial3: true,
      ),
      home: ProfileListPage(
        store: store,
        enrollmentPageBuilder:
            enrollmentPageBuilder ?? (context) => const EnrollmentPage(),
      ),
    );
  }
}
