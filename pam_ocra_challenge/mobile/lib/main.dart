import 'package:flutter/material.dart';

import 'src/app.dart';
import 'src/profile_store.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(OcraApp(store: SecureProfileStore()));
}
