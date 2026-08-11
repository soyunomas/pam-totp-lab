import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:ocra_client/src/app.dart';
import 'package:ocra_client/src/profile.dart';
import 'package:ocra_client/src/profile_store.dart';

import 'profile_test.dart';

void main() {
  testWidgets('enrolls a scanned profile and lists its identity', (
    tester,
  ) async {
    final store = MemoryProfileStore();
    await tester.pumpWidget(
      OcraApp(
        store: store,
        enrollmentPageBuilder: (context) => Scaffold(
          body: TextButton(
            onPressed: () => Navigator.pop(context, validEnrollmentUri),
            child: const Text('Simular QR'),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();
    expect(find.text('No hay perfiles enrolados'), findsOneWidget);

    await tester.tap(find.byIcon(Icons.qr_code_scanner));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Simular QR'));
    await tester.pumpAndSettle();

    expect(find.text('alice@server.example/sshd'), findsOneWidget);
  });

  testWidgets('computes and then hides an OCRA response', (tester) async {
    final store = MemoryProfileStore();
    await store.save(_profile());
    await tester.pumpWidget(OcraApp(store: store));
    await tester.pumpAndSettle();
    await tester.tap(find.text('alice@server.example/sshd'));
    await tester.pumpAndSettle();

    await tester.enterText(find.byKey(const Key('challenge')), '1234567890');
    await tester.tap(find.text('Calcular respuesta'));
    await tester.pump();
    expect(find.text('75619513'), findsOneWidget);

    await tester.pump(const Duration(seconds: 30));
    expect(find.byKey(const Key('response')), findsNothing);
  });

  testWidgets('does not calculate malformed challenges', (tester) async {
    final store = MemoryProfileStore();
    await store.save(_profile());
    await tester.pumpWidget(OcraApp(store: store));
    await tester.pumpAndSettle();
    await tester.tap(find.text('alice@server.example/sshd'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('challenge')), '123');
    await tester.tap(find.text('Calcular respuesta'));
    await tester.pump();
    expect(find.text('Introduce exactamente 10 dígitos'), findsOneWidget);
  });
}

OcraProfile _profile() => OcraProfile.parseEnrollmentUri(
  validEnrollmentUri.replaceFirst(
    'AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPQ',
    'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA',
  ),
);
