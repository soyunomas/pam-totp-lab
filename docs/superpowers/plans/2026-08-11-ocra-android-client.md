# OCRA Android Client Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Entregar una app Flutter Android que se enrola por QR y calcula respuestas compatibles con `pam_ocra_challenge`.

**Architecture:** El núcleo criptográfico y el parser serán Dart puro. La UI consumirá un repositorio abstracto respaldado por Android Keystore; `ocra-enroll` producirá la URI y la enviará a `qrencode` por stdin.

**Tech Stack:** Flutter/Dart, `crypto`, `mobile_scanner`, `flutter_secure_storage`, C11, OpenSSL y `qrencode`.

## Global Constraints

- Suite única: `OCRA-1:HOTP-SHA256-8:QN10`.
- Secreto Base32 de 32 bytes, desafío decimal de 10 dígitos y respuesta de 8.
- Sin red, logs sensibles ni portapapeles automático.
- TDD para lógica Dart y cambios C; los archivos generados por Flutter están exentos.

---

### Task 1: Scaffold y núcleo OCRA

**Files:**
- Create: `pam_ocra_challenge/mobile/pubspec.yaml`
- Create: `pam_ocra_challenge/mobile/lib/src/ocra.dart`
- Test: `pam_ocra_challenge/mobile/test/ocra_test.dart`

**Interfaces:**
- Produces: `String computeOcraResponse(Uint8List secret, String challenge)` y `Uint8List decodeBase32Secret(String value)`.

- [ ] Generar el proyecto Android con package `dev.pamtotplab.ocra_client` y añadir dependencias.
- [ ] Escribir tests de vector cruzado, ceros iniciales y entradas inválidas; ejecutar `flutter test test/ocra_test.dart` y observar fallo por API ausente.
- [ ] Implementar Base32 estricto, campo Q de 128 bytes, HMAC-SHA256 y truncado dinámico.
- [ ] Repetir el test hasta verde y confirmar el vector contra `ocra-client`.
- [ ] Commit: `ocra-mobile: implement RFC 6287 response core`.

### Task 2: Perfil QR y almacenamiento seguro

**Files:**
- Create: `pam_ocra_challenge/mobile/lib/src/profile.dart`
- Create: `pam_ocra_challenge/mobile/lib/src/profile_store.dart`
- Test: `pam_ocra_challenge/mobile/test/profile_test.dart`
- Test: `pam_ocra_challenge/mobile/test/profile_store_test.dart`

**Interfaces:**
- Produces: `OcraProfile.parseEnrollmentUri(String)`, `OcraProfile.identity`, `ProfileStore.list/save/delete` y `SecureProfileStore`.

- [ ] Escribir tests para URI válida, duplicados, ausencia de campos, suite, `key_id`, Base32 y rotación; observar fallos por API ausente.
- [ ] Implementar modelo/parser inmutable con validación cerrada.
- [ ] Escribir tests contractuales del repositorio usando `MemoryProfileStore`; observar fallo.
- [ ] Implementar repositorio en memoria y adaptador `flutter_secure_storage` sin persistir secretos fuera del Keystore.
- [ ] Ejecutar ambos archivos de test hasta verde.
- [ ] Commit: `ocra-mobile: add secure QR profiles`.

### Task 3: Interfaz Android

**Files:**
- Create: `pam_ocra_challenge/mobile/lib/main.dart`
- Create: `pam_ocra_challenge/mobile/lib/src/app.dart`
- Create: `pam_ocra_challenge/mobile/lib/src/profile_list_page.dart`
- Create: `pam_ocra_challenge/mobile/lib/src/enrollment_page.dart`
- Create: `pam_ocra_challenge/mobile/lib/src/response_page.dart`
- Modify: `pam_ocra_challenge/mobile/android/app/src/main/AndroidManifest.xml`
- Test: `pam_ocra_challenge/mobile/test/app_test.dart`

**Interfaces:**
- Consumes: `ProfileStore`, `OcraProfile` y `computeOcraResponse`.

- [ ] Escribir widget tests para vacío, enrolamiento simulado, desafío inválido, respuesta y ocultación a 30 segundos; observar fallos.
- [ ] Implementar lista, escáner inyectable y formulario numérico accesible.
- [ ] Añadir solo permiso `CAMERA`, desactivar backup Android y evitar permiso de Internet.
- [ ] Ejecutar widget tests hasta verde.
- [ ] Commit: `ocra-mobile: build Android enrollment UI`.

### Task 4: QR desde ocra-enroll e integración

**Files:**
- Modify: `pam_ocra_challenge/tools/ocra_enroll.c`
- Modify: `pam_ocra_challenge/tests/test_enroll.c`
- Modify: `pam_ocra_challenge/Makefile`
- Modify: `pam_ocra_challenge/README.md`
- Create: `pam_ocra_challenge/mobile/README.md`

**Interfaces:**
- Produces: opción `--qr` para `add` y `rotate`, con URI por stdin a `/usr/bin/qrencode`.

- [ ] Añadir tests C con proveedor de QR inyectable que verifiquen URI, ausencia de secreto en argv/logs, rollback y orden anterior a confirmación; observar fallo.
- [ ] Implementar serialización percent-encoded y ejecución de `qrencode` por stdin con limpieza de buffers.
- [ ] Ejecutar `make -C pam_ocra_challenge test-enroll` hasta verde.
- [ ] Documentar alta, rotación, borrado del perfil local del servidor y build APK.
- [ ] Ejecutar `dart format`, `flutter analyze`, `flutter test`, build APK debug y una verificación dirigida C.
- [ ] Commit: `ocra: add Android QR enrollment client`.
