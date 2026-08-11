# OCRA Client Android — APK release

Aplicación Android compilada en modo `release`, optimizada y con símbolos Dart
ofuscados. No es una compilación `debug`.

## Instalación

Descarga `ocra-client-android-release.apk` en el teléfono y ábrelo, o instala
desde un equipo con ADB:

```bash
adb install -r ocra-client-android-release.apk
```

SHA-256:

```text
ffd9c89d2ca4a6f2593558b7b68f98218f5ff20c94974ea22193ccd1b5a52b2a
```

Es una distribución directa para el laboratorio y no un paquete firmado para
Google Play. El código fuente y las instrucciones de compilación están en
[`../mobile`](../mobile/README.md).
