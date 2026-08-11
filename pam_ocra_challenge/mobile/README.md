# OCRA Client para Android

Cliente Flutter sin conexión para `pam_ocra_challenge`. Implementa RFC 6287
con la suite fija `OCRA-1:HOTP-SHA256-8:QN10`, guarda varios perfiles en el
almacén seguro de Android y solo acepta los QR emitidos por `ocra-enroll`.

## APK listo para instalar

El repositorio incluye el
[APK Android release optimizado](../app/ocra-client-android-release.apk), junto
con su [SHA-256](../app/SHA256SUMS). Instálalo mediante:

```bash
adb install -r ../app/ocra-client-android-release.apk
```

## Compilar e instalar

```bash
cd pam_ocra_challenge/mobile
flutter pub get
flutter build apk --release --obfuscate \
  --split-debug-info=build/release-symbols
adb install -r build/app/outputs/flutter-apk/app-release.apk
```

También puede ejecutarse directamente en un teléfono conectado:

```bash
flutter run
```

## Uso

1. En el servidor genera el QR con `ocra-enroll add ... --qr`.
2. Abre **OCRA Client**, pulsa **Enrolar** y escanéalo.
3. Al iniciar sesión por SSH, introduce en la app el desafío de 10 dígitos.
4. Escribe en SSH la respuesta de 8 dígitos. La app la oculta a los 30 segundos.

El QR contiene el secreto: escanéalo en privado y no lo fotografíes ni lo
conserves. La aplicación no solicita permiso de red; la cámara solo se usa para
el enrolamiento.
