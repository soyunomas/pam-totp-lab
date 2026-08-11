# Cliente Android OCRA — diseño

## Objetivo

Crear un cliente Flutter Android pequeño para los perfiles de `pam_ocra_challenge`. Debe enrolarse mediante QR, conservar el secreto cifrado y calcular exclusivamente respuestas para `OCRA-1:HOTP-SHA256-8:QN10` conforme a RFC 6287.

## Alcance

- Proyecto Android en `pam_ocra_challenge/mobile/` con nombre visible `OCRA Client`.
- Varios perfiles identificados por host, usuario, servicio y `key_id`.
- Enrolamiento y rotación mediante QR generado opcionalmente por `ocra-enroll`.
- Entrada manual de un desafío decimal de exactamente 10 dígitos.
- Respuesta decimal de exactamente 8 dígitos, ocultable y eliminada de la interfaz después de 30 segundos.
- Sin red, telemetría, logs sensibles ni copia automática al portapapeles.

Quedan fuera del MVP la sincronización, copias en nube, iOS, notificaciones, lectura OCR del terminal y suites OCRA configurables.

## Protocolo criptográfico

La app acepta únicamente la suite literal `OCRA-1:HOTP-SHA256-8:QN10` y secretos Base32 mayúsculos que decodifiquen exactamente 32 bytes.

Para un desafío `Q`:

1. convertir sus 10 dígitos a entero decimal;
2. codificar el entero en bytes big-endian mínimos;
3. colocarlos al inicio de un campo de 128 bytes y rellenar a la derecha con cero;
4. calcular `HMAC-SHA256(K, OCRASuite || 0x00 || Q)`;
5. aplicar truncado dinámico HOTP y reducir módulo `100000000`;
6. devolver ocho dígitos con ceros iniciales.

Esta codificación coincide con RFC 6287 y con `ocra_suite.c`.

## Enrolamiento QR

`ocra-enroll add` y `rotate` admitirán `--qr` junto a `--client-profile`. El perfil de archivo seguirá formando parte de la transacción existente. El QR se renderizará desde el registro nuevo antes del commit del servidor; en rotación aparecerá antes del desafío de confirmación para que la app pueda calcularlo. Si `qrencode` falla, la operación hará rollback.

El payload será una URI percent-encoded:

```text
pam-ocra://enroll?v=1&host=HOST&user=USER&service=SERVICE&suite=OCRA-1%3AHOTP-SHA256-8%3AQN10&key_id=16HEX&secret=BASE32
```

`host` procede de `gethostname()`. Todos los campos tendrán límites y validación cerrada. `ocra-enroll` enviará la URI por `stdin` a `/usr/bin/qrencode`; nunca aparecerá en argumentos, logs o mensajes de error. Un fallo al renderizar hará fallar la operación solicitada con `--qr`.

Tras confirmar que el móvil funciona, el operador puede eliminar el perfil de cliente del servidor si el teléfono será el único cliente, conservando el secreto root-only del servidor.

## App y almacenamiento

- `mobile_scanner` captura únicamente el QR de enrolamiento.
- Un parser puro Dart valida esquema, versión, campos, duplicados y tamaños antes de almacenar.
- `flutter_secure_storage` guarda cada perfil cifrado mediante Android Keystore; preferencias normales solo podrán contener metadatos no secretos si fueran necesarias.
- Una rotación con la misma identidad lógica y `key_id` nuevo sustituye el perfil tras confirmación del usuario. Un QR idéntico es idempotente.
- La app no solicitará permiso de red. La cámara se solicitará solo al iniciar el escáner.

La interfaz tendrá tres vistas: lista de perfiles, escáner de enrolamiento y cálculo de respuesta. Los errores serán genéricos y no mostrarán el secreto.

## Pruebas y aceptación

- Tests unitarios del núcleo con vectores de la implementación de referencia RFC 6287 para codificación y truncado, además de vectores `QN10` independientes cruzados con el módulo C.
- Tests del parser para URI válida, suite/versiones desconocidas, Base32 inválido, campos repetidos o ausentes y longitudes incorrectas.
- Tests del repositorio seguro con una implementación en memoria.
- Widget tests para enrolamiento, desafío inválido, cálculo y ocultación de respuesta.
- Tests C para que `--qr` no filtre el secreto en argv/logs y coloque el QR antes de la confirmación de rotación.
- `flutter analyze`, `flutter test`, pruebas dirigidas de `ocra-enroll` y build APK debug deben pasar.

El MVP se acepta cuando un perfil creado por `ocra-enroll --qr`, escaneado en Android, produce para el mismo desafío exactamente la respuesta aceptada por `pam_ocra_challenge`.

## Seguridad operativa

El QR contiene la clave compartida: debe mostrarse en consola local, sin capturas ni grabación. La app no convierte OCRA en resistente a phishing en tiempo real. El módulo y el cliente continúan siendo software de laboratorio hasta completar el piloto manual.
