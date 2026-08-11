# pam_totp_enroll

Herramienta de enrolamiento **por línea de comandos** para los módulos TOTP de `pam-totp-lab`. Genera un secreto aleatorio de 160 bits, construye un URI `otpauth://`, muestra un QR en la terminal y **no escribe el secreto en disco hasta que el usuario demuestre que el móvil quedó correctamente configurado introduciendo un TOTP válido**.

No es un módulo PAM. Su salida por defecto, `~/.google_authenticator`, es compatible directamente con `pam_strict_totp`.

## Propiedades

- Generación criptográfica mediante `secrets.token_bytes(20)`.
- TOTP RFC 6238 con HMAC-SHA1, 6 dígitos y periodo de 30 segundos.
- Ventana de verificación de ±1 periodo, alineada con `pam_strict_totp`.
- QR de terminal mediante `qrencode`.
- El URI que contiene el secreto se pasa a `qrencode` por **stdin**, no como argumento del proceso, para evitar exponerlo en `ps`.
- Escritura atómica del secreto con modo `0600`.
- No sobrescribe un enrolamiento existente salvo uso explícito de `--force`.
- Tres intentos de verificación; si fallan, no se escribe ningún secreto.

## Dependencias

Linux Mint / Debian / Ubuntu:

```bash
make deps
```

Equivale a instalar:

```bash
sudo apt install python3 qrencode
```

No requiere módulos Python externos ni `oathtool`.

## Pruebas antes de usar

```bash
make verify
```

La puerta `verify` comprueba sintaxis Python y ejecuta pruebas sobre:

- vector oficial RFC 6238 SHA-1;
- ventana TOTP ±30 segundos y validación de formato;
- codificación del URI `otpauth://`;
- generación Base32 sin padding;
- escritura `0600`;
- rechazo de sobrescritura accidental;
- sustitución segura de un symlink con `--force` sin modificar su destino;
- flujo completo de enrolamiento correcto;
- garantía de que códigos incorrectos no crean el archivo;
- garantía de que un archivo existente detiene el proceso antes de generar un nuevo secreto;
- ausencia del secreto en los argumentos de `qrencode`;
- fallo cerrado si `qrencode` no está disponible.

## Uso desde el repositorio

```bash
cd pam_totp_enroll
make verify
python3 pam_totp_enroll.py
```

La herramienta mostrará un QR. Escanéalo con una aplicación compatible con TOTP y escribe el código de seis dígitos que aparezca en el móvil. El código se solicita sin eco en la terminal.

Tras validarlo correctamente se crea:

```text
~/.google_authenticator
```

con permisos `0600`.

### Personalizar issuer y cuenta

```bash
python3 pam_totp_enroll.py \
  --issuer "Linux Mint" \
  --account "$USER"
```

### Instalar el comando

```bash
sudo make install
pam-totp-enroll --issuer "Linux Mint" --account "$USER"
```

Por defecto se instala como `/usr/local/bin/pam-totp-enroll`. Para desinstalar:

```bash
sudo make uninstall
```

## Rotar un secreto existente

Por seguridad, un archivo existente hace fallar el enrolamiento **antes de generar un secreto nuevo**. Para una rotación deliberada:

```bash
pam-totp-enroll --force
```

`--force` sólo sustituye el archivo después de verificar correctamente el nuevo TOTP. La escritura final es atómica.

## Integración con pam_strict_totp

Una vez finalizado el enrolamiento, `pam_strict_totp` puede leer directamente el archivo generado. No es necesario transformar el secreto.

Ejemplo de comprobación:

```bash
stat -c '%a %U %n' ~/.google_authenticator
```

Debe mostrar modo `600` y el usuario correcto antes de activar PAM.

## Modelo de seguridad

El QR y el URI `otpauth://` contienen el secreto TOTP. No hagas capturas de pantalla, no los registres en logs y no los transmitas por canales no confiables. La herramienta no imprime el URI ni el secreto en texto y sólo conserva el secreto en memoria durante el enrolamiento.

La herramienta valida que el móvil conoce el secreto antes de persistirlo, pero no puede proteger un terminal ya comprometido. TOTP tampoco evita phishing en tiempo real.

## Prueba de PAM

No modifiques inicialmente `/etc/pam.d/common-auth`. Conserva una sesión administrativa o consola local de recuperación y prueba primero con una cuenta no crítica, siguiendo las precauciones del README principal y de `pam_strict_totp`.
