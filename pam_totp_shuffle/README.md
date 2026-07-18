# `pam_totp_shuffle`

Módulo PAM experimental que solicita los seis dígitos de un TOTP estándar en un orden aleatorio. La aplicación autenticadora no cambia: continúa generando un código RFC 6238 normal.

Ejemplo:

```text
Código mostrado por la aplicación: 123456
Prompt PAM: TOTP en orden 4-1-6-2-5-3:
Respuesta: 416253
```

El módulo reconstruye internamente `123456`, valida el TOTP mediante liboath y aplica el antirreplay común del repositorio.

## Alcance de seguridad

Este mecanismo no crea un factor adicional ni aumenta la fortaleza criptográfica de TOTP. Solo puede dificultar observaciones parciales en las que el atacante ve la respuesta pero no el prompt, o el prompt pero no la entrada.

No protege frente a phishing en tiempo real, grabación simultánea de pantalla y teclado, malware que capture el prompt y la respuesta, compromiso del secreto TOTP ni acceso `root` al sistema.

## Arquitectura

El módulo es completamente local. No utiliza red, daemon, broker, TPM ni hardware especial.

```text
Aplicación → PAM → pam_totp_shuffle.so
                     ├── ~/.pam_totp_shuffle
                     ├── liboath
                     └── /run/pam-totp-lab/ (antirreplay)
```

La lectura del fichero del usuario requiere cambios temporales de EUID, EGID y grupos. Está orientada a consumidores PAM aislados por proceso. No debe asumirse segura dentro de una aplicación PAM multihilo sin rediseñar ese acceso.

## Dependencias

```bash
sudo apt update
sudo apt install -y build-essential libpam0g-dev liboath-dev clang valgrind binutils
```

## Compilación y pruebas

```bash
cd pam_totp_shuffle
make test
make build
make hardening
make verify
```

La puerta completa cubre las 720 permutaciones posibles, generación aleatoria repetida, entradas inválidas, permisos inseguros, symlinks, hard links, secretos multilínea, GCC, Clang, análisis estático, sanitizers, Valgrind y hardening ELF.

La compilación de verificación trata todos los avisos admitidos como errores para impedir que una regresión se integre silenciosamente.

## Instalación

```bash
cd pam_totp_shuffle
sudo make install
```

## Crear el secreto

El secreto debe ser Base32 sin relleno, con caracteres `A-Z` y `2-7`, y entre 16 y 128 caracteres. Debe coincidir con la entrada configurada en la aplicación TOTP.

```bash
install -m 600 /dev/null ~/.pam_totp_shuffle
nano ~/.pam_totp_shuffle
chmod 600 ~/.pam_totp_shuffle
```

El archivo contiene una única línea:

```text
JBSWY3DPEHPK3PXP
```

Se rechazan archivos con propietario incorrecto, permisos para grupo u otros, symlinks, hard links, varias líneas o contenido no Base32.

## Configuración PAM

No lo añadas inicialmente a `common-auth`. Prueba primero un servicio aislado y conserva una sesión administrativa abierta.

```pam
auth required pam_unix.so
auth required pam_totp_shuffle.so
account required pam_permit.so
```

Para OpenSSH, la conversación PAM debe estar habilitada:

```text
UsePAM yes
KbdInteractiveAuthentication yes
```

## Opción `nullok`

```pam
auth required pam_totp_shuffle.so nullok
```

`nullok` devuelve `PAM_IGNORE` únicamente cuando `~/.pam_totp_shuffle` no existe. Un fichero presente pero inseguro, vacío o corrupto bloquea la autenticación. No se aceptan otras opciones.

## Antirreplay

Después de aceptar un código, el contador TOTP se registra bajo `/run/pam-totp-lab/`. El mismo contador no puede aceptarse dos veces mientras exista ese estado. El estado se pierde al reiniciar.

## Recuperación y desinstalación

Antes de desplegar, conserva una sesión administrativa abierta, prueba el módulo en otro terminal y confirma la sincronización horaria.

Para retirar el módulo, elimina primero su línea del servicio PAM y después ejecuta:

```bash
cd pam_totp_shuffle
sudo make uninstall
```

La desinstalación no elimina `~/.pam_totp_shuffle`.
