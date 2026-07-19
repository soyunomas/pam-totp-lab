# `pam_totp_rollover`

Módulo PAM experimental que exige dos códigos TOTP de periodos consecutivos.
El primer código debe pertenecer exactamente al periodo actual y el segundo al
periodo siguiente.

```text
Primer código TOTP: 123456
                 espera hasta el cambio de periodo
Código TOTP del periodo siguiente: 654321
```

Utiliza TOTP estándar de seis dígitos, SHA-1 y periodos de 30 segundos. No
requiere una aplicación especial.

## Alcance de seguridad

El flujo dificulta utilizar un único código capturado con antelación: para
completar la autenticación se necesita acceso al generador durante dos periodos
consecutivos. No crea dos factores independientes y no protege frente a
phishing interactivo, malware, grabación completa ni compromiso del secreto.

El primer contador se consume antes de comenzar el segundo paso. Un fallo,
cancelación o timeout no permite reutilizarlo. El estado se guarda en
`/run/pam-totp-lab`, por lo que sobrevive a procesos PAM pero se pierde al
reiniciar el sistema. Cada actualización utiliza un archivo temporal, `fsync`,
renombrado atómico y sincronización del directorio.

## Compilación y pruebas

Dependencias para Debian o Ubuntu:

```bash
sudo apt install build-essential clang libpam0g-dev liboath-dev \
    libssl-dev valgrind binutils
```

Puerta rápida:

```bash
make verify-local
```

Puerta completa con GCC, Clang, análisis estático, ASan, UBSan, Valgrind y
hardening ELF:

```bash
make verify
```

También están disponibles `make test`, `make production` y `make hardening`.
Las pruebas usan relojes simulados y no esperan periodos TOTP reales.

## Enrolamiento

Registra un secreto Base32 compatible con TOTP estándar y guárdalo en el home
del usuario:

```bash
umask 077
head -c 20 /dev/urandom | base32 | tr -d '=\n' \
    > "$HOME/.pam_totp_rollover"
chmod 0600 "$HOME/.pam_totp_rollover"
```

El archivo debe cumplir estas condiciones:

- pertenecer al usuario;
- ser regular, modo `0600` y tener un solo enlace físico;
- contener 16–128 caracteres Base32 mayúsculos, sin `=` ni espacios;
- tener como máximo un salto de línea final;
- no ser un symlink ni un hard link.

El home debe pertenecer al usuario y no ser escribible por grupo u otros.

## Instalación y PAM

```bash
sudo make install
```

`make install` detecta el directorio PAM habitual de la distribución e instala
`pam_totp_rollover.so` como `root:root` con modo `0644`. No modifica ninguna
pila PAM: esa operación debe realizarla el administrador después de crear una
copia de seguridad.

Prueba primero en un servicio aislado y conserva una consola o sesión
administrativa. Ejemplo después de la contraseña:

```pam
auth required pam_unix.so
auth required pam_totp_rollover.so
```

Por defecto, un usuario sin secreto es rechazado. La opción explícita `nullok`
devuelve `PAM_IGNORE` cuando el archivo no existe:

```pam
auth required pam_totp_rollover.so nullok
```

No se admite ninguna otra opción. No instales el módulo automáticamente en
`common-auth` durante las primeras pruebas.

Para SSH en Debian o Ubuntu, una vez superado el piloto aislado, el módulo puede
añadirse después de la autenticación primaria en `/etc/pam.d/sshd`:

```pam
@include common-auth
auth required pam_totp_rollover.so
```

Usa `nullok` solo durante una migración deliberada: las cuentas sin
`~/.pam_totp_rollover` omitirán este factor. Antes de editar la pila, conserva
una consola o sesión administrativa abierta y crea una copia con permisos de
`root`:

```bash
sudo cp -a /etc/pam.d/sshd /etc/pam.d/sshd.pre-rollover
sudo sshd -t
```

Después de editar, ejecuta de nuevo `sudo sshd -t` antes de abrir una sesión de
prueba. No cierres la sesión de recuperación hasta completar el flujo entero
con una cuenta no crítica.

## Validación posterior a la instalación

Comprueba al menos lo siguiente:

1. La contraseña incorrecta falla sin completar el flujo.
2. El código actual seguido del código de `N+1` permite el acceso.
3. Repetir el primer código, responder tarde o usar un código de otro periodo
   falla y no permite reutilizar el contador consumido.
4. Dos intentos concurrentes de la misma cuenta no comparten la secuencia.
5. `sshd -t` sigue pasando y una cuenta administrativa de recuperación puede
   iniciar sesión.

Verificación básica del binario y los secretos enrolados:

```bash
sudo stat -c '%U:%G %a %n' \
    /lib/x86_64-linux-gnu/security/pam_totp_rollover.so \
    /home/USUARIO/.pam_totp_rollover
sudo sshd -t
systemctl is-active ssh
```

La ruta del módulo puede ser `/lib/security` o `/usr/lib64/security` en otras
distribuciones.

## Reloj, concurrencia y timeout

- El primer código se valida con ventana cero contra el contador actual.
- El módulo toma un bloqueo exclusivo por usuario, servicio e identidad del
  secreto después de validar el primer código y lo conserva hasta finalizar el
  segundo paso.
- Una autenticación concurrente sobre el mismo ámbito falla inmediatamente;
  no espera en una cola.
- Tras el cambio de periodo hay 25 segundos para responder al segundo prompt;
  al comenzar `N+2` el código se rechaza aunque quede deadline monotónico.
- Se utiliza `CLOCK_MONOTONIC` para la espera y el deadline. El reloj de pared
  solo determina el contador TOTP.
- Un retroceso o salto que no termine exactamente en `N+1` deniega el acceso.

PAM no proporciona una forma portable de cancelar una función de conversación
que el cliente mantenga bloqueada. El módulo rechaza una respuesta tardía al
recuperar el control, pero SSH, `login` o el consumidor PAM deben imponer su
propio timeout para evitar retener el proceso y el bloqueo indefinidamente.

El módulo aplica un retraso PAM tras los fallos. El servicio debe mantener
además límites de intentos adecuados; el módulo no implementa un contador de
bloqueo independiente.

## Recuperación y desinstalación

Si la prueba impide acceder, utiliza la sesión administrativa conservada y
retira primero la línea de la pila PAM. Después puedes eliminar el módulo:

```bash
sudo make uninstall
```

Para revertir la configuración SSH, restaura la copia solo desde la consola o
sesión administrativa que mantuviste abierta y valida el resultado antes de
cerrarla:

```bash
sudo cp -a /etc/pam.d/sshd.pre-rollover /etc/pam.d/sshd
sudo sshd -t
```

La desinstalación no borra secretos de usuarios ni estado de `/run`. Para
reiniciar el estado volátil durante un mantenimiento controlado, elimina solo
los archivos `ptr_*` dentro de `/run/pam-totp-lab` después de retirar el módulo
de todos los servicios y confirmar que no hay autenticaciones en curso.
