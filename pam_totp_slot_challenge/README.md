# `pam_totp_slot_challenge`

Módulo PAM experimental que selecciona aleatoriamente uno de varios secretos TOTP locales y solicita el código correspondiente al slot elegido.

```text
Slots configurados: A, B, C y D
Desafío actual: TOTP del slot C:
```

El cliente no elige el slot. La selección se realiza dentro del módulo mediante `getrandom()` y muestreo sin sesgo modular.

## Alcance de seguridad

El módulo limita la utilidad de comprometer un único secreto. Con cuatro slots y solo uno comprometido, el atacante dispone aproximadamente de una oportunidad entre cuatro por desafío antes de aplicar los límites de intentos del servicio.

No es un quorum, no añade un factor independiente y no protege frente a phishing interactivo, malware en el proceso PAM ni compromiso de todos los secretos. Guardar todos los slots en el mismo teléfono reduce notablemente la independencia práctica.

## Slots disponibles

La primera versión utiliza nombres cerrados:

| Índice | Archivo | Prompt | Estado antirreplay |
| ---: | --- | --- | --- |
| 1 | `A.secret` | `TOTP del slot A:` | `pam_totp_slot_a` |
| 2 | `B.secret` | `TOTP del slot B:` | `pam_totp_slot_b` |
| 3 | `C.secret` | `TOTP del slot C:` | `pam_totp_slot_c` |
| 4 | `D.secret` | `TOTP del slot D:` | `pam_totp_slot_d` |

La opción PAM `slots=N` activa los primeros `N` slots. Solo se aceptan `2`, `3` o `4`. La opción es obligatoria y cualquier argumento desconocido produce `PAM_SERVICE_ERR`.

## Dependencias

En Debian o Ubuntu:

```bash
sudo apt update
sudo apt install -y build-essential clang libpam0g-dev liboath-dev valgrind binutils
```

## Compilación y pruebas

Puerta local, sin necesitar cabeceras PAM/liboath reales para la prueba de integración simulada:

```bash
make verify-local
```

Puerta completa, destinada a un sistema de desarrollo con todas las dependencias:

```bash
make verify
```

La puerta completa incluye GCC, Clang, construcción real del `.so`, pruebas unitarias, integración PAM simulada, concurrencia, análisis estático, ASan, UBSan, Valgrind y verificación ELF de Full RELRO y pila no ejecutable.

Para compilar únicamente el módulo:

```bash
make production
```

## Enrolamiento

Cada usuario crea un directorio privado:

```bash
install -d -m 0700 "$HOME/.pam_totp_slots"
```

Registra entre dos y cuatro secretos TOTP diferentes mediante una aplicación compatible con RFC 6238. Guarda únicamente el secreto Base32 en mayúsculas, sin espacios ni padding `=`:

```bash
printf '%s\n' 'SECRETO_BASE32_DEL_SLOT_A' > "$HOME/.pam_totp_slots/A.secret"
printf '%s\n' 'SECRETO_BASE32_DEL_SLOT_B' > "$HOME/.pam_totp_slots/B.secret"
chmod 0600 "$HOME/.pam_totp_slots/A.secret" "$HOME/.pam_totp_slots/B.secret"
```

Para tres o cuatro slots, repite el proceso con `C.secret` y `D.secret`.

Requisitos de cada archivo:

- propietario: el usuario autenticado;
- permisos sin acceso de grupo ni otros;
- archivo regular con un único enlace;
- una sola línea;
- entre 16 y 128 caracteres Base32 `A–Z` y `2–7`;
- sin symlinks, hard links, padding, espacios ni líneas adicionales.

El módulo falla de forma cerrada si el slot seleccionado no existe o es inseguro. No existe opción `nullok`.

## Instalación

```bash
sudo make install
```

El Makefile instala `pam_totp_slot_challenge.so` en el directorio PAM detectado.

Añade el módulo únicamente al servicio que quieras probar. Ejemplo para dos slots:

```text
auth required /lib/x86_64-linux-gnu/security/pam_totp_slot_challenge.so slots=2
```

La ruta exacta puede ser `/usr/lib64/security/` o `/lib/security/` según la distribución.

Para SSH, la pila debe permitir autenticación interactiva y PAM. Mantén una sesión administrativa abierta mientras pruebas una configuración nueva y valida primero el archivo con una cuenta no crítica.

## Comportamiento de autenticación

1. PAM proporciona el nombre de usuario.
2. El módulo valida `slots=N`.
3. Selecciona uniformemente un índice entre `0` y `N-1`.
4. Abre `~/.pam_totp_slots/<slot>.secret` mediante descriptores y `O_NOFOLLOW`.
5. Muestra el prompt del slot seleccionado.
6. Exige exactamente seis dígitos.
7. Valida el TOTP con liboath.
8. Consume el contador en un espacio antirreplay independiente por slot.

Los errores de identidad o secreto utilizan una validación TOTP ficticia antes de denegar para reducir diferencias triviales de ejecución. Los códigos, secretos y respuestas no se escriben en logs.

## Antirreplay

El módulo reutiliza `pam_common/totp_replay.c`. El estado se guarda bajo:

```text
/run/pam-totp-lab/
```

Cada slot utiliza una etiqueta diferente. Un contador consumido en `A` no bloquea el mismo contador numérico de `B`, pero no puede reutilizarse dentro del propio slot.

El estado de `/run` es volátil y desaparece al reiniciar. Este módulo no proporciona antirreplay persistente entre reinicios.

## Recuperación

Antes de modificar una pila PAM:

1. conserva una sesión root o una consola local abierta;
2. realiza una copia del archivo de `/etc/pam.d/` afectado;
3. prueba con otra sesión antes de cerrar la sesión de recuperación.

Si el acceso falla, elimina o comenta la línea del módulo desde la sesión de recuperación. Para retirar el binario:

```bash
sudo make uninstall
```

No instales este módulo directamente en `common-auth` durante las primeras pruebas.

## Límites conocidos

- Un slot comprometido sigue permitiendo intentos cuando ese slot es elegido.
- Varios secretos en el mismo dispositivo no son factores independientes.
- La selección aleatoria puede añadir fricción operativa y riesgo de bloqueo si falta un slot.
- No protege frente a retransmisión o phishing en tiempo real.
- `root` o un proceso PAM comprometido puede leer los secretos durante el uso.
- El modelo no sustituye a un quorum ni al control de dos personas.
