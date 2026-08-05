# Plan de desarrollo bloqueado por fases: `pam_ocra_challenge`

## 1. Objetivo

Implementar un módulo PAM local de autenticación challenge-response basado en OCRA.

Flujo previsto:

```text
PAM genera un desafío numérico
        ↓
El usuario lo introduce en un cliente OCRA
        ↓
El cliente calcula una respuesta de 8 dígitos
        ↓
PAM calcula la respuesta esperada
        ↓
Comparación constante
        ↓
PAM_SUCCESS o PAM_AUTH_ERR
```

El desarrollo debe realizarse mediante fases acumulativas. Ninguna fase puede considerarse terminada solamente porque el código compile.

Cada fase debe:

1. incluir pruebas positivas y negativas;
2. ejecutar todas las pruebas de las fases anteriores;
3. compilar con GCC y Clang;
4. compilar con `-Wall -Wextra -Werror -Wpedantic`;
5. no introducir nuevas advertencias;
6. no desactivar pruebas, sanitizadores ni controles existentes;
7. finalizar con un commit independiente;
8. detener el desarrollo si alguna prueba falla.

---

# 2. Contrato fijo del MVP

La primera versión debe implementar exclusivamente:

```text
OCRASuite:
OCRA-1:HOTP-SHA256-8:QN10
```

Parámetros:

```text
Algoritmo HMAC:       SHA-256
Respuesta:            8 dígitos decimales
Desafío:              10 dígitos decimales
Longitud del secreto: 32 bytes aleatorios
Codificación:         Base32 mayúscula sin padding
```

Restricciones:

* funcionamiento completamente local;
* sin daemon;
* sin red;
* sin servidor remoto;
* sin autenticación móvil en el MVP;
* sin suites configurables;
* sin contador OCRA;
* sin timestamp OCRA;
* sin PIN integrado en OCRA;
* sin `nullok`;
* un secreto independiente por UID y servicio PAM;
* secretos propiedad de `root`;
* cualquier error produce denegación;
* no registrar secretos, desafíos ni respuestas;
* no modificar automáticamente `/etc/pam.d/common-auth`.

El cliente inicial será una utilidad CLI independiente. Una aplicación móvil queda fuera del alcance del MVP.

---

# 3. Reglas obligatorias para Codex

## 3.1 Regla de no avance

Codex debe trabajar únicamente en la fase activa.

Está prohibido:

* comenzar archivos de una fase futura;
* añadir scaffolding no utilizado para fases posteriores;
* marcar una fase como terminada sin ejecutar sus comandos;
* cambiar una prueba para ocultar un defecto;
* eliminar una prueba que falla;
* reducir flags de compilación;
* añadir excepciones a Valgrind o sanitizadores sin justificar un falso positivo externo;
* continuar después de una puerta fallida.

Cuando una puerta falle:

```text
1. detener el avance;
2. identificar la causa;
3. corregir solamente la fase actual o una regresión introducida;
4. repetir la puerta completa;
5. no iniciar la siguiente fase hasta obtener salida cero.
```

## 3.2 Registro de progreso

Crear:

```text
pam_ocra_challenge/PROGRESS.md
```

Formato:

```text
Fase activa: 0
Última puerta superada: ninguna
Commit base: <SHA>
Estado: EN_PROGRESO
```

Al terminar una fase:

```text
Fase activa: 2
Última puerta superada: gate-01
Commit de la fase: <SHA>
Estado: EN_PROGRESO
```

Solo puede escribirse `COMPLETADA` después de superar la puerta final.

## 3.3 Commits

Un commit por fase:

```text
ocra: define MVP contract and gated build
ocra: implement RFC 6287 core
ocra: add secure numeric challenges
ocra: add protected secret store
ocra: add atomic rate limiting
ocra: add CLI response client
ocra: add enrollment and rotation tool
ocra: integrate PAM authentication flow
ocra: add integration and concurrency coverage
ocra: add hardening and CI verification
ocra: document isolated deployment pilot
```

No mezclar refactors ajenos al módulo.

## 3.4 Puertas acumulativas

El `Makefile` deberá exponer:

```text
make gate-00
make gate-01
make gate-02
make gate-03
make gate-04
make gate-05
make gate-06
make gate-07
make gate-08
make gate-09
```

Cada puerta debe depender de la anterior:

```makefile
gate-01: gate-00 test-ocra-core
gate-02: gate-01 test-challenge
gate-03: gate-02 test-secret-store
```

Una puerta debe detenerse en el primer error.

---

# 4. Estructura objetivo

```text
pam_ocra_challenge/
├── DEVELOPMENT.md
├── PROGRESS.md
├── README.md
├── Makefile
├── pam_ocra_challenge.c
├── ocra_core.c
├── ocra_core.h
├── ocra_suite.c
├── ocra_suite.h
├── challenge.c
├── challenge.h
├── secret_store.c
├── secret_store.h
├── rate_limit.c
├── rate_limit.h
├── secure_memory.c
├── secure_memory.h
├── scope.c
├── scope.h
├── tools/
│   ├── ocra_client.c
│   └── ocra_enroll.c
└── tests/
    ├── test_ocra_core.c
    ├── test_ocra_vectors.c
    ├── test_challenge.c
    ├── test_secret_store.c
    ├── test_rate_limit.c
    ├── test_client.c
    ├── test_enroll.c
    ├── test_module.c
    ├── test_concurrency.c
    ├── fuzz_secret_parser.c
    └── fixtures/
```

No crear todos los archivos al principio. Cada archivo se crea en su fase correspondiente.

---

# Fase 0 — Baseline, contrato y puerta de desarrollo

## Objetivo

Confirmar que el repositorio está sano antes de introducir cambios y preparar las puertas acumulativas.

## Trabajo

1. Registrar el SHA inicial.
2. Ejecutar las pruebas completas actuales.
3. Crear `pam_ocra_challenge/`.
4. Crear `DEVELOPMENT.md`.
5. Crear `PROGRESS.md`.
6. Crear un `Makefile` mínimo.
7. Añadir compilación vacía controlada de un test trivial.
8. No implementar todavía OCRA ni PAM.

## Puerta `gate-00`

Debe ejecutar:

```bash
set -euo pipefail

make -C tests verify

make -C pam_ocra_challenge clean
make -C pam_ocra_challenge CC=gcc test-bootstrap
make -C pam_ocra_challenge clean
make -C pam_ocra_challenge CC=clang test-bootstrap
```

## Criterios de aceptación

* La puerta existente del repositorio pasa sin modificaciones debilitantes.
* GCC compila con todas las advertencias como errores.
* Clang compila con todas las advertencias como errores.
* `git diff --check` no informa de errores.
* No existe código criptográfico todavía.

## Condición de parada

Si `make -C tests verify` falla antes de los cambios, detener el proyecto y registrar el fallo como problema de baseline. No atribuirlo al nuevo módulo.

---

# Fase 1 — Núcleo OCRA determinista

## Objetivo

Implementar el algoritmo OCRA sin dependencias de PAM, archivos, reloj ni aleatoriedad.

## Archivos

```text
ocra_core.c
ocra_core.h
ocra_suite.c
ocra_suite.h
secure_memory.c
secure_memory.h
tests/test_ocra_core.c
tests/test_ocra_vectors.c
```

## Trabajo

Implementar:

1. suite fija `OCRA-1:HOTP-SHA256-8:QN10`;
2. serialización exacta del `DataInput` OCRA;
3. HMAC-SHA256 mediante OpenSSL;
4. truncamiento dinámico HOTP;
5. reducción decimal a ocho dígitos;
6. validación estricta de desafío de diez dígitos;
7. respuesta con ceros iniciales;
8. limpieza de buffers temporales;
9. API sin asignaciones innecesarias.

API aproximada:

```c
#define OCRA_CHALLENGE_DIGITS 10U
#define OCRA_RESPONSE_DIGITS 8U
#define OCRA_SECRET_BYTES 32U

int ocra_compute_response(
    const unsigned char secret[OCRA_SECRET_BYTES],
    const char challenge[OCRA_CHALLENGE_DIGITS + 1U],
    char response[OCRA_RESPONSE_DIGITS + 1U]
);
```

La implementación debe comprobar los tamaños explícitamente. No usar `strlen()` sobre material binario.

## Pruebas obligatorias

* vectores oficiales de RFC 6287 aplicables;
* vectores internos calculados de manera independiente;
* desafío `0000000000`;
* desafío `9999999999`;
* ceros iniciales;
* desafío demasiado corto;
* desafío demasiado largo;
* espacios;
* signo positivo o negativo;
* caracteres no decimales;
* secreto nulo;
* output nulo;
* modificación de un bit del secreto;
* modificación de un dígito del desafío;
* determinismo;
* respuesta siempre de ocho dígitos;
* prueba de que el buffer de salida queda limpio tras error.

## Puerta `gate-01`

```bash
set -euo pipefail

make -C pam_ocra_challenge gate-00
make -C pam_ocra_challenge clean
make -C pam_ocra_challenge CC=gcc test-ocra-core
make -C pam_ocra_challenge clean
make -C pam_ocra_challenge CC=clang test-ocra-core

make -C pam_ocra_challenge \
  BUILD_DIR=build/asan \
  CC=clang \
  CFLAGS_EXTRA="-O1 -fno-omit-frame-pointer -fsanitize=address,undefined" \
  LDFLAGS_EXTRA="-fsanitize=address,undefined" \
  test-ocra-core

valgrind \
  --leak-check=full \
  --show-leak-kinds=all \
  --errors-for-leak-kinds=definite,indirect,possible \
  --error-exitcode=99 \
  pam_ocra_challenge/build/gcc/test_ocra_core
```

## Criterio de salida

No avanzar hasta que los vectores y todas las pruebas negativas pasen con GCC, Clang, ASan, UBSan y Valgrind.

---

# Fase 2 — Generación segura del desafío

## Objetivo

Generar desafíos numéricos de diez dígitos sin sesgo y sin fallback inseguro.

## Archivos

```text
challenge.c
challenge.h
tests/test_challenge.c
```

## Trabajo

Implementar:

```c
int ocra_generate_challenge(
    char output[OCRA_CHALLENGE_DIGITS + 1U]
);
```

Requisitos:

* utilizar `getrandom()`;
* tratar correctamente `EINTR`;
* fallar si la fuente de aleatoriedad falla;
* no usar `rand()`, `random()`, tiempo, PID ni contador como sustituto;
* generar uniformemente valores entre `0` y `9 999 999 999`;
* usar rejection sampling;
* preservar ceros iniciales;
* permitir inyectar una fuente determinista solo en tests.

No crear pruebas estadísticas frágiles. Probar matemáticamente el rejection sampling mediante entradas inyectadas.

## Pruebas obligatorias

* valor mínimo;
* valor máximo;
* ceros iniciales;
* rechazo de muestras fuera del límite;
* múltiples `EINTR`;
* fallo permanente de `getrandom()`;
* lectura parcial;
* output nulo;
* terminador NUL;
* no escribir fuera del buffer;
* generación determinista con el proveedor de pruebas.

## Puerta `gate-02`

Debe ejecutar todo `gate-01` y después:

```bash
make -C pam_ocra_challenge CC=gcc test-challenge
make -C pam_ocra_challenge CC=clang test-challenge
make -C pam_ocra_challenge sanitize-challenge
make -C pam_ocra_challenge valgrind-challenge
```

## Criterio de salida

No avanzar si existe cualquier camino que use una fuente de entropía alternativa.

---

# Fase 3 — Almacén root-only de secretos

## Objetivo

Leer secretos OCRA mediante rutas seguras y configuración estricta.

## Diseño de almacenamiento

```text
/etc/security/pam-ocra/
└── users/
    └── <uid>/
        └── <service>.conf
```

Permisos:

```text
/etc/security/pam-ocra          root:root 0700
users                           root:root 0700
<uid>                           root:root 0700
<service>.conf                  root:root 0600
```

Formato:

```text
version=1
suite=OCRA-1:HOTP-SHA256-8:QN10
key_id=16-hex-digits
secret=BASE32
enabled=yes
```

## Archivos

```text
secret_store.c
secret_store.h
scope.c
scope.h
tests/test_secret_store.c
tests/fixtures/
```

## Requisitos

* abrir directorios desde descriptores;
* usar `openat()`;
* usar `O_NOFOLLOW`;
* usar `O_CLOEXEC`;
* exigir archivo regular;
* exigir propietario `root`;
* exigir un único enlace físico;
* exigir modo `0600`;
* limitar tamaño;
* rechazar NUL embebido;
* rechazar líneas duplicadas;
* rechazar campos desconocidos;
* rechazar campos ausentes;
* rechazar Base32 inválida;
* rechazar padding `=`;
* rechazar nombres de servicio con `/`, `..` o caracteres desconocidos;
* no seguir symlinks en ningún componente;
* limpiar el secreto tras cualquier error.

La API de producción debe utilizar la ruta fija. Los tests pueden usar una variante `_at()` con directorio temporal.

## Pruebas obligatorias

* archivo válido;
* archivo ausente;
* directorio ausente;
* propietario incorrecto;
* permisos `0644`;
* permisos `0660`;
* symlink;
* hard link;
* FIFO;
* socket;
* dispositivo;
* archivo vacío;
* archivo excesivo;
* línea excesiva;
* campo repetido;
* campo desconocido;
* versión desconocida;
* suite diferente;
* `key_id` inválido;
* secreto corto;
* secreto largo;
* Base32 minúscula;
* padding;
* espacio final;
* CRLF, según política definida;
* NUL embebido;
* nombre de servicio manipulado;
* UID fuera de rango textual;
* cambio de archivo entre operaciones.

## Puerta `gate-03`

Debe ejecutar todo `gate-02` y después:

```bash
make -C pam_ocra_challenge CC=gcc test-secret-store
make -C pam_ocra_challenge CC=clang test-secret-store
make -C pam_ocra_challenge sanitize-secret-store
make -C pam_ocra_challenge valgrind-secret-store
```

Añadir fuzzing del parser a partir de esta fase:

```bash
make -C pam_ocra_challenge fuzz-secret-parser
```

El fuzzing debe ejecutar al menos:

```text
10 000 iteraciones en la puerta local
```

## Criterio de salida

No avanzar hasta que el parser sea fail-closed ante cualquier formato no reconocido.

---

# Fase 4 — Estado de desafíos y rate limiting atómico

## Objetivo

Evitar fuerza bruta concurrente y repetición accidental de desafíos recientes.

## Archivos

```text
rate_limit.c
rate_limit.h
tests/test_rate_limit.c
tests/test_concurrency.c
```

## Estado

```text
/run/pam-totp-lab/ocra/
```

Propiedades:

```text
root:root
0700
```

Ámbito:

```text
UID + PAM_SERVICE + key_id
```

## Política inicial

```text
Máximo:         5 intentos
Ventana:        5 minutos
Bloqueo:        5 minutos
Reloj:          CLOCK_MONOTONIC
```

## Semántica obligatoria

La comprobación y reserva del intento deben ocurrir en una única sección crítica.

Flujo:

```text
bloquear estado
    ↓
leer y validar estado
    ↓
comprobar bloqueo
    ↓
reservar/incrementar intento
    ↓
persistir
    ↓
desbloquear
    ↓
mostrar desafío
```

Una cancelación de la conversación cuenta como intento.

Una autenticación correcta puede reiniciar la ventana mediante otra operación bloqueada.

No implementar:

```text
check()
mostrar prompt
record_failure()
```

Ese diseño permite que varios procesos pasen el chequeo simultáneamente.

## Desafíos recientes

Mantener un anillo acotado de desafíos recientes por ámbito.

Requisitos:

* comprobar y reservar el desafío bajo bloqueo;
* regenerar ante colisión;
* limitar el número de regeneraciones;
* denegar ante error de estado;
* formato versionado y acotado;
* nunca crecer indefinidamente.

## Pruebas obligatorias

* primer intento permitido;
* quinto intento;
* sexto intento bloqueado;
* expiración de ventana;
* expiración del bloqueo;
* reloj monotónico anterior al almacenado;
* estado corrupto;
* estado truncado;
* permisos incorrectos;
* symlink;
* hard link;
* overflow;
* desafío repetido;
* anillo lleno;
* reinicio tras éxito;
* cien procesos concurrentes;
* ningún incremento perdido;
* no superar el límite bajo concurrencia;
* dos usuarios independientes;
* dos servicios independientes;
* dos `key_id` independientes.

## Puerta `gate-04`

Debe ejecutar todo `gate-03` y después:

```bash
make -C pam_ocra_challenge CC=gcc test-rate-limit
make -C pam_ocra_challenge CC=clang test-rate-limit
make -C pam_ocra_challenge test-concurrency
make -C pam_ocra_challenge sanitize-rate-limit
make -C pam_ocra_challenge valgrind-rate-limit
```

La prueba concurrente debe fallar si seis o más intentos obtienen autorización cuando el límite es cinco.

## Criterio de salida

No avanzar mientras exista una carrera entre comprobación y actualización.

---

# Fase 5 — Cliente CLI OCRA

## Objetivo

Crear un cliente funcional e independiente para calcular respuestas antes de integrar PAM.

## Archivo

```text
tools/ocra_client.c
tests/test_client.c
```

## Interfaz

```bash
ocra-client --profile servidor-sudo
```

Entrada:

```text
Desafío OCRA: 7361942058
```

Salida:

```text
Respuesta: 48291037
```

## Perfiles

```text
~/.config/pam-ocra-client/<perfil>.conf
```

Modo obligatorio:

```text
0600
```

El cliente:

* no acepta secretos en argumentos;
* no acepta secretos mediante variables de entorno;
* no registra el secreto;
* valida propietario y permisos;
* usa el mismo parser o un parser compatible;
* limpia secreto y respuesta;
* rechaza suites desconocidas;
* no contiene lógica duplicada del algoritmo.

## Pruebas obligatorias

* respuesta idéntica al núcleo;
* perfil válido;
* perfil ausente;
* permisos incorrectos;
* symlink;
* formato inválido;
* desafío inválido;
* EOF;
* cancelación;
* respuesta con ceros iniciales;
* secreto no visible en salida;
* secreto no visible en errores.

## Puerta `gate-05`

Debe ejecutar todo `gate-04` y después:

```bash
make -C pam_ocra_challenge CC=gcc test-client
make -C pam_ocra_challenge CC=clang test-client
make -C pam_ocra_challenge sanitize-client
make -C pam_ocra_challenge valgrind-client
```

Añadir una prueba de extremo a extremo sin PAM:

```text
generar desafío
    ↓
cliente calcula respuesta
    ↓
verificador independiente la acepta
```

## Criterio de salida

No integrar PAM hasta disponer de un cliente que produzca respuestas verificables.

---

# Fase 6 — Enrolamiento, rotación y revocación

## Objetivo

Crear una utilidad administrativa que genere e instale secretos correctamente.

## Archivo

```text
tools/ocra_enroll.c
tests/test_enroll.c
```

## Operaciones

```bash
sudo ocra-enroll add --user alice --service sudo
sudo ocra-enroll rotate --user alice --service sudo
sudo ocra-enroll revoke --user alice --service sudo
sudo ocra-enroll inspect --user alice --service sudo
```

## Flujo de alta

1. comprobar EUID 0;
2. resolver usuario y UID;
3. validar servicio;
4. generar 32 bytes mediante `getrandom()`;
5. generar `key_id`;
6. crear configuración del servidor;
7. crear perfil del cliente en una ruta explícita;
8. usar archivos temporales en el mismo directorio;
9. escribir con `0600`;
10. ejecutar `fsync()` sobre archivos;
11. renombrar atómicamente;
12. ejecutar `fsync()` sobre directorios;
13. borrar buffers;
14. no sobrescribir una credencial sin opción explícita.

La herramienta no debe aceptar el secreto como argumento.

## Rotación

La rotación debe:

* generar nueva clave y nuevo `key_id`;
* no reutilizar estado de rate limit del secreto anterior;
* instalar de forma atómica;
* permitir confirmar la nueva credencial antes de retirar la anterior;
* definir claramente rollback si la confirmación falla.

## Revocación

La revocación debe:

* deshabilitar o eliminar la credencial de forma explícita;
* no borrar silenciosamente otras credenciales;
* limpiar el estado asociado;
* registrar únicamente UID, servicio y operación.

## Pruebas obligatorias

* alta válida;
* usuario inexistente;
* servicio inválido;
* ejecución sin root;
* colisión de archivo;
* symlink de destino;
* fallo de escritura;
* escritura parcial;
* fallo de `fsync`;
* fallo antes de `rename`;
* fallo después de `rename`;
* rollback;
* rotación;
* revocación;
* permisos finales;
* propietario final;
* secreto de 32 bytes;
* `key_id` diferente tras rotación;
* perfil cliente compatible.

## Puerta `gate-06`

Debe ejecutar todo `gate-05` y después:

```bash
make -C pam_ocra_challenge CC=gcc test-enroll
make -C pam_ocra_challenge CC=clang test-enroll
make -C pam_ocra_challenge sanitize-enroll
make -C pam_ocra_challenge valgrind-enroll
```

## Criterio de salida

No integrar PAM mientras el enrolamiento pueda dejar archivos parciales, permisivos o inconsistentes.

---

# Fase 7 — Integración PAM

## Objetivo

Implementar `pam_sm_authenticate()` utilizando exclusivamente componentes ya probados.

## Archivo

```text
pam_ocra_challenge.c
tests/test_module.c
```

## Flujo obligatorio

```text
validar pamh y argumentos
        ↓
obtener PAM_USER
        ↓
obtener PAM_SERVICE
        ↓
resolver UID o activar ruta ficticia
        ↓
cargar secreto o secreto ficticio
        ↓
reservar intento de rate limit
        ↓
generar y reservar desafío
        ↓
mostrar desafío
        ↓
solicitar respuesta sin eco
        ↓
validar exactamente 8 dígitos
        ↓
calcular respuesta esperada
        ↓
comparar en tiempo constante
        ↓
éxito: reiniciar rate limit
fallo: conservar intento
        ↓
limpiar toda la memoria
```

## Requisitos PAM

* ningún argumento admitido en la versión 1;
* cualquier argumento devuelve `PAM_SERVICE_ERR`;
* sin `nullok`;
* `pam_sm_setcred()` devuelve `PAM_SUCCESS`;
* no modificar `PAM_AUTHTOK`;
* usar `pam_fail_delay()` como defensa adicional, no como rate limit;
* usuario inexistente y secreto inexistente deben recorrer una ruta ficticia;
* la ruta ficticia debe mostrar el mismo tipo de prompts;
* los mensajes visibles no deben distinguir errores;
* los logs no deben incluir desafío, respuesta ni secreto.

## Prompts

```text
Desafío OCRA para sudo: 7361942058
Respuesta OCRA:
```

La respuesta debe solicitarse con:

```text
PAM_PROMPT_ECHO_OFF
```

## Comparación

Usar comparación de tiempo constante sobre ocho bytes.

No usar:

```c
strcmp(expected, supplied)
```

## Pruebas obligatorias

* autenticación correcta;
* respuesta incorrecta;
* respuesta anterior para nuevo desafío;
* usuario inexistente;
* secreto inexistente;
* secreto corrupto;
* respuesta corta;
* respuesta larga;
* caracteres no numéricos;
* respuesta nula;
* conversación cancelada;
* error al generar desafío;
* estado bloqueado;
* error de rate limit;
* argumento desconocido;
* servicio inválido;
* `pam_set_data` o conversación fallida;
* limpieza de buffers;
* mismo comportamiento externo en ruta real y ficticia.

## Puerta `gate-07`

Debe ejecutar todo `gate-06` y después:

```bash
make -C pam_ocra_challenge CC=gcc test-module
make -C pam_ocra_challenge CC=clang test-module
make -C pam_ocra_challenge sanitize-module
make -C pam_ocra_challenge valgrind-module
```

## Criterio de salida

No avanzar si cualquier error puede producir `PAM_SUCCESS`, `PAM_IGNORE` o una omisión del desafío.

---

# Fase 8 — Integración real, aislamiento y concurrencia

## Objetivo

Cargar el módulo PAM compilado en un harness aislado sin modificar `/etc/pam.d`.

## Trabajo

Usar `pam_start_confdir()` con:

```text
directorio temporal de políticas PAM
módulo compilado en build/
usuarios y secretos de prueba
reloj, aleatoriedad y estado controlables
```

No usar cuentas reales ni modificar servicios reales.

## Pruebas de integración

* pila PAM con módulo correcto;
* pila con módulo `required`;
* pila con módulo `requisite`;
* contraseña anterior fallida;
* OCRA correcto;
* OCRA incorrecto;
* servicio diferente;
* secreto diferente por servicio;
* cinco intentos concurrentes;
* sexto intento bloqueado;
* dos usuarios simultáneos;
* cancelación;
* proceso terminado durante prompt;
* desafío reservado no reutilizado;
* estado corrupto;
* reinicio simulado del estado volátil;
* respuesta capturada no válida para otro desafío;
* respuesta capturada no válida para otro servicio;
* cambio de `key_id` después de rotación.

## Puerta `gate-08`

Debe ejecutar todo `gate-07` y después:

```bash
make -C pam_ocra_challenge integration
make -C pam_ocra_challenge integration-concurrent
make -C pam_ocra_challenge integration-negative
```

Después ejecutar regresión completa:

```bash
make -C tests verify
```

## Criterio de salida

No avanzar si el módulo solo funciona mediante tests unitarios pero no puede cargarse en una pila PAM aislada.

---

# Fase 9 — Hardening, CI y documentación

## Objetivo

Aplicar la puerta de calidad completa y documentar el uso seguro.

## Hardening de compilación

Módulo compartido:

```text
-fPIC
-fstack-protector-strong
-Wall
-Wextra
-Werror
-Wpedantic
-Wl,-z,relro
-Wl,-z,now
```

Herramientas:

```text
-fPIE
-pie
-fstack-protector-strong
-Wl,-z,relro
-Wl,-z,now
```

Verificar:

* Full RELRO;
* binding inmediato;
* pila no ejecutable;
* ausencia de RPATH;
* ausencia de RUNPATH;
* ausencia de TEXTREL;
* símbolos no deseados;
* permisos correctos de instalación.

## Análisis

Ejecutar:

```text
GCC
Clang
Clang Static Analyzer
ASan
UBSan
Valgrind
libFuzzer
hardening ELF
```

## README obligatorio

Documentar:

* modelo de amenaza;
* qué protege;
* qué no protege;
* suite fija;
* cliente necesario;
* enrolamiento;
* rotación;
* revocación;
* rate limiting;
* recuperación;
* logs;
* instalación;
* desinstalación;
* rollback;
* incompatibilidad con clientes TOTP normales;
* advertencia sobre consumidores PAM multihilo, si aplica;
* prueba aislada antes del despliegue.

## CI

Añadir el módulo al workflow del repositorio.

La CI debe ejecutar:

```bash
make -C pam_ocra_challenge verify
make -C tests verify
```

## Puerta `gate-09`

```bash
set -euo pipefail

make -C pam_ocra_challenge clean
make -C pam_ocra_challenge verify
make -C tests verify
git diff --check
git status --short
```

`verify` debe incluir todas las puertas anteriores.

## Criterio de salida

La fase termina únicamente cuando la puerta completa pasa desde un árbol limpio.

---

# Fase 10 — Piloto manual aislado

## Objetivo

Validar el módulo en un sistema de pruebas antes de considerarlo desplegable.

Esta fase requiere intervención humana. Codex no debe marcarla automáticamente como superada.

## Preparación

* máquina virtual o equipo no crítico;
* consola local disponible;
* sesión administrativa abierta;
* copia de `/etc/pam.d`;
* cuenta de prueba no administrativa;
* servicio PAM exclusivo para el piloto;
* procedimiento de recuperación probado.

## Casos manuales

1. autenticación correcta;
2. respuesta incorrecta;
3. desafío anterior;
4. desafío de otro servicio;
5. cancelación;
6. cliente cerrado;
7. cinco fallos;
8. bloqueo;
9. expiración de bloqueo;
10. rotación;
11. revocación;
12. secreto con permisos incorrectos;
13. estado corrupto;
14. dos procesos concurrentes;
15. reinicio;
16. desinstalación;
17. rollback completo.

## Evidencia requerida

Registrar en:

```text
pam_ocra_challenge/PILOT.md
```

Para cada caso:

```text
Fecha:
Sistema:
Commit:
Caso:
Resultado esperado:
Resultado observado:
PASS/FAIL:
```

## Puerta humana final

La fase solo puede marcarse como superada cuando una persona escriba:

```text
PILOT_APPROVED=yes
Approved-by=<nombre>
Commit=<sha>
```

Sin esa aprobación, el estado del proyecto debe ser:

```text
IMPLEMENTACIÓN COMPLETA
PILOTO PENDIENTE
NO APROBADO PARA PRODUCCIÓN
```

---

# 5. Definición de terminado

El módulo solo está terminado cuando:

* todas las puertas `gate-00` a `gate-09` pasan;
* la CI pasa desde un checkout limpio;
* las pruebas existentes del repositorio siguen pasando;
* no hay advertencias de GCC ni Clang;
* ASan y UBSan no encuentran errores;
* Valgrind no encuentra errores atribuibles al módulo;
* el parser ha sido fuzzed;
* las carreras están probadas con múltiples procesos;
* el módulo se carga en una pila PAM aislada;
* existe enrolamiento, rotación y revocación;
* existe documentación de recuperación;
* el piloto manual ha sido aprobado.

Una compilación correcta no equivale a una fase superada.

---

# 6. Instrucción inicial para Codex

Comienza exclusivamente por la Fase 0.

Antes de escribir código:

1. inspecciona la estructura del repositorio;
2. registra el SHA actual;
3. ejecuta `make -C tests verify`;
4. informa del resultado;
5. crea únicamente los archivos de la Fase 0;
6. ejecuta `gate-00`;
7. detente al terminar la fase;
8. no comiences la Fase 1 hasta que `gate-00` haya finalizado con código cero.

Al finalizar cada fase, muestra:

```text
Fase:
Archivos modificados:
Pruebas ejecutadas:
Resultado:
Commit:
Siguiente fase desbloqueada: sí/no
```
