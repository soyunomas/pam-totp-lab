# Plan de desarrollo de `pam_totp_slot_challenge`

El módulo selecciona aleatoriamente uno de varios secretos TOTP locales y solicita únicamente el código del slot elegido.

## Alcance inicial

- Entre 2 y 4 slots fijos: `A`, `B`, `C` y `D`.
- Secretos en `~/.pam_totp_slots/<slot>.secret`.
- Un solo desafío por autenticación.
- Selección exclusivamente dentro del módulo; el cliente no elige el slot.
- Antirreplay independiente por usuario y slot.
- Sin daemon, red, broker, TPM ni criptografía propia.

## Estado de las puertas

### Fase 1 — Política y selección: completada localmente

- [x] Lista cerrada de slots.
- [x] Rechazo de cantidades fuera de 2–4.
- [x] Selección uniforme con `getrandom()` y rechazo de sesgo modular.
- [x] Pruebas deterministas de la ruta de rechazo y pruebas repetidas del RNG.
- [x] Warnings fatales, análisis estático, ASan y UBSan.

### Fase 2 — Lectura segura: completada localmente

- [x] Directorio de usuario privado y propiedad correcta.
- [x] Archivos regulares `0600`, sin symlinks ni hard links.
- [x] Base32 mayúscula, sin padding, una única línea y límites estrictos.
- [x] Ausencia o corrupción produce denegación.
- [x] Pruebas negativas y sanitizers.

### Fase 3 — Integración PAM/TOTP: completada localmente

- [x] Obtener usuario mediante PAM.
- [x] Seleccionar el slot antes del prompt.
- [x] Prompt inequívoco sin revelar dispositivo físico.
- [x] Validar exactamente seis dígitos mediante liboath.
- [x] Antirreplay separado mediante etiquetas cerradas por slot.
- [x] Limpiar secreto, código y respuesta.
- [x] Prueba de integración con PAM, liboath, lector y replay simulados.

### Fase 4 — Endurecimiento: puerta local completada; puerta remota pendiente

- [x] Pruebas negativas, concurrencia y separación de estado.
- [x] Clang Static Analyzer, ASan y UBSan.
- [x] Puerta local `make verify-local`.
- [ ] Compilación real con GCC y Clang contra PAM/liboath.
- [ ] Valgrind.
- [ ] Full RELRO, pila no ejecutable y ausencia de RPATH, RUNPATH y TEXTREL.

Las tres comprobaciones pendientes requieren el runner de GitHub Actions o un sistema con `libpam0g-dev`, `liboath-dev`, Valgrind y binutils.

### Fase 5 — Documentación e integración: documentación completada; fusión bloqueada por CI

- [x] README del módulo con instalación, enrolamiento, recuperación y límites.
- [x] README principal actualizado en la rama.
- [x] PR borrador abierta.
- [ ] Revisión remota completa en verde.
- [ ] Fusión a `main`.

## Límite de seguridad

La selección aleatoria reduce la utilidad de comprometer un único secreto, pero no equivale a un quorum. Con un slot comprometido de cuatro, un atacante obtiene aproximadamente una oportunidad entre cuatro por desafío antes del rate limiting. Varios secretos almacenados en el mismo dispositivo tampoco son factores independientes.
