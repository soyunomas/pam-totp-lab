# Plan de desarrollo de `pam_totp_slot_challenge`

El módulo selecciona aleatoriamente uno de varios secretos TOTP locales y solicita únicamente el código del slot elegido.

## Alcance inicial

- Entre 2 y 4 slots fijos: `A`, `B`, `C` y `D`.
- Secretos en `~/.pam_totp_slots/<slot>.secret`.
- Un solo desafío por autenticación.
- Selección exclusivamente dentro del módulo; el cliente no elige el slot.
- Antirreplay independiente por usuario y slot.
- Sin daemon, red, broker, TPM ni criptografía propia.

## Puertas obligatorias

### Fase 1 — Política y selección

- Lista cerrada de slots.
- Rechazo de cantidades fuera de 2–4.
- Selección uniforme con `getrandom()` y rechazo de sesgo modular.
- Pruebas deterministas de la ruta de rechazo y pruebas repetidas del RNG.

La fase solo se cierra si pasan compilación con warnings fatales, pruebas unitarias, análisis estático, ASan y UBSan.

### Fase 2 — Lectura segura

- Directorio de usuario privado y propiedad correcta.
- Archivos regulares `0600`, sin symlinks ni hard links.
- Base32 mayúscula, sin padding, una única línea y límites estrictos.
- Ausencia o corrupción produce denegación.

### Fase 3 — Integración PAM/TOTP

- Obtener usuario mediante PAM.
- Seleccionar el slot antes del prompt.
- Prompt inequívoco sin revelar dispositivo físico.
- Validar exactamente seis dígitos mediante liboath.
- Antirreplay separado mediante etiquetas cerradas por slot.
- Limpiar secreto, código y respuesta.

### Fase 4 — Endurecimiento

- Pruebas negativas, concurrencia y separación de estado.
- GCC y Clang.
- Clang Static Analyzer, ASan, UBSan y Valgrind.
- Full RELRO, pila no ejecutable y ausencia de RPATH, RUNPATH y TEXTREL.

### Fase 5 — Documentación e integración

- README del módulo con instalación, enrolamiento, recuperación y límites.
- README principal actualizado.
- PR revisada y fusionada únicamente con todas las puertas disponibles en verde.

## Límite de seguridad

La selección aleatoria reduce la utilidad de comprometer un único secreto, pero no equivale a un quorum. Con un slot comprometido de cuatro, un atacante obtiene aproximadamente una oportunidad entre cuatro por desafío antes del rate limiting. Varios secretos almacenados en el mismo dispositivo tampoco son factores independientes.
