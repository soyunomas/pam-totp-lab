# 🧪 PAM TOTP Lab

Colección experimental y educativa de módulos **PAM (Pluggable Authentication Modules)** para Linux. El repositorio explora autenticación TOTP, políticas temporales y desafíos locales sin convertir el laboratorio en una plataforma distribuida.

> **Compatibilidad:** varios módulos leen archivos de usuario mediante cambios temporales de EUID, EGID y grupos. Ese modelo está orientado a consumidores PAM aislados por proceso, como los flujos habituales de SSH o `sudo`; no debe asumirse seguro para una aplicación multihilo sin rediseñar primero el acceso a credenciales. `pam_partial_key` también crea un proceso auxiliar y mantiene la misma restricción de despliegue.

## Resumen de implementaciones

El repositorio contiene doce implementaciones. Todas disponen de un directorio propio y documentación específica.

| Implementación | Descripción breve | Documentación |
| :--- | :--- | :--- |
| `pam-sandwich` | Combina TOTP y contraseña en un único campo de entrada. | [README](./pam-sandwich/README.md) |
| `pam_strict_totp` | Implementa TOTP clásico endurecido con antirreplay local. | [README](./pam_strict_totp/README.md) |
| `pam_totp_domains` | Usa un secreto TOTP distinto según el servicio PAM. | [README](./pam_totp_domains/README.md) |
| `pam_totp_shuffle` | Solicita los dígitos TOTP en un orden aleatorio. | [README](./pam_totp_shuffle/README.md) |
| `pam_totp_slot_challenge` | Selecciona aleatoriamente uno de varios secretos TOTP. | [README](./pam_totp_slot_challenge/README.md) |
| `pam_totp_rollover` | Exige códigos TOTP de dos periodos consecutivos. | [README](./pam_totp_rollover/README.md) |
| `pam_chronoguard` | Añade patrones derivados del tiempo a una contraseña. | [README](./pam_chronoguard/README.md) |
| `pam_partial_key` | Solicita posiciones aleatorias de una clave maestra. | [README](./pam_partial_key/README.md) |
| `pam_school_schedule` | Autoriza el acceso según una agenda y la hora local. | [README](./pam_school_schedule/README.md) |
| `pam_2man_totp` | Exige la autenticación secuencial de dos usuarios. | [README](./pam_2man_totp/README.md) |
| `pam_schedule_totp_override` | Permite una excepción TOTP docente fuera del horario asignado. | [README](./pam_schedule_totp_override/README.md) |
| `pam_schedule_partial_key_override` | Permite una excepción horaria mediante posiciones de una clave docente. | [README](./pam_schedule_partial_key_override/README.md) |

## 📂 Implementaciones

### 1. `pam-sandwich`

Inserta un TOTP estándar alrededor de la contraseña para clientes con interfaces limitadas.

- Formato: `[3 dígitos] + [contraseña] + [3 dígitos]`.
- Alcance: compatibilidad y ofuscación; no sustituye un flujo MFA explícito.
- [Documentación](./pam-sandwich/README.md)

### 2. `pam_strict_totp`

Implementación endurecida del desafío TOTP clásico.

- Contraseña y TOTP en prompts separados.
- Fail-closed, limpieza de memoria y antirreplay local.
- [Documentación](./pam_strict_totp/README.md)

### 3. `pam_totp_domains`

Utiliza un secreto TOTP diferente según el servicio indicado por `PAM_SERVICE`.

- Dominios cerrados para `sshd`, `sudo`, `login` y `su`.
- Secretos separados en `~/.pam_totp_domains/`.
- Antirreplay independiente por usuario y servicio.
- Limita el impacto transversal de la filtración de un único secreto.
- [Documentación](./pam_totp_domains/README.md)

### 4. `pam_totp_shuffle`

Solicita los seis dígitos de un TOTP en un orden aleatorio y reconstruye internamente el código original.

- Permutación uniforme mediante `getrandom()`.
- Ejemplo: orden `4-1-6-2-5-3`; para `123456`, la respuesta es `416253`.
- Es un experimento de interfaz frente a observaciones parciales; no añade un factor ni aumenta la seguridad criptográfica de TOTP.
- [Documentación](./pam_totp_shuffle/README.md)

### 5. `pam_totp_slot_challenge`

Selecciona aleatoriamente uno de 2–4 secretos TOTP de un mismo usuario.

- Slots cerrados `A–D`.
- Lectura segura de `~/.pam_totp_slots/*.secret`.
- Antirreplay independiente por slot.
- No es un quorum ni un factor adicional.
- [Documentación](./pam_totp_slot_challenge/README.md)

### 6. `pam_totp_rollover`

Exige un TOTP del periodo actual y otro del periodo inmediatamente siguiente.

- Ventana cero para el primer código y secuencia exacta `N → N+1`.
- Bloqueo no bloqueante y antirreplay durante los dos prompts.
- Reloj monotónico para espera y deadline, con pruebas sin esperas reales.
- Implementación compilable, endurecida y validada en un piloto SSH con una
  cuenta no crítica y una sesión administrativa de recuperación.
- Mitiga la captura aislada de un código; no evita phishing en tiempo real.
- [Documentación](./pam_totp_rollover/README.md)

### 7. `pam_chronoguard`

Aplica prefijos y sufijos derivados del tiempo a una contraseña.

- Configuración local de patrones como `PRE=HH` y `POST=DD`.
- Mecanismo experimental de ofuscación temporal.
- [Documentación](./pam_chronoguard/README.md)

### 8. `pam_partial_key`

Solicita posiciones aleatorias de una clave maestra.

- Hashing posicional y comparación de tiempo constante.
- No es MFA; observaciones repetidas pueden revelar posiciones.
- [Documentación](./pam_partial_key/README.md)

### 9. `pam_school_schedule`

Autoriza según una agenda local y variables temporales.

- Diseñado para laboratorios o accesos restringidos por horario.
- Falla de forma cerrada si la configuración no es válida.
- [Documentación](./pam_school_schedule/README.md)

### 10. `pam_2man_totp`

Requiere la autenticación secuencial de dos usuarios distintos.

- TOTP del iniciador y de un autorizador privilegiado.
- Orientado a operaciones donde una sola persona no debe actuar sola.
- [Documentación](./pam_2man_totp/README.md)

### 11. `pam_schedule_totp_override`

Aplica un horario por cuenta y exige un TOTP docente específico fuera de la franja ordinaria.

- Configuración y secretos protegidos por `root`.
- Intervalos exactos con soporte para cruces de medianoche.
- Antirreplay por cuenta, servicio y secreto.
- Limitación concurrente de intentos mediante reloj monotónico.
- No resuelve la falta de atribución causada por contraseñas compartidas.
- [Documentación](./pam_schedule_totp_override/README.md)

### 12. `pam_schedule_partial_key_override`

Aplica un horario por cuenta y solicita tres posiciones de una clave docente fuera de la franja ordinaria.

- Configuración, claves y estado persistente protegidos por `root`.
- Los tríos ordenados aceptados no vuelven a emitirse con la misma clave.
- Rate limiting concurrente y marca acotada entre las fases `auth` y `account`.
- No es OTP ni evita la reconstrucción gradual de la clave por observación.
- [Documentación](./pam_schedule_partial_key_override/README.md)

## ⚡ Comparativa rápida

| Módulo | Tecnología | Interacción | Mitigación o experimento principal |
| :--- | :--- | :--- | :--- |
| `pam-sandwich` | TOTP combinado | Un prompt | Compatibilidad con clientes limitados |
| `pam_strict_totp` | TOTP | Prompt TOTP estándar | Fuerza bruta y repetición |
| `pam_totp_domains` | TOTP por servicio | Prompt del dominio | Compromiso transversal de un secreto |
| `pam_totp_shuffle` | TOTP permutado | Desafío de orden | Observación parcial de la entrada |
| `pam_totp_slot_challenge` | Varios TOTP | Un slot aleatorio | Compromiso aislado de un secreto |
| `pam_totp_rollover` | TOTP consecutivo | Dos prompts separados por un periodo | Captura aislada de un código |
| `pam_chronoguard` | Patrón temporal | Un prompt | Observación parcial y variación temporal |
| `pam_partial_key` | Hash posicional | Desafío de posiciones | Captura parcial por keylogger |
| `pam_school_schedule` | Agenda y reloj | Prompt contextual | Acceso fuera de horario |
| `pam_2man_totp` | TOTP dual | Cuatro pasos | Amenaza interna individual |
| `pam_schedule_totp_override` | Horario + TOTP | Prompt solo fuera de horario | Excepciones docentes supervisadas |
| `pam_schedule_partial_key_override` | Horario + hash posicional | Tres posiciones fuera de horario | Autorización docente sin TOTP |

## 🛠️ Requisitos generales

En Debian o Ubuntu:

```bash
sudo apt update
sudo apt install -y build-essential clang libpam0g-dev liboath-dev libssl-dev valgrind binutils
```

Verificación general del repositorio:

```bash
make -C tests verify
```

Puertas específicas disponibles cuando la carpeta correspondiente está presente:

```bash
make -C pam_totp_domains verify
make -C pam_totp_shuffle verify
make -C pam_totp_slot_challenge verify
make -C pam_totp_rollover verify
make -C pam_schedule_totp_override verify
make -C pam_schedule_partial_key_override verify
```

## Advertencia de despliegue

El repositorio es un laboratorio. No modifiques `common-auth` durante las primeras pruebas. Mantén una sesión administrativa o consola local abierta, realiza copias de la configuración de `/etc/pam.d/` y prueba primero con una cuenta no crítica.

No publiques contraseñas, semillas Base32, códigos TOTP ni archivos de
enrolamiento. Los ejemplos del repositorio usan valores ficticios; genera un
secreto independiente para cada cuenta y distribúyelo por un canal seguro.
