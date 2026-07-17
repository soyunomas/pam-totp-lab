# 🧪 PAM TOTP Lab

Colección experimental y educativa de módulos **PAM (Pluggable Authentication Modules)** para Linux. El repositorio explora autenticación TOTP, políticas temporales y desafíos locales sin convertir el laboratorio en una plataforma distribuida.

> **Compatibilidad:** varios módulos existentes leen archivos de usuario mediante cambios temporales de EUID, EGID y grupos. Ese modelo está orientado a consumidores PAM aislados por proceso, como los flujos habituales de SSH o `sudo`; no debe asumirse seguro para una aplicación multihilo sin rediseñar primero el acceso a credenciales. `pam_partial_key` también crea un proceso auxiliar y mantiene la misma restricción de despliegue.

## 📂 Módulos

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

### 3. `pam_totp_slot_challenge`

Selecciona aleatoriamente uno de 2–4 secretos TOTP de un mismo usuario.

- Slots cerrados `A–D`.
- Selección uniforme mediante `getrandom()`.
- Lectura segura de `~/.pam_totp_slots/*.secret`.
- Antirreplay independiente por slot.
- No es un quorum ni un factor adicional.
- [Documentación](./pam_totp_slot_challenge/README.md)

### 4. `pam_chronoguard`

Aplica prefijos y sufijos derivados del tiempo a una contraseña.

- Configuración local de patrones como `PRE=HH` y `POST=DD`.
- Mecanismo experimental de ofuscación temporal.
- [Documentación](./pam_chronoguard/README.md)

### 5. `pam_partial_key`

Solicita posiciones aleatorias de una clave maestra.

- Hashing posicional y comparación de tiempo constante.
- No es MFA; observaciones repetidas pueden revelar posiciones.
- [Documentación](./pam_partial_key/README.md)

### 6. `pam_school_schedule`

Autoriza según una agenda local y variables temporales.

- Diseñado para laboratorios o accesos restringidos por horario.
- Falla de forma cerrada si la configuración no es válida.
- [Documentación](./pam_school_schedule/README.md)

### 7. `pam_2man_totp`

Requiere la autenticación secuencial de dos usuarios distintos.

- TOTP del iniciador y de un autorizador privilegiado.
- Orientado a operaciones donde una sola persona no debe actuar sola.
- [Documentación](./pam_2man_totp/README.md)

## ⚡ Comparativa rápida

| Módulo | Tecnología | Interacción | Mitigación o experimento principal |
| :--- | :--- | :--- | :--- |
| `pam-sandwich` | TOTP | Un prompt combinado | Compatibilidad con clientes limitados |
| `pam_strict_totp` | TOTP | Prompt TOTP estándar | Fuerza bruta y repetición |
| `pam_totp_slot_challenge` | Varios TOTP | Un slot aleatorio | Compromiso aislado de un secreto |
| `pam_chronoguard` | Patrón temporal | Un prompt | Observación parcial y variación temporal |
| `pam_partial_key` | Hash posicional | Desafío de posiciones | Captura parcial por keylogger |
| `pam_school_schedule` | Agenda y reloj | Prompt contextual | Acceso fuera de horario |
| `pam_2man_totp` | TOTP dual | Cuatro pasos | Amenaza interna individual |

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

Los módulos nuevos pueden añadir una puerta específica dentro de su propio directorio. Para `pam_totp_slot_challenge`:

```bash
make -C pam_totp_slot_challenge verify-local
make -C pam_totp_slot_challenge verify
```

## Advertencia de despliegue

El repositorio es un laboratorio. No modifiques `common-auth` durante las primeras pruebas. Mantén una sesión administrativa o consola local abierta, realiza copias de la configuración de `/etc/pam.d/` y prueba primero con una cuenta no crítica.
