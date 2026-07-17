# 🧪 PAM TOTP Lab

Este repositorio contiene implementaciones experimentales y educativas de módulos **PAM (Pluggable Authentication Modules)** para Linux, enfocadas en autenticación de doble factor, controles contextuales y experimentos de interfaz alrededor de TOTP.

El objetivo es demostrar estrategias locales y auditables para integrar códigos OTP, políticas temporales y desafíos interactivos en flujos como SSH, `sudo` y login local.

> **Compatibilidad:** varios módulos leen ficheros de usuario mediante cambios
> temporales de EUID, EGID y grupos. Ese modelo está orientado a consumidores PAM
> aislados por proceso, como los flujos habituales de SSH o `sudo`; no debe
> asumirse seguro para una aplicación multihilo sin rediseñar primero el acceso a
> credenciales. `pam_partial_key` también crea un proceso auxiliar y mantiene la
> misma restricción de despliegue.

## 📂 Estructura del proyecto

El repositorio se divide en siete módulos independientes:

### 1. 🥪 `pam-sandwich`

Oculta un TOTP estándar dentro de la contraseña para clientes con conversaciones PAM limitadas.

* **Formato:** `[3 dígitos] + [Contraseña] + [3 dígitos]`.
* **Documentación:** [pam-sandwich](./pam-sandwich/README.md).

### 2. 🛡️ `pam_strict_totp`

Implementación endurecida del flujo TOTP clásico con prompts separados.

* **Características:** fail-close, lectura segura del secreto, limpieza de memoria y antirreplay.
* **Documentación:** [pam_strict_totp](./pam_strict_totp/README.md).

### 3. 🔀 `pam_totp_shuffle`

Solicita los seis dígitos de un TOTP estándar en un orden aleatorio y reconstruye el código antes de validarlo.

* **Ejemplo:** orden `4-1-6-2-5-3`; para `123456`, la respuesta es `416253`.
* **Alcance:** experimento de interfaz frente a observaciones parciales; no añade un factor ni aumenta la seguridad criptográfica de TOTP.
* **Documentación:** [pam_totp_shuffle](./pam_totp_shuffle/README.md).

### 4. ⏳ `pam_chronoguard`

Aplica reglas temporales personalizables alrededor de una credencial.

* **Formato:** `[Prefijo temporal] + [Contraseña] + [Sufijo temporal]`.
* **Documentación:** [pam_chronoguard](./pam_chronoguard/README.md).

### 5. 🏦 `pam_partial_key`

Solicita posiciones aleatorias de una clave y utiliza hashing posicional.

* **Límite:** no es MFA; observaciones repetidas pueden revelar posiciones reutilizables.
* **Documentación:** [pam_partial_key](./pam_partial_key/README.md).

### 6. 🏫 `pam_school_schedule`

Restringe la autenticación según una agenda o franja horaria local.

* **Objetivo:** impedir accesos fuera de periodos autorizados.
* **Documentación:** [pam_school_schedule](./pam_school_schedule/README.md).

### 7. 👥 `pam_2man_totp`

Requiere la autenticación TOTP secuencial de dos usuarios distintos.

* **Objetivo:** aplicar control dual en operaciones críticas.
* **Documentación:** [pam_2man_totp](./pam_2man_totp/README.md).

---

## ⚡ Comparativa rápida

| Módulo | Tecnología base | UX | Dependencia principal | Mitigación o propósito |
| :--- | :--- | :--- | :--- | :--- |
| `pam-sandwich` | TOTP | Un prompt combinado | App TOTP | Compatibilidad con clientes limitados |
| `pam_strict_totp` | TOTP | Dos prompts | App TOTP | Fuerza bruta y repetición |
| `pam_totp_shuffle` | TOTP permutado | Desafío de orden | App TOTP | Observación parcial de la entrada |
| `pam_chronoguard` | Patrón temporal | Un prompt | Regla temporal | Observación parcial y acceso contextual |
| `pam_partial_key` | Hash posicional | Desafío | Clave mental | Captura parcial por keylogger |
| `pam_school_schedule` | Agenda y reloj | Prompt contextual | Configuración local | Acceso fuera de horario |
| `pam_2man_totp` | TOTP dual | Cuatro pasos | Dos personas | Amenaza interna individual |

---

## 🛠️ Requisitos generales

```bash
sudo apt update
sudo apt install -y build-essential libpam0g-dev liboath-dev libssl-dev
```

La verificación completa del repositorio se ejecuta con:

```bash
make -C tests verify
```

Los módulos que incluyen una puerta propia documentan también su objetivo `make verify` dentro de su carpeta.
