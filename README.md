# 🧪 PAM TOTP Lab

Este repositorio contiene implementaciones experimentales y educativas de módulos **PAM (Pluggable Authentication Modules)** para Linux, enfocadas en la autenticación de Doble Factor (2FA) y estrategias de ofuscación temporal.

El objetivo es demostrar diferentes estrategias de integración de códigos OTP y variables de tiempo en el flujo de autenticación de SSH y login local.

> **Roadmap experimental:** consulta [TODO: autenticación PAM experimental](./TODO_AUTHENTICATION_IDEAS.md)
> para ver nuevas propuestas, fases de desarrollo, riesgos y criterios de prueba.

> **Compatibilidad:** varios módulos leen ficheros de usuario mediante cambios
> temporales de EUID, EGID y grupos. Ese modelo está orientado a consumidores PAM
> aislados por proceso, como los flujos habituales de SSH o `sudo`; no debe
> asumirse seguro para una aplicación multihilo sin rediseñar primero el acceso a
> credenciales. `pam_partial_key` también crea un proceso auxiliar y mantiene la
> misma restricción de despliegue.

## 📂 Estructura del Proyecto

El repositorio se divide en siete módulos independientes, cada uno con su propia lógica de seguridad y experiencia de usuario (UX):

### 1. 🥪 `pam-sandwich` (Estrategia de Fusión TOTP)
Un enfoque experimental donde el código TOTP estándar se "esconde" dentro de la contraseña del usuario.
* **Mecanismo:** concatena el token OATH con la contraseña.
* **Formato:** `[3 dígitos] + [Contraseña] + [3 dígitos]`.
* **🔗 [Documentación](./pam-sandwich/README.md)**

### 2. 🛡️ `pam_strict_totp` (TOTP estándar endurecido)
Implementación minimalista del flujo TOTP clásico.
* **Mecanismo:** contraseña y código de verificación en prompts separados.
* **Características:** fail-close, separación temporal de privilegios, antirreplay y rate limiting.
* **🔗 [Documentación](./pam_strict_totp/README.md)**

### 3. 🧭 `pam_totp_domains` (TOTP separado por servicio)
Utiliza un secreto TOTP diferente para cada servicio PAM.
* **Mecanismo:** `PAM_SERVICE=sshd` selecciona `sshd.secret`; `sudo` selecciona `sudo.secret`.
* **Caso de uso:** limitar el impacto de la filtración de un secreto y evitar reutilizar el mismo factor entre SSH, `sudo`, `login` y `su`.
* **Seguridad:** lista cerrada de servicios, lectura segura de archivos, permisos estrictos y estado antirreplay independiente por dominio.
* **🔗 [Documentación](./pam_totp_domains/README.md)**

### 4. ⏳ `pam_chronoguard` (Ofuscación temporal dinámica)
Implementa un sandwich temporal personalizable sin dispositivos externos.
* **Mecanismo:** el usuario define reglas de tiempo como `PRE=HH` y `POST=DD`.
* **Formato:** `[Prefijo temporal] + [Contraseña] + [Sufijo temporal]`.
* **🔗 [Documentación](./pam_chronoguard/README.md)**

### 5. 🏦 `pam_partial_key` (Autenticación parcial)
Solicita caracteres concretos de una clave maestra.
* **Mecanismo:** desafío de posiciones aleatorias.
* **Seguridad:** hashing posicional y comparación de tiempo constante. No es MFA y observaciones repetidas pueden revelar posiciones.
* **🔗 [Documentación](./pam_partial_key/README.md)**

### 6. 🏫 `pam_school_schedule` (Horario lectivo)
Valida el acceso según la agenda local del usuario.
* **Mecanismo:** solo permite autenticación durante una franja configurada.
* **Formato:** palabra clave más variable temporal.
* **🔗 [Documentación](./pam_school_schedule/README.md)**

### 7. 👥 `pam_2man_totp` (Control dual)
Requiere la autenticación secuencial de dos usuarios distintos.
* **Mecanismo:** TOTP del iniciador y TOTP de un autorizador privilegiado.
* **Caso de uso:** operaciones críticas donde ningún administrador debe actuar solo.
* **🔗 [Documentación](./pam_2man_totp/README.md)**

---

## ⚡ Comparativa rápida

| Módulo | Tecnología base | UX | Dependencia principal | Mitigación principal |
| :--- | :--- | :--- | :--- | :--- |
| `pam-sandwich` | TOTP | Un prompt | App TOTP | Compatibilidad con clientes limitados |
| `pam_strict_totp` | TOTP | Dos prompts | App TOTP | Fuerza bruta y repetición |
| `pam_totp_domains` | TOTP por servicio | Un prompt TOTP | Varios secretos TOTP | Reutilización y compromiso transversal |
| `pam_chronoguard` | Patrón temporal | Un prompt | Regla mental | Observación parcial |
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

El módulo `pam_totp_domains` añade además su propia puerta específica:

```bash
make -C pam_totp_domains verify
```
