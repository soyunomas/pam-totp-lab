# 🧪 PAM TOTP Lab

Este repositorio contiene implementaciones experimentales y educativas de módulos **PAM (Pluggable Authentication Modules)** para Linux, enfocadas en la autenticación de Doble Factor (2FA) y estrategias de ofuscación temporal.

El objetivo es demostrar diferentes estrategias de integración de códigos OTP y variables de tiempo en el flujo de autenticación de SSH y login local.

## 📂 Estructura del Proyecto

El repositorio se divide en cinco módulos independientes, cada uno con su propia lógica de seguridad y experiencia de usuario (UX):

### 1. 🥪 `pam-sandwich` (Estrategia de Fusión TOTP)
Un enfoque experimental donde el código TOTP estándar (Google Authenticator) se "esconde" dentro de la contraseña del usuario.
*   **Mecanismo:** El usuario concatena el token OATH generado por una app.
*   **Formato:** `[3 dígitos] + [Contraseña] + [3 dígitos]`.
*   **Caso de uso:** Clientes SSH o interfaces antiguas que no soportan `KbdInteractive` o para ocultar el uso de 2FA en un solo input.
*   **🔗 [Ir a la documentación de pam-sandwich](./pam-sandwich/README.md)**

### 2. 🛡️ `pam_strict_totp` (Estrategia Estándar Hardened)
Una implementación de alta seguridad diseñada bajo estándares **MISRA-C**. Sigue el flujo estándar de desafío-respuesta.
*   **Mecanismo:** Autenticación en dos pasos separados e interactivos.
*   **Formato:** Primero pide `Password` -> Si es correcto, pide `Verification Code`.
*   **Características:** Fail-close por defecto, separación de privilegios, protección contra ataques de repetición y rate limiting.
*   **🔗 [Ir a la documentación de pam_strict_totp](./pam_strict_totp/README.md)**

### 3. ⏳ `pam_chronoguard` (Ofuscación Temporal Dinámica)
Un módulo de "Defensa Dinámica" que implementa una estrategia de **Sandwich Temporal Personalizable** sin dispositivos externos.
*   **Mecanismo:** El usuario define reglas de tiempo en su perfil (ej. `PRE=HH`, `POST=DD`).
*   **Formato:** `[Prefijo Temporal] + [Contraseña] + [Sufijo Temporal]`.
*   **Caso de uso:** Protección contra Keyloggers y Shoulder Surfing mediante "MFA Cognitivo" (lo que sabes + cuándo lo sabes).
*   **Seguridad:** Código auditado (CERT-C), limpieza de memoria activa (Anti-Forensic) y validación de permisos estricta.
*   **🔗 [Ir a la documentación de pam_chronoguard](./pam_chronoguard/README.md)**

### 4. 🏦 `pam_partial_key` (Estrategia Bancaria)
Implementación del método clásico de autenticación parcial donde nunca se envía la contraseña completa por la red.
*   **Mecanismo:** El sistema solicita caracteres en índices aleatorios (ej. "Introduce posiciones 2, 8 y 14").
*   **Formato:** Prompt: `Posiciones [2] [8] [14]:` -> Input: `a 7 H`.
*   **Caso de uso:** Entornos hostiles con alto riesgo de **Keyloggers**. Si un atacante captura las teclas, solo obtiene 3 caracteres desordenados inservibles para futuros intentos.
*   **Seguridad:** Hashing posicional (SHA256 + Salt + Index), comparación de tiempo constante y protección contra Replay Attacks.
*   **🔗 [Ir a la documentación de pam_partial_key](./pam_partial_key/README.md)**

### 5. 🏫 `pam_school_schedule` (Estrategia de Horario Lectivo)
Módulo de autenticación contextual que valida el acceso basándose en la agenda o cronograma del usuario.
*   **Mecanismo:** El acceso solo se permite si el usuario tiene una actividad programada en el minuto exacto del login.
*   **Formato:** Prompt: `Materia Actual (User):` -> Input: `REDES-45` (Palabra clave + Variable temporal).
*   **Caso de uso:** Control estricto de acceso a laboratorios o servidores, permitiendo el login solo durante horas de clase o guardias específicas.
*   **Seguridad:** Fail-Close (bloqueo total si no hay agenda), variables dinámicas (`%H`, `%M`) para aumentar entropía y *Zero Warnings Policy*.
*   **🔗 [Ir a la documentación de pam_school_schedule](./pam_school_schedule/README.md)**

---

## ⚡ Comparativa Rápida

| Característica | pam-sandwich 🥪 | pam_strict_totp 🛡️ | pam_chronoguard ⏳ | pam_partial_key 🏦 | pam_school_schedule 🏫 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Tecnología Base** | TOTP (OATH) | TOTP (OATH) | Tiempo (Pattern) | Partial Hash (SHA256) | Agenda / Reloj |
| **Experiencia UX** | 1 Solo Prompt | 2 Prompts | 1 Solo Prompt | Interactivo (Desafío) | Prompt Contextual |
| **Dependencia** | App Móvil | App Móvil | Reloj Mental | Clave Mental / Fichero | Configuración (File) |
| **Complejidad Uso** | Media | Baja | Alta | Media (Visual) | Media (Cálculo) |
| **Nivel Seguridad** | Medio (Obscurity) | Muy Alto (Hardened) | Alto (Anti-Forensic) | Alto (Anti-Keylogger) | Alto (Fail-Close) |
| **Mitigación Principal** | Phishing Simple | Fuerza Bruta / Robo | Shoulder Surfing | **Keyloggers / Replay** | **Acceso Fuera Horario** |

---

## 🛠️ Requisitos Generales

Para compilar cualquiera de los módulos en sistemas Debian/Ubuntu, se recomiendan las siguientes librerías base (incluyendo OpenSSL para el módulo bancario):

```bash
sudo apt update
sudo apt install -y build-essential libpam0g-dev liboath-dev libssl-dev
```
