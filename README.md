# 🧪 PAM TOTP Lab

Este repositorio contiene implementaciones experimentales y educativas de módulos **PAM (Pluggable Authentication Modules)** para Linux, enfocadas en la autenticación de Doble Factor (2FA) utilizando el algoritmo TOTP (Time-based One-Time Password).

El objetivo es demostrar dos estrategias diferentes de integración de códigos OTP en el flujo de autenticación de SSH y login local.

## 📂 Estructura del Proyecto

El repositorio se divide en dos módulos independientes, cada uno con su propia lógica de seguridad y experiencia de usuario (UX):

### 1. 🥪 `pam-sandwich` (Estrategia de Fusión)
Un enfoque experimental donde el código TOTP se "esconde" dentro de la contraseña del usuario.
*   **Mecanismo:** El usuario introduce todo en un solo campo.
*   **Formato:** `[3 dígitos] + [Contraseña] + [3 dígitos]`.
*   **Caso de uso:** Clientes SSH o interfaces antiguas que no soportan `KbdInteractive` (prompts interactivos) o para ocultar el uso de 2FA en un solo input.
*   **🔗 [Ir a la documentación de pam-sandwich](./pam-sandwich/README.md)**

### 2. 🛡️ `pam_strict_totp` (Estrategia Estándar Hardened)
Una implementación de alta seguridad diseñada bajo estándares **MISRA-C** y **CERT-C**. Sigue el flujo estándar de desafío-respuesta.
*   **Mecanismo:** Autenticación en dos pasos separados.
*   **Formato:** Primero pide `Password` -> Si es correcto, pide `Verification Code`.
*   **Características:** Fail-close por defecto, separación de privilegios, protección contra ataques de repetición y rate limiting.
*   **🔗 [Ir a la documentación de pam_strict_totp](./pam_strict_totp/README.md)**

---

## ⚡ Comparativa Rápida

| Característica | pam-sandwich 🥪 | pam_strict_totp 🛡️ |
| :--- | :--- | :--- |
| **Experiencia de Usuario** | 1 Solo Prompt (Input largo) | 2 Prompts (Interactivo) |
| **Complejidad de Uso** | Media (Usuario debe dividir el token) | Baja (Estándar de industria) |
| **Nivel de Seguridad** | Medio (Seguridad por oscuridad + 2FA) | Alto (Hardened, Audit Ready) |
| **Manejo de Errores** | Silencioso | Estricto con Retardo (Delay) |
| **Ventana de Tiempo** | 30 segundos | 0 segundos (Requiere NTP preciso) |

---

## 🛠️ Requisitos Generales

Ambos proyectos requieren las mismas librerías base para compilar en sistemas Debian/Ubuntu:

```bash
sudo apt update
sudo apt install -y build-essential libpam0g-dev liboath-dev
```

## 🚀 Compilación e Instalación

Cada directorio funciona como un proyecto independiente con su propio `Makefile`.

1. Entra en el directorio deseado:
   ```bash
   cd pam_strict_totp  # o cd pam-sandwich
   ```

2. Compila e instala:
   ```bash
   make deps
   make install
   ```

3. Lee las instrucciones de configuración ("Hints") que aparecerán tras la instalación.

---

## ⚠️ Advertencia de Seguridad

Estos módulos interactúan con el sistema de autenticación central de Linux. **Una mala configuración puede dejarte fuera de tu sistema.**

1. **Nunca cierres tu sesión actual** mientras configuras PAM.
2. Abre siempre una **segunda terminal** para probar el login antes de desconectarte.
3. Asegúrate de tener acceso físico o una consola de recuperación (VNC/LOM) disponible si estás trabajando en un servidor remoto.

## 📄 Licencia

Este proyecto se distribuye bajo la licencia **MIT**. Consulta el archivo `LICENSE` en cada subdirectorio para más detalles.
