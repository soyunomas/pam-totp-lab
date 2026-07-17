# pam_school_schedule

**Módulo PAM de Autenticación Contextual basada en Horarios.**

`pam_school_schedule` es un módulo de seguridad diseñado para entornos educativos o críticos que requieren una validación de presencia temporal. Permite el acceso al sistema únicamente si existe una actividad programada válida para el usuario en el momento exacto de la autenticación.

Desarrollado bajo estrictos estándares de **Secure Coding (MISRA-C / CERT-C)**, garantizando gestión segura de memoria, aislamiento de privilegios y robustez contra condiciones de carrera.

## 🛡️ Características de Seguridad

*   **Anti-Timing Attacks:** Comparación de tokens de tiempo constante (`secure_equals`) para evitar la deducción de claves por análisis de latencia.
*   **Privilege Separation:** El proceso reduce sus privilegios efectivos a los del usuario objetivo antes de leer cualquier configuración.
*   **Symlink Protection:** Apertura de archivos con `O_NOFOLLOW` y validación de descriptores (`fstat`) para prevenir ataques de sustitución de archivos.
*   **Memory Hygiene:** Borrado activo (`explicit_bzero` pattern) de secretos en RAM inmediatamente después de su uso.
*   **Input Sanitization:** Limpieza estricta de caracteres no alfanuméricos en el prompt para evitar inyección de terminal.

## Requisitos

*   Linux (Debian, Ubuntu, RHEL, CentOS, Linux Mint).
*   Librerías de desarrollo de PAM (`libpam0g-dev`).
*   Compilador `gcc`.

```bash
sudo apt update
sudo apt install -y build-essential libpam0g-dev
```

## Instalación

1.  **Compilar el módulo:**
    ```bash
    make build
    ```

2.  **Instalar en el sistema:**
    ```bash
    sudo make install
    ```
    *Esto copiará `pam_school_schedule.so` al directorio de seguridad del sistema (ej. `/lib/x86_64-linux-gnu/security/`).*

3.  **Desinstalación (si es necesaria):**
    ```bash
    sudo make uninstall
    ```

## Configuración del Usuario

Cada usuario debe definir su propio horario en su directorio `HOME`.

1.  **Crear el archivo:**
    ```bash
    nano ~/.school_schedule
    ```

2.  **Formato:** `DIA INICIO FIN TOKEN`
    *   **DIA:** SUN, MON, TUE, WED, THU, FRI, SAT.
    *   **HORA:** HH:MM (Formato 24h).
    *   **TOKEN:** La palabra clave esperada. Soporta variables dinámicas:
        *   `%H`: Hora actual (00-23).
        *   `%M`: Minuto actual (00-59).

    **Ejemplo de configuración:**
    ```text
    # Lunes: Clase de Redes (08:00 - 08:55).
    # Token dinámico. Si entras a las 08:05, la clave es "REDES-05".
    MON 08:00 08:55 REDES-%M

    # Jueves: Guardia (11:00 - 11:30). Clave fija.
    THU 11:00 11:30 GUARDIA_SALA_1

    # Viernes: Salida (Clave combinada Hora+Minuto).
    FRI 14:00 15:00 SALIDA-%H%M
    ```

3.  **⚠️ CRÍTICO: Permisos**
    El módulo **bloqueará el acceso** si el archivo es legible por otros usuarios.
    ```bash
    chmod 600 ~/.school_schedule
    ```

## Configuración del Sistema (SSH)

Para integrar este módulo en SSH, edita el archivo PAM correspondiente.

1.  **Editar PAM:**
    ```bash
    sudo nano /etc/pam.d/sshd
    ```

2.  **Añadir el módulo:**
    Recomendamos usar `nullok` para permitir el acceso a usuarios que no tengan horario configurado (administradores, usuarios de servicio).

    ```pam
    # Autenticación estándar (incluye password del sistema)
    @include common-auth

    # Requerir validación de horario escolar
    # nullok: Si el usuario no tiene ~/.school_schedule, se le permite pasar.
    # Un archivo inseguro, corrupto o sin una franja válida sigue denegando.
    # Si quitamos 'nullok', el acceso es denegado por defecto.
    auth required pam_school_schedule.so nullok
    ```

3.  **Configuración SSH (`/etc/ssh/sshd_config`):**
    Asegúrate de que `ChallengeResponseAuthentication` o `KbdInteractiveAuthentication` estén activados.
    ```ssh
    UsePAM yes
    KbdInteractiveAuthentication yes
    ```

4.  **Reiniciar servicio:**
    ```bash
    sudo systemctl restart ssh
    ```

## Troubleshooting

Si experimentas problemas de acceso, revisa los logs de autenticación en tiempo real:

```bash
sudo tail -f /var/log/auth.log
```

*   **Error:** `PAM_SCHOOL: Insecure permissions on ...`
    *   **Solución:** Ejecuta `chmod 600 ~/.school_schedule`.
*   **Modulo ignorado:** Si usas `nullok` y el archivo no existe, el login procederá normalmente solo con la contraseña de usuario.

## Licencia

Este proyecto se distribuye bajo la licencia MIT.
