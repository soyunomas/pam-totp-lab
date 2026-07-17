# pam_sandwich

Módulo PAM (Pluggable Authentication Module) escrito en C para Linux. Implementa un esquema de autenticación de Doble Factor (2FA) embebido, donde el código TOTP se divide e inserta al inicio y al final de la contraseña del usuario.

## Funcionamiento

El módulo espera que la entrada de contraseña tenga el siguiente formato:
`[3 dígitos prefijo] + [Contraseña del sistema] + [3 dígitos sufijo]`

Utiliza `liboath` para la validación TOTP y gestión estricta de permisos de archivo para el almacenamiento de secretos.

La validación admite un paso de desfase en ambas direcciones. El módulo no
persiste todavía el contador TOTP consumido, por lo que un código puede
reutilizarse mientras permanezca en esa ventana. Una defensa anti-replay real
requiere estado por usuario y actualización atómica entre procesos PAM.

## Requisitos

Probado en **Debian** y **Ubuntu**. Se requieren las librerías de desarrollo de PAM y OATH.

*   `gcc`
*   `make`
*   `libpam0g-dev`
*   `liboath-dev`

```bash
sudo apt update
sudo apt install -y build-essential libpam0g-dev liboath-dev
```

## Instalación

1. **Clonar el repositorio:**

```bash
git clone https://github.com/soyunomas/pam_sandwich.git
cd pam_sandwich
```

2. **Instalar dependencias (Ubuntu/Debian):**

```bash
make deps
```

3. **Compilar e instalar:**

```bash
make install
```

Esto compilará el objeto compartido `pam_sandwich.so` y lo copiará al directorio de seguridad del sistema (usualmente `/lib/x86_64-linux-gnu/security` o `/lib/security`).

## Configuración del Usuario

Cada usuario que requiera autenticación debe tener un archivo de secretos configurado en su directorio home.

1.  Crear el archivo con el secreto en Base32 (mínimo 16 caracteres):
    ```bash
    echo "TU_SECRETO_BASE32" > ~/.google_authenticator
    ```

2.  **IMPORTANTE:** Establecer permisos estrictos. El módulo ignorará archivos inseguros.
    ```bash
    chmod 600 ~/.google_authenticator
    ```

## Configuración del Sistema

Para instrucciones detalladas sobre cómo editar `/etc/pam.d/sshd` y `/etc/ssh/sshd_config`, una vez instalado el módulo, ejecuta:

```bash
make hints
```

Si el usuario no tiene `.google_authenticator`, el módulo deniega el acceso
por defecto. Añade `nullok` explícitamente en la línea PAM sólo si quieres que
la ausencia del archivo deje continuar la pila:

```text
auth required pam_sandwich.so nullok
```

## Licencia

Este proyecto se distribuye bajo la licencia MIT. Consulta el archivo `LICENSE` para más detalles.
