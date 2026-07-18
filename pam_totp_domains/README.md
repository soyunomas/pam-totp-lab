# PAM TOTP Domains

`pam_totp_domains` utiliza un secreto TOTP distinto según el servicio PAM que solicita la autenticación.

```text
PAM_SERVICE=sshd  -> ~/.pam_totp_domains/sshd.secret
PAM_SERVICE=sudo  -> ~/.pam_totp_domains/sudo.secret
PAM_SERVICE=login -> ~/.pam_totp_domains/login.secret
PAM_SERVICE=su    -> ~/.pam_totp_domains/su.secret
```

El módulo es local: no usa broker, daemon, red, TPM ni una aplicación propia. Los secretos son TOTP estándar RFC 6238.

## Qué aporta

Un secreto filtrado para SSH no genera códigos válidos para `sudo`, `login` o `su`. Esto exige que cada fichero contenga un secreto diferente.

No evita phishing interactivo, malware en el cliente, compromiso de `root`, robo de todos los secretos o fallos del dispositivo TOTP.

## Servicios admitidos

La política está compilada como lista cerrada. Solo se aceptan `sshd`, `sudo`, `login` y `su`. Nombres desconocidos, diferencias de mayúsculas y valores con forma de ruta se rechazan. `PAM_SERVICE` nunca se concatena directamente para construir una ruta.

## Compilación y verificación

En Debian o Ubuntu:

```bash
cd pam_totp_domains
make deps
make verify
sudo make install
```

`make verify` ejecuta pruebas funcionales y negativas, análisis estático, Valgrind, AddressSanitizer, UndefinedBehaviorSanitizer y comprobaciones ELF de Full RELRO, pila no ejecutable y ausencia de RPATH, RUNPATH y TEXTREL.

La suite elimina sus fixtures mediante operaciones directas sobre descriptores y no invoca una shell durante la limpieza.

## Configuración del usuario

```bash
install -d -m 0700 ~/.pam_totp_domains
umask 077
head -c 20 /dev/urandom | base32 | tr -d '=\n' > ~/.pam_totp_domains/sshd.secret
chmod 600 ~/.pam_totp_domains/sshd.secret
```

Repite la generación para `sudo.secret`, `login.secret` o `su.secret`. No copies el mismo valor. Añade cada secreto por separado a tu aplicación TOTP con etiquetas como `Servidor - SSH` y `Servidor - SUDO`.

El directorio debe pertenecer al usuario y tener modo `0700`. Cada secreto debe ser un fichero regular, propiedad del usuario, con modo `0600`, un único enlace y contenido Base32 mayúsculo sin padding. Symlinks, hard links, permisos inseguros, ficheros multilínea y formatos inválidos se rechazan.

## Configuración PAM

Ejemplo para `/etc/pam.d/sshd`:

```pam
auth required pam_totp_domains.so
```

Ejemplo para `/etc/pam.d/sudo`:

```pam
auth required pam_totp_domains.so
```

El mismo módulo elige automáticamente el secreto correcto mediante `PAM_SERVICE`.

Para un despliegue gradual puede usarse:

```pam
auth required pam_totp_domains.so nullok
```

`nullok` solo ignora la ausencia real del directorio o del fichero del servicio. Un archivo inseguro, corrupto o enlazado continúa denegando.

Mantén una sesión administrativa abierta mientras modificas PAM y prueba cada servicio por separado antes de cerrar la vía de recuperación.

## Anti-replay

El estado se separa por dominio bajo `/run/pam-totp-lab/`, usando etiquetas como `ptd_sshd` y `ptd_sudo`. El mismo contador se rechaza al reutilizarse dentro de un dominio, pero un contador legítimo de SSH no bloquea el de `sudo`.

El estado de `/run` es volátil y se reinicia al arrancar. Cualquier error al validar, bloquear o actualizar el estado provoca denegación, por lo que el consumidor PAM debe ejecutar el módulo con EUID 0.

## Desinstalación

Elimina primero las líneas PAM añadidas y después ejecuta:

```bash
cd pam_totp_domains
sudo make uninstall
```

Los secretos de usuario no se eliminan automáticamente.
