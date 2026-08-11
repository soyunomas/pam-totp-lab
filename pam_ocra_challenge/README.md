# pam_ocra_challenge

Módulo PAM experimental de desafío-respuesta OCRA local. Presenta un desafío decimal de 10 dígitos y exige una respuesta de 8 dígitos calculada por el cliente de terminal o por la aplicación Android incluida, con una credencial distinta por usuario y servicio.

> Estado: implementación completa, piloto manual pendiente y **no aprobada para producción**. Prueba siempre en una máquina no crítica, con consola y sesión administrativa de recuperación abiertas.

## Modelo de amenaza y límites

Protege frente a la reutilización directa de una respuesta capturada, separa credenciales por servicio y limita intentos concurrentemente. Los desafíos recientes se reservan antes del prompt y el estado queda aislado por UID, servicio y `key_id`.

No protege un endpoint comprometido, malware que robe el perfil del cliente, phishing o relay en tiempo real, ni una cuenta ya autenticada. No es TOTP: Google Authenticator y otros clientes TOTP normales son incompatibles. Se necesita uno de los clientes incluidos y un canal seguro para entregar su perfil.

La suite es fija y no configurable:

```text
OCRA-1:HOTP-SHA256-8:QN10
```

El módulo no cambia EUID, EGID ni grupos al leer su almacén root-only. Aun así, cualquier integración en un consumidor PAM multihilo debe validarse de forma aislada porque PAM, la conversación y las bibliotecas del proceso comparten recursos.

## Compilación e instalación

En Debian/Ubuntu se requieren `build-essential`, `libpam0g-dev`, `libssl-dev`, `binutils` y `qrencode`:

```bash
make -C pam_ocra_challenge compile-module-production compile-enroll-production
sudo make -C pam_ocra_challenge install
```

La instalación crea el módulo, `ocra-client`, `ocra-enroll` y estos directorios root-only:

```text
/etc/security/pam-ocra/users/       root:root 0700
/run/pam-totp-lab/ocra/             root:root 0700
```

Los secretos de servidor se guardan como `/etc/security/pam-ocra/users/<uid>/<servicio>.conf`, con directorios `0700` y archivo `0600`. Los perfiles de cliente también deben ser `0600` y propiedad del usuario que ejecuta el cliente.

No modifiques `common-auth`. Crea primero un servicio exclusivo, por ejemplo `/etc/pam.d/ocra-pilot`:

```text
auth requisite pam_ocra_challenge.so
```

El módulo versión 1 no acepta argumentos. Cualquier argumento hace fallar la configuración de forma cerrada.

## Enrolamiento y uso

El alta y la rotación requieren una ruta explícita para el perfil. Añade `--qr` para enrolar la aplicación Android:

```bash
sudo ocra-enroll add --user alice --service ocra-pilot \
  --client-profile /ruta-segura/alice-ocra-pilot.conf --qr
sudo ocra-enroll inspect --user alice --service ocra-pilot
sudo ocra-enroll rotate --user alice --service ocra-pilot \
  --client-profile /ruta-segura/alice-ocra-pilot-nuevo.conf --qr
sudo ocra-enroll revoke --user alice --service ocra-pilot
```

Instala el perfil en `~/.config/pam-ocra-client/<nombre>` con directorio no escribible por grupo/otros y archivo `0600`. Cuando PAM muestre el desafío, calcula la respuesta así:

```bash
ocra-client --profile <nombre>
```

Para Android, compila e instala [OCRA Client](./mobile/README.md), pulsa
**Enrolar** y escanea el QR mostrado en la terminal. En cada acceso introduce
en la app el desafío de 10 dígitos que muestra PAM y devuelve por SSH la
respuesta de 8 dígitos. El URI secreto se entrega a `/usr/bin/qrencode` por
`stdin`, no aparece en los argumentos de ningún proceso y no se imprime como
texto.

La rotación genera secreto y `key_id` nuevos, confirma el perfil nuevo antes de retirar el anterior y separa su rate limit. La revocación elimina solo la credencial indicada y su estado asociado.

## Rate limiting, recuperación y logs

La política permite como máximo cinco reservas en cinco minutos y bloquea cinco minutos. Usa `CLOCK_MONOTONIC`, bloqueo entre procesos y persistencia atómica bajo `/run`; un reinicio elimina ese estado volátil. Un estado ausente se recrea y uno corrupto provoca fallo cerrado.

Las operaciones administrativas usan un journal para recuperar altas, rotaciones o revocaciones interrumpidas. Antes de reintentar, conserva los archivos, ejecuta de nuevo `ocra-enroll` para que recupere la transacción y verifica con `inspect`. Si no puede recuperarse, restaura la copia del perfil/credencial desde consola y mantén deshabilitado el servicio piloto.

Los logs del módulo solo informan indisponibilidad o fallo de conversación/cálculo; nunca deben contener secreto, desafío ni respuesta. La herramienta administrativa registra operación, UID y servicio, no la clave.

## Verificación, rollback y desinstalación

La integración usa `pam_start_confdir()` y políticas temporales, sin tocar `/etc/pam.d`:

```bash
make -C pam_ocra_challenge verify-fast
make -C pam_ocra_challenge integration
```

`make verify` ejecuta la puerta acumulativa completa y es la usada por CI. Antes del despliegue manual completa [PILOT.md](./PILOT.md).

Rollback seguro:

1. mantén abierta la sesión administrativa de recuperación;
2. elimina o comenta la línea del servicio PAM exclusivo;
3. comprueba desde otra sesión que el servicio vuelve a autenticar;
4. revoca las credenciales si siguen accesibles;
5. desinstala los binarios.

```bash
sudo make -C pam_ocra_challenge uninstall
```

La desinstalación conserva deliberadamente `/etc/security/pam-ocra` y los perfiles del cliente para evitar pérdida accidental. Elimínalos solo después de verificar el rollback y hacer una copia segura.
