# `pam_schedule_partial_key_override`

Módulo PAM local que aplica un horario por cuenta y, fuera de la franja
ordinaria, solicita tres posiciones aleatorias de una clave maestra docente.
No valida la contraseña: debe colocarse después de un `pam_unix.so` con control
`requisite`.

```text
contraseña correcta
    ├── dentro del horario → acceso
    └── fuera del horario → tres posiciones de la clave docente
```

## Compilación

```bash
make test
make all
make hardening
sudo make install
```

## Configuración

`/etc/security/pam-schedule-partial-key.conf`, archivo regular `root:root 0600`:

```text
version=1
default=ignore
user=A;days=Mo-Fr;time=0800-1400;authorizer=profesor-1
user=B;days=Mo-Fr;time=1400-2000;authorizer=profesor-1
```

Enrolamiento de una clave docente de 8–64 caracteres:

```bash
sudo schedule_partial_key_manager profesor-1
```

La herramienta lee la clave de forma interactiva y crea atómicamente
`/etc/security/pam-schedule-partial-key/profesor-1.pkey`, `root:root 0600`.
El archivo contiene una sal y hashes SHA-256 independientes por posición, no la
clave completa.

El directorio `/var/lib/pam-schedule-partial-key`, `root:root 0700`, registra
los tríos ordenados ya emitidos. El estado es persistente, se actualiza bajo
`flock()` y un trío no vuelve a utilizarse con la misma clave y contexto.

## PAM

Prueba primero en un servicio aislado y conserva una sesión administrativa:

```pam
auth    requisite pam_unix.so
auth    required  pam_schedule_partial_key_override.so
account required  pam_schedule_partial_key_override.so
```

No se admiten opciones. Dentro de horario no aparece otro prompt. Fuera de
horario se muestra:

```text
Acceso fuera de horario. Clave docente, posiciones [12] [3] [19]:
```

La respuesta contiene exactamente tres caracteres en ese orden.

## Seguridad y límites

- La clave parcial es conocimiento, no posesión ni OTP.
- Observaciones suficientes pueden reconstruir posiciones de la clave.
- El registro persistente evita repetir el mismo trío, pero no evita la
  acumulación de caracteres observados.
- Cinco fallos en cinco minutos bloquean durante cinco minutos.
- Configuración, claves o estado ausentes, corruptos o inseguros deniegan.
- Los logs no contienen posiciones, respuestas, hashes, sales ni claves.
- No protege frente a relay en tiempo real, malware, terminal comprometido o
  `root` comprometido.
- La política no termina sesiones ya abiertas al finalizar la franja.

Usa claves docentes largas y aleatorias, limita el número de autorizaciones y
rota antes de que se hayan observado demasiadas posiciones.

## Recuperación y desinstalación

Elimina primero las líneas del servicio PAM y después:

```bash
sudo make uninstall
```

La desinstalación no elimina configuración, claves ni estado. Para recuperar
acceso, usa una consola o sesión administrativa conservada y restaura la copia
del archivo PAM del servicio.
