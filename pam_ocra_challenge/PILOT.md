# Piloto manual de pam_ocra_challenge

```text
PILOT_APPROVED=no
Approved-by=
Commit=
```

Estado actual:

```text
IMPLEMENTACIÓN COMPLETA
PILOTO PENDIENTE
NO APROBADO PARA PRODUCCIÓN
```

Ejecutar en una máquina no crítica, con consola local, sesión administrativa abierta, copia de `/etc/pam.d`, cuenta no administrativa y servicio PAM exclusivo. Repetir este bloque para cada caso:

```text
Fecha:
Sistema:
Commit:
Caso:
Resultado esperado:
Resultado observado:
PASS/FAIL:
```

Casos obligatorios: autenticación correcta; respuesta incorrecta; desafío anterior; desafío de otro servicio; cancelación; cliente cerrado; cinco fallos y bloqueo; expiración del bloqueo; rotación; revocación; permisos incorrectos; estado corrupto; dos procesos concurrentes; reinicio; desinstalación y rollback completo.

Una persona debe cambiar `PILOT_APPROVED` a `yes`, identificarse y registrar el commit únicamente después de completar todos los casos.
