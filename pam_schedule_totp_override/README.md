# `pam_schedule_totp_override`

Módulo PAM local para aplicar horarios de acceso por cuenta y permitir una excepción fuera de horario mediante un TOTP docente específico para esa cuenta.

El módulo **no valida la contraseña**. Debe colocarse después de `pam_unix.so` o del mecanismo de contraseña habitual, configurado para detener el stack inmediatamente si la contraseña falla:

```text
contraseña correcta
    ├── dentro del horario → acceso
    └── fuera del horario → TOTP docente adicional
```

## Modelo de uso

Ejemplo para tres cuentas compartidas de un centro educativo:

```text
A → mañana
B → tarde
C → noche
```

Si B necesita realizar un examen por la mañana, la contraseña común no basta. El profesor introduce o supervisa el TOTP asociado exclusivamente a B.

Este control autoriza una excepción de política. No identifica al alumno real mientras las contraseñas sean compartidas.

## Dependencias

En Debian o Ubuntu:

```bash
sudo apt update
sudo apt install -y build-essential clang libpam0g-dev liboath-dev valgrind binutils
```

## Compilación y verificación

```bash
cd pam_schedule_totp_override
make test
make verify
sudo make install
```

La puerta completa ejecuta GCC y Clang, pruebas funcionales y negativas, análisis estático, ASan, UBSan, Valgrind y comprobaciones ELF de Full RELRO, pila no ejecutable y ausencia de RPATH, RUNPATH y TEXTREL.

## Configuración

El archivo fijo es:

```text
/etc/security/pam-schedule-override.conf
```

Debe ser un archivo regular `root:root`, sin enlaces, con un único enlace físico y modo `0600`.

Ejemplo:

```text
version=1
default=ignore
user=A;days=Mo-Fr;time=0800-1400;secret=A.secret
user=B;days=Mo-Fr;time=1400-2000;secret=B.secret
user=C;days=Mo-Fr;time=2000-0200;secret=C.secret
```

La sintaxis es cerrada:

- `version=1` es obligatorio.
- `default=ignore` devuelve `PAM_IGNORE` para cuentas no listadas.
- `default=deny` deniega cuentas no listadas.
- Cada cuenta aparece una sola vez en la versión 1.
- Cada nombre de secreto solo puede asignarse a una cuenta.
- Los días admitidos son `Mo`, `Tu`, `We`, `Th`, `Fr`, `Sa` y `Su`.
- Se admiten listas y rangos ascendentes, por ejemplo `Mo-Fr,Su`.
- Las horas usan `HHMM-HHMM` y el final es exclusivo.
- Si la hora inicial es posterior a la final, el intervalo cruza medianoche.
- `0800-0800` se rechaza por ser ambiguo.
- No se admiten rutas ni nombres de secreto con `..`.

La política utiliza el reloj y la zona horaria del servidor. El módulo elimina `TZ` del entorno antes de consultar la hora local. En el cambio de hora de primavera, los minutos inexistentes no se autorizan; en el cambio de otoño, una franja repetida se considera válida en ambas apariciones.

## Secretos docentes

Los secretos se guardan bajo:

```text
/etc/security/pam-schedule-override/
├── A.secret
├── B.secret
└── C.secret
```

El directorio debe ser `root:root` con modo `0700`. Cada secreto debe ser un archivo regular `root:root`, modo `0600`, un solo enlace, una única línea Base32 mayúscula sin padding y entre 16 y 128 caracteres.

Ejemplo de creación:

```bash
sudo install -d -o root -g root -m 0700 \
  /etc/security/pam-schedule-override

umask 077
head -c 20 /dev/urandom | base32 | tr -d '=\n' | \
  sudo tee /etc/security/pam-schedule-override/B.secret >/dev/null
sudo chown root:root /etc/security/pam-schedule-override/B.secret
sudo chmod 0600 /etc/security/pam-schedule-override/B.secret
```

Cada cuenta debe utilizar un secreto distinto. El profesor añade las entradas a una aplicación TOTP estándar con etiquetas inequívocas, por ejemplo `Centro - Excepción A`, `Centro - Excepción B` y `Centro - Excepción C`.

## Configuración PAM

Prueba primero en un servicio PAM aislado y conserva una sesión administrativa abierta.

Ejemplo conceptual:

```pam
auth    requisite pam_unix.so
auth    required  pam_schedule_totp_override.so
account required  pam_schedule_totp_override.so
```

El control `requisite` evita solicitar o consumir un TOTP docente cuando la contraseña anterior es incorrecta. Adapta el stack al servicio concreto y revisa sus módulos existentes antes de desplegarlo.

Dentro del horario, el módulo no muestra un segundo prompt. Fuera del horario muestra:

```text
Acceso fuera de horario. Código de autorización docente:
```

No se admiten opciones del módulo. Cualquier argumento desconocido produce `PAM_SERVICE_ERR`.

## Antirreplay y limitación de intentos

Un TOTP aceptado se consume mediante el estado común de `/run/pam-totp-lab/`. La clave de replay incluye la cuenta, el servicio PAM y el archivo de secreto seleccionado.

Los intentos fuera de horario se limitan por cuenta y servicio:

- cinco fallos dentro de cinco minutos;
- bloqueo durante cinco minutos;
- reloj monotónico para que un cambio del reloj civil no elimine el bloqueo;
- actualización protegida mediante `flock()`;
- cualquier error de estado deniega el acceso.

El estado bajo `/run` se pierde al reiniciar.

## Auditoría

Se registra mediante syslog:

- cuenta;
- servicio PAM;
- aceptación o rechazo de la excepción;
- bloqueo o error del estado de intentos.

Nunca se registra la contraseña, el TOTP ni el secreto Base32.

## Límites

- Las contraseñas compartidas impiden atribuir el acceso a una persona concreta.
- Un TOTP dictado puede reenviarse mientras siga vigente.
- El compromiso del dispositivo docente afecta los secretos enrolados en él.
- El módulo comprueba la política durante autenticación y gestión de cuenta; no finaliza una sesión ya abierta cuando termina la franja.
- Requiere reloj del servidor sincronizado y procedimientos de rotación y revocación.
- `TZ` y `tzset()` afectan estado global del proceso; se recomienda un consumidor PAM aislado por proceso.
- No protege frente a phishing en tiempo real, malware, compromiso de `root` o robo simultáneo de la contraseña y el dispositivo docente.

## Recuperación y desinstalación

Antes del despliegue:

1. conserva una consola local o sesión administrativa abierta;
2. prueba con una cuenta no crítica;
3. valida cada frontera horaria y un cruce de medianoche;
4. confirma la sincronización NTP;
5. verifica el procedimiento de rotación de secretos.

Para retirarlo, elimina primero las líneas PAM y después ejecuta:

```bash
cd pam_schedule_totp_override
sudo make uninstall
```

La desinstalación no elimina la configuración ni los secretos docentes.
