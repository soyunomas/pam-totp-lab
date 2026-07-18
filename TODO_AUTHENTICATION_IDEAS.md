# TODO: ideas experimentales TOTP para PAM

Este documento recopila propuestas para ampliar **PAM TOTP Lab** con nuevos módulos de autenticación TOTP.

Las propuestas siguen el estilo actual del proyecto:

- un módulo PAM independiente por idea;
- funcionamiento completamente local;
- compatibilidad con aplicaciones TOTP estándar siempre que sea posible;
- sin broker;
- sin daemon residente;
- sin servicios de red;
- sin TPM ni dispositivos especiales;
- sin criptografía inventada;
- con implementación pequeña, auditable y acompañada de pruebas.

Estas ideas son experimentales. Algunas aumentan realmente la resistencia frente a determinados ataques; otras exploran interfaces de autenticación, combinaciones de factores o mecanismos de protección local. Cada módulo debe documentar claramente qué mejora y qué no mejora.

## Objetivo

Explorar formas diferentes de utilizar TOTP dentro de PAM sin convertir el proyecto en una plataforma distribuida de autenticación.

Los módulos deben poder funcionar con una arquitectura sencilla:

```text
Aplicación
    │
    └── PAM
          │
          └── módulo experimental
                ├── configuración local
                ├── secreto TOTP
                ├── estado antirreplay opcional
                └── resultado PAM_SUCCESS / PAM_AUTH_ERR
```

Se permite una herramienta de configuración o enrolamiento ejecutada manualmente, pero no un proceso permanente.

## Reglas comunes

- [ ] Cada idea debe implementarse en su propio directorio.
- [ ] El módulo debe fallar de forma cerrada ante errores.
- [ ] No se aceptarán secretos mediante argumentos de línea de comandos.
- [ ] Los archivos de usuario deberán tener propietario y permisos estrictos.
- [ ] Los archivos globales deberán estar protegidos por `root`.
- [ ] Los códigos y secretos se compararán en tiempo constante cuando sea aplicable.
- [ ] Las copias sensibles se limpiarán explícitamente de memoria.
- [ ] La ventana TOTP tendrá un límite pequeño y configurable.
- [ ] Un código aceptado no podrá reutilizarse dentro del estado antirreplay disponible.
- [ ] No se escribirán códigos TOTP, contraseñas, PIN ni secretos en logs.
- [ ] Los límites de seguridad se explicarán sin presentar ofuscación como criptografía.
- [ ] Todos los módulos tendrán pruebas positivas, negativas, de permisos y de concurrencia.
- [ ] Ningún módulo se instalará automáticamente en `common-auth`.
- [ ] Cada README incluirá procedimiento de recuperación y desinstalación.

## Prioridad recomendada

| Orden | Proyecto | Valor | Complejidad | Aplicación TOTP estándar |
| ---: | --- | --- | --- | --- |
| 1 | `pam_totp_domains` | Muy alto | Baja | Sí |
| 2 | `pam_totp_epoch_guard` | Muy alto | Media | Sí |
| 3 | `pam_totp_quorum` | Alto | Media | Sí |
| 4 | `pam_totp_slot_challenge` | Alto | Media | Sí |
| 5 | `pam_totp_rollover` | Alto | Media | Sí |
| 6 | `pam_totp_sealed_seed` | Alto | Alta | Sí |
| 7 | `pam_totp_ladder` | Medio-alto | Media | Sí |
| 8 | `pam_totp_shuffle` | Experimental | Baja | Sí |
| 9 | `pam_totp_ticket` | Experimental | Alta | Sí |
| 10 | `pam_totp_duress` | Investigación | Media | Sí |
| 11 | `pam_schedule_totp_override` | Alto | Baja-media | Sí |

---

## 1. `pam_totp_domains`: secretos separados por servicio

### Idea

Utilizar un secreto TOTP diferente dependiendo del servicio PAM que solicita la autenticación.

Ejemplo:

```text
sshd  → secreto SSH
sudo  → secreto SUDO
login → secreto LOGIN
su    → secreto SU
```

Es frecuente reutilizar el mismo secreto TOTP para varios servicios. Si ese secreto queda expuesto, todos esos servicios quedan afectados.

Este módulo separaría criptográficamente los dominios de autenticación sin necesitar infraestructura externa.

### Experiencia de usuario

El usuario tendría varias entradas en su aplicación:

```text
Servidor - SSH
Servidor - SUDO
Servidor - LOGIN
```

El prompt indicaría claramente cuál debe utilizar:

```text
TOTP para SUDO:
```

### Formato de configuración

```text
~/.pam_totp_domains/
├── sshd.secret
├── sudo.secret
├── login.secret
└── su.secret
```

También podría utilizarse un único archivo estructurado con límites estrictos.

### Desarrollo

- [ ] `DOMAIN-01` Obtener el servicio exclusivamente mediante `PAM_SERVICE`.
- [ ] `DOMAIN-02` Definir una lista permitida de nombres de servicio.
- [ ] `DOMAIN-03` Rechazar rutas, separadores y nombres desconocidos.
- [ ] `DOMAIN-04` Implementar secretos independientes por servicio.
- [ ] `DOMAIN-05` Permitir una política explícita para servicios sin secreto.
- [ ] `DOMAIN-06` Implementar estado antirreplay separado por usuario y servicio.
- [ ] `DOMAIN-07` Crear una herramienta de enrolamiento que genere los QR.
- [ ] `DOMAIN-08` Añadir migración desde un único secreto TOTP.

### Pruebas de aceptación

- [ ] El código de SSH nunca funciona para `sudo`.
- [ ] Un nombre de servicio manipulado no permite leer otro archivo.
- [ ] El antirreplay de un servicio no bloquea códigos legítimos de otro.
- [ ] Un servicio desconocido se rechaza salvo configuración explícita.
- [ ] Los prompts muestran claramente el dominio solicitado.

### Valor de seguridad

Alto. Limita el impacto de la filtración de un secreto y evita reutilizar el mismo factor entre servicios con niveles de riesgo diferentes.

## 2. `pam_totp_epoch_guard`: antirreplay persistente entre reinicios

### Idea

Crear una variante de TOTP endurecida cuyo estado antirreplay sobreviva a reinicios.

Un estado almacenado únicamente en `/run` desaparece al reiniciar. Después del arranque, un código capturado dentro de la ventana válida podría volver a aceptarse hasta que el nuevo estado quede establecido.

Este módulo guardaría de forma segura el último contador TOTP consumido.

### Estado propuesto

```text
/var/lib/pam-totp-lab/replay/
└── <uid>-<service>.state
```

Contenido conceptual:

```text
version
uid
service
secret_id
last_counter
```

### Desarrollo

- [ ] `EPOCH-01` Definir un formato pequeño, versionado y acotado.
- [ ] `EPOCH-02` Crear archivos propiedad de `root` y no accesibles por usuarios.
- [ ] `EPOCH-03` Usar bloqueo exclusivo durante lectura, comparación y actualización.
- [ ] `EPOCH-04` Actualizar mediante archivo temporal, `fsync` y renombrado atómico.
- [ ] `EPOCH-05` Rechazar estados truncados, duplicados o con formato desconocido.
- [ ] `EPOCH-06` Definir comportamiento ante rollback del archivo.
- [ ] `EPOCH-07` Separar estado por UID, servicio y secreto enrolado.
- [ ] `EPOCH-08` Crear una herramienta administrativa para reiniciar el estado de forma explícita.

### Pruebas de aceptación

- [ ] Reiniciar el equipo no permite reutilizar el último código aceptado.
- [ ] Dos procesos concurrentes no pueden aceptar el mismo contador.
- [ ] Una caída durante la escritura no deja un estado permisivo.
- [ ] Un archivo vacío o corrupto produce denegación.
- [ ] Cambiar el secreto no hereda accidentalmente el contador anterior.
- [ ] El reloj atrasado no reactiva códigos consumidos.

### Valor de seguridad

Muy alto como mejora del módulo endurecido existente. No cambia la experiencia del usuario y resuelve una limitación concreta del estado volátil.

## 3. `pam_totp_quorum`: varios TOTP de un mismo usuario

### Idea

Exigir varios códigos TOTP independientes para autenticar a un único usuario.

Ejemplo de política:

```text
2 de 3 secretos registrados
```

Los secretos pueden estar almacenados en:

- un teléfono;
- una tableta;
- una llave con generador TOTP;
- una aplicación instalada en otro equipo.

No debe confundirse con `pam_2man_totp`: aquí existe un solo usuario, pero utiliza varias credenciales TOTP.

### Experiencia de usuario

```text
Código TOTP principal:
Código TOTP secundario:
```

O, para una política de tres credenciales:

```text
Introduce dos códigos de los slots A, B y C:
```

### Configuración

```text
~/.pam_totp_quorum
```

Ejemplo conceptual:

```text
threshold=2
slot=A:<secret>
slot=B:<secret>
slot=C:<secret>
```

### Desarrollo

- [ ] `QUORUM-01` Definir un máximo pequeño de slots.
- [ ] `QUORUM-02` Validar que cada secreto sea diferente.
- [ ] `QUORUM-03` Implementar políticas `1 de N`, `2 de N` y `N de N`.
- [ ] `QUORUM-04` Mantener estado antirreplay independiente por slot.
- [ ] `QUORUM-05` Evitar que el mismo código o slot cuente dos veces.
- [ ] `QUORUM-06` Permitir desactivar un slot mediante una herramienta administrativa.
- [ ] `QUORUM-07` Documentar que varios secretos en el mismo dispositivo no son factores realmente independientes.
- [ ] `QUORUM-08` Limitar el número de prompts y el tiempo total de autenticación.

### Pruebas de aceptación

- [ ] Un único slot no alcanza un umbral de dos.
- [ ] Repetir dos veces el mismo slot no alcanza el umbral.
- [ ] Un código válido para A no se acepta como B.
- [ ] Los códigos consumidos quedan registrados por separado.
- [ ] Un slot desactivado no puede utilizarse.
- [ ] Los errores no revelan qué slot concreto falló.

### Valor de seguridad

Alto cuando los secretos están realmente separados. Bajo si todos están guardados en la misma aplicación y el mismo dispositivo.

## 4. `pam_totp_slot_challenge`: selección aleatoria de credencial

### Idea

El usuario registra varios secretos TOTP identificados como slots:

```text
A, B, C, D
```

En cada autenticación, PAM selecciona aleatoriamente uno:

```text
Introduce el código del slot C:
```

Un atacante que haya robado solamente uno de los secretos no sabrá de antemano cuál será solicitado.

### Diferencia respecto a `pam_totp_quorum`

`pam_totp_quorum` exige varios códigos en cada login.

`pam_totp_slot_challenge` exige solo uno, pero cambia aleatoriamente cuál.

Es menos fuerte que un quorum, pero más cómodo.

### Desarrollo

- [ ] `SLOT-01` Permitir entre dos y ocho slots.
- [ ] `SLOT-02` Seleccionar el slot mediante aleatoriedad criptográfica.
- [ ] `SLOT-03` Evitar sesgos mediante selección uniforme.
- [ ] `SLOT-04` No permitir que el cliente elija el slot.
- [ ] `SLOT-05` Mantener antirreplay independiente para cada secreto.
- [ ] `SLOT-06` Permitir nombres cortos que no revelen el dispositivo.
- [ ] `SLOT-07` Implementar una opción `challenge_count=2`.
- [ ] `SLOT-08` Añadir estadísticas de prueba para verificar la distribución.

### Pruebas de aceptación

- [ ] Los slots aparecen con una distribución aproximadamente uniforme.
- [ ] El código de otro slot no es aceptado.
- [ ] El usuario no puede forzar repetidamente su slot preferido.
- [ ] Un fallo no provoca automáticamente la selección de un slot más débil.
- [ ] El mismo contador no puede consumirse dos veces en un slot.

### Limitación

Con un secreto comprometido y cuatro slots, el atacante tendría aproximadamente una oportunidad entre cuatro en cada desafío, antes de aplicar rate limiting.

No sustituye a un verdadero segundo factor independiente.

## 5. `pam_totp_rollover`: doble código consecutivo

### Idea

Exigir dos códigos TOTP pertenecientes a periodos temporales consecutivos.

Flujo:

```text
1. Introducir el código actual.
2. Esperar al siguiente intervalo.
3. Introducir el nuevo código.
```

Esto demuestra que el usuario conserva acceso al generador durante más de un instante. Un código capturado de forma aislada no sería suficiente.

### Experiencia de usuario

```text
Primer código TOTP:
Código correcto. Introduce el siguiente código cuando cambie:
```

Para evitar esperas excesivas, el módulo podría iniciar este flujo solo cuando queden pocos segundos para el cambio o mostrar:

```text
Siguiente código en aproximadamente 8 segundos.
```

### Desarrollo

- [ ] `ROLLOVER-01` Registrar el contador del primer código aceptado.
- [ ] `ROLLOVER-02` Exigir exactamente el contador siguiente.
- [ ] `ROLLOVER-03` Establecer un timeout total estricto.
- [ ] `ROLLOVER-04` No aceptar dos códigos del mismo periodo.
- [ ] `ROLLOVER-05` No aceptar un código anterior como segundo paso.
- [ ] `ROLLOVER-06` Consumir ambos contadores de forma segura.
- [ ] `ROLLOVER-07` Añadir un modo que espere antes del primer prompt cuando el periodo acaba de comenzar.
- [ ] `ROLLOVER-08` Documentar el impacto de hasta treinta segundos adicionales.

### Pruebas de aceptación

- [ ] Dos códigos del mismo contador son rechazados.
- [ ] Un código capturado anteriormente no completa el flujo.
- [ ] El segundo código debe corresponder exactamente al periodo siguiente.
- [ ] Un timeout invalida el primer paso.
- [ ] Dos autenticaciones simultáneas no pueden compartir la misma secuencia.

### Valor de seguridad

Medio-alto frente a capturas aisladas o respuestas obtenidas con antelación. Sigue siendo vulnerable a phishing interactivo en tiempo real.

## 6. `pam_totp_sealed_seed`: secreto TOTP cifrado con la contraseña

### Idea

Guardar el secreto TOTP cifrado en lugar de almacenarlo directamente en Base32.

La clave de cifrado se derivaría de la contraseña introducida por el usuario mediante un KDF estándar, como Argon2id o scrypt. Después se utilizaría un algoritmo AEAD mantenido por una biblioteca reconocida.

Flujo:

```text
contraseña PAM
    │
    ├── validación normal mediante pam_unix
    │
    └── derivación de clave
              │
              └── descifrado temporal del secreto TOTP
```

El módulo reutilizaría la contraseña mediante `use_first_pass` o `try_first_pass`, sin volver a mostrarla.

### Objetivo

La copia del archivo del usuario no sería suficiente para recuperar inmediatamente el secreto TOTP. También sería necesaria la contraseña correcta.

### Formato conceptual

```text
version
kdf
kdf_parameters
salt
nonce
ciphertext
authentication_tag
```

### Desarrollo

- [ ] `SEALED-01` Utilizar exclusivamente KDF y AEAD existentes.
- [ ] `SEALED-02` Definir parámetros mínimos y máximos del KDF.
- [ ] `SEALED-03` Integrar `use_first_pass` y `try_first_pass`.
- [ ] `SEALED-04` No conservar la contraseña más tiempo del necesario.
- [ ] `SEALED-05` Limpiar contraseña, clave derivada y secreto descifrado.
- [ ] `SEALED-06` Hacer indistinguibles los errores de contraseña, formato y TOTP.
- [ ] `SEALED-07` Crear una utilidad para enrolar y cambiar la contraseña.
- [ ] `SEALED-08` Diseñar una migración segura desde secretos en texto.
- [ ] `SEALED-09` Protegerse frente a parámetros KDF manipulados que agoten memoria.
- [ ] `SEALED-10` Documentar que `root` o un PAM comprometido puede capturar la contraseña durante el uso.

### Pruebas de aceptación

- [ ] Una contraseña incorrecta nunca produce un secreto utilizable.
- [ ] Alterar un byte del archivo invalida el descifrado.
- [ ] Los parámetros excesivos se rechazan antes de reservar memoria.
- [ ] No aparecen secretos en volcados de prueba después de la limpieza.
- [ ] Cambiar la contraseña vuelve a cifrar el secreto de forma segura.
- [ ] El módulo no solicita la contraseña dos veces cuando está correctamente apilado.

### Valor de seguridad

Alto frente al robo aislado del archivo TOTP. No protege frente a `root`, malware dentro del proceso PAM o captura de la contraseña durante la autenticación.

## 7. `pam_totp_ladder`: dificultad adaptativa local

### Idea

Aumentar progresivamente el requisito TOTP después de intentos fallidos.

Ejemplo:

```text
Estado normal:
    1 TOTP

Después de 2 fallos:
    1 TOTP + espera

Después de 4 fallos:
    2 TOTP consecutivos

Después de 6 fallos:
    bloqueo temporal
```

No se trata de aceptar diferentes niveles de seguridad según el riesgo, sino de hacer que los fallos nunca reduzcan la protección.

### Estado local

```text
/run/pam-totp-lab/ladder/<uid>-<service>
```

O estado persistente, según la política elegida.

### Desarrollo

- [ ] `LADDER-01` Definir estados y transiciones explícitas.
- [ ] `LADDER-02` Separar contadores por usuario y servicio.
- [ ] `LADDER-03` Evitar desbordamientos y valores negativos.
- [ ] `LADDER-04` Aplicar retrasos con un límite máximo.
- [ ] `LADDER-05` Escalar a `pam_totp_rollover` después del umbral.
- [ ] `LADDER-06` Reiniciar gradualmente el nivel después de accesos válidos.
- [ ] `LADDER-07` Evitar que un atacante bloquee indefinidamente una cuenta.
- [ ] `LADDER-08` Añadir herramienta administrativa para consultar y reiniciar estado.
- [ ] `LADDER-09` No revelar si el usuario existe.
- [ ] `LADDER-10` Probar intentos concurrentes.

### Pruebas de aceptación

- [ ] Los fallos siempre mantienen o aumentan el nivel.
- [ ] Un acceso correcto no borra arbitrariamente todo el historial.
- [ ] Cien procesos concurrentes no pierden incrementos.
- [ ] El estado de un usuario no afecta a otro.
- [ ] El bloqueo tiene una duración máxima documentada.
- [ ] La ausencia o corrupción del estado no concede acceso.

### Riesgo

Puede utilizarse para causar denegación de servicio. El diseño deberá equilibrar escalado, rate limiting y recuperación.

## 8. `pam_totp_shuffle`: entrada permutada

### Idea

Mostrar una permutación aleatoria de las posiciones del código TOTP.

Para un código:

```text
123456
```

El módulo podría mostrar:

```text
Introduce las posiciones en este orden: 4-1-6-2-5-3
```

La respuesta sería:

```text
416253
```

El módulo reconstruye internamente el TOTP original y lo valida.

### Variantes

#### Permutación completa

```text
Orden: 4-1-6-2-5-3
```

#### Rotación

```text
Empieza por la posición 3 y continúa circularmente
```

#### Inversión

```text
Introduce el código de derecha a izquierda
```

La permutación completa es la variante principal.

### Desarrollo

- [ ] `SHUFFLE-01` Generar una permutación uniforme.
- [ ] `SHUFFLE-02` Mostrar todas las posiciones sin ambigüedad.
- [ ] `SHUFFLE-03` Validar exactamente seis dígitos.
- [ ] `SHUFFLE-04` Reconstruir el código sin modificar el buffer original.
- [ ] `SHUFFLE-05` Limpiar tanto la entrada como el código reconstruido.
- [ ] `SHUFFLE-06` Añadir modo de accesibilidad con rotaciones simples.
- [ ] `SHUFFLE-07` Evitar repetir patrones predecibles.
- [ ] `SHUFFLE-08` Integrar el antirreplay normal.

### Pruebas de aceptación

- [ ] Todas las permutaciones reconstruyen correctamente el código.
- [ ] Posiciones repetidas o ausentes son rechazadas.
- [ ] Una respuesta correspondiente a otra permutación falla.
- [ ] No se producen accesos fuera de rango.
- [ ] El código original y el transformado se limpian de memoria.

### Valor de seguridad

Experimental.

Puede dificultar observaciones parciales donde una persona ve únicamente el teclado o solo la respuesta. No protege frente a un keylogger que capture también el prompt, una grabación completa de pantalla ni phishing en tiempo real.

No debe presentarse como un nuevo factor.

## 9. `pam_totp_ticket`: reutilización local limitada

### Idea

Después de una autenticación TOTP correcta, crear un ticket local de corta duración para evitar solicitar códigos repetidamente.

El ticket estaría ligado como mínimo a:

```text
usuario
servicio PAM
terminal o sesión
boot_id
hora de emisión
hora de expiración
```

No existiría ningún daemon. El propio módulo PAM leería y actualizaría archivos protegidos por `root`.

### Ejemplo

```text
Primer sudo:
    contraseña + TOTP

Siguientes sudo durante 3 minutos en la misma terminal:
    contraseña, sin nuevo TOTP
```

### Objetivo

Explorar una experiencia similar al timestamp de `sudo`, pero controlada por el módulo TOTP y con vinculaciones más estrictas.

### Desarrollo

- [ ] `TICKET-01` Definir exactamente qué identifica una sesión o terminal.
- [ ] `TICKET-02` No confiar en variables de entorno proporcionadas por el cliente.
- [ ] `TICKET-03` Vincular el ticket a usuario, servicio y `boot_id`.
- [ ] `TICKET-04` Establecer una duración máxima pequeña.
- [ ] `TICKET-05` Crear y actualizar tickets de forma atómica.
- [ ] `TICKET-06` Añadir opción `always_prompt` para servicios críticos.
- [ ] `TICKET-07` Invalidar tickets al reiniciar.
- [ ] `TICKET-08` Proporcionar una orden para eliminar todos los tickets.
- [ ] `TICKET-09` No permitir que un usuario copie el ticket de otro.
- [ ] `TICKET-10` Comparar el riesgo con el timestamp nativo de `sudo`.

### Pruebas de aceptación

- [ ] El ticket no funciona en otra terminal.
- [ ] El ticket no funciona para otro servicio.
- [ ] El ticket no funciona para otro usuario.
- [ ] Cambiar el `boot_id` lo invalida.
- [ ] Un archivo copiado o modificado es rechazado.
- [ ] La expiración no puede evitarse atrasando el reloj de pared.
- [ ] La configuración de servicios críticos ignora cualquier ticket.

### Valor de seguridad

No aumenta la seguridad criptográfica. Es un experimento de equilibrio entre seguridad y usabilidad.

Una duración excesiva convertiría el ticket en una forma de omitir el segundo factor.

## 10. `pam_totp_duress`: código de coacción

### Idea

Registrar un segundo secreto TOTP destinado a situaciones de coacción.

El código de coacción **nunca concedería acceso**. Produciría el mismo error visible que un código incorrecto, pero escribiría un evento local protegido.

```text
TOTP normal  → autenticación normal
TOTP coacción → denegación + registro local
TOTP inválido → denegación normal
```

### Acción local permitida

Inicialmente, solo:

- escribir un marcador propiedad de `root`;
- generar un mensaje genérico en `syslog`;
- incrementar un contador de incidentes.

No se enviarán mensajes de red ni se ejecutarán comandos.

### Desarrollo

- [ ] `DURESS-01` Exigir secretos normal y de coacción diferentes.
- [ ] `DURESS-02` Comparar ambos códigos sin diferencias temporales observables.
- [ ] `DURESS-03` Denegar siempre el acceso tras un código de coacción.
- [ ] `DURESS-04` No revelar en el prompt que existe esta función.
- [ ] `DURESS-05` Crear el marcador mediante escritura atómica.
- [ ] `DURESS-06` Aplicar límites al número y tamaño de eventos.
- [ ] `DURESS-07` No ejecutar scripts ni comandos configurables.
- [ ] `DURESS-08` Diseñar un método administrativo para consultar y limpiar alertas.
- [ ] `DURESS-09` Analizar diferencias de tiempo y mensajes.
- [ ] `DURESS-10` Documentar los riesgos humanos del mecanismo.

### Pruebas de aceptación

- [ ] Un código de coacción jamás devuelve `PAM_SUCCESS`.
- [ ] El mensaje visible es equivalente al de un fallo ordinario.
- [ ] El evento no contiene el código introducido.
- [ ] Un usuario no puede eliminar el marcador.
- [ ] Un atacante no puede utilizar la función para llenar el disco.
- [ ] No existen diferencias temporales claras entre fallo normal y coacción.

### Riesgo

Es una función delicada. Si la persona que coacciona espera que el acceso funcione, la denegación puede empeorar la situación.

Debe mantenerse como investigación y no presentarse como una solución universal de seguridad personal.


## 11. `pam_schedule_totp_override`: excepción horaria autorizada por profesor

> **Estado:** implementado en `pam_schedule_totp_override/`, con pruebas de política, archivos, concurrencia, integración PAM y endurecimiento.

### Idea

Combinar una política horaria normal con una excepción TOTP supervisada. Cada cuenta puede autenticarse sin excepción únicamente durante su franja asignada:

```text
usuario A → mañana
usuario B → tarde
usuario C → noche
```

Fuera de esa franja, la contraseña habitual no basta. El módulo solicita un TOTP adicional controlado por el profesor:

```text
usuario B intenta entrar por la mañana
    ├── contraseña correcta
    ├── horario ordinario denegado
    └── TOTP de excepción para B → acceso excepcional
```

El objetivo es autorizar exámenes, recuperaciones o actividades extraordinarias sin modificar temporalmente el horario general ni revelar un secreto permanente nuevo al alumno.

### Diseño recomendado

La primera versión debe ser un módulo de autenticación combinado y fail-closed:

1. Obtener usuario, servicio y hora desde fuentes confiables de PAM y del sistema.
2. Validar la contraseña mediante el módulo normal del stack.
3. Comprobar la franja configurada para la cuenta.
4. Si está dentro de horario, devolver éxito sin solicitar TOTP de excepción.
5. Si está fuera de horario, solicitar un TOTP de profesor específico para esa cuenta.
6. Consumir el contador mediante estado antirreplay separado por usuario y servicio.
7. Registrar únicamente que se utilizó una excepción, nunca el código ni el secreto.

No debe utilizarse un único secreto TOTP global. Un código global podría autorizar cualquier cuenta durante la misma ventana temporal. La configuración recomendada utiliza un secreto distinto por cuenta protegida:

```text
/etc/security/pam-schedule-override/
├── A.secret
├── B.secret
└── C.secret
```

Los archivos serán propiedad de `root`, regulares, sin enlaces y con permisos estrictos. El profesor tendrá las entradas correspondientes en una aplicación TOTP estándar:

```text
Centro - Excepción A
Centro - Excepción B
Centro - Excepción C
```

### Configuración conceptual

```text
/etc/security/pam-schedule-override.conf
```

```text
user=A;days=Mo-Fr;time=0800-1400;override=A.secret
user=B;days=Mo-Fr;time=1400-2000;override=B.secret
user=C;days=Mo-Fr;time=2000-2359;override=C.secret
```

La sintaxis real deberá ser pequeña, versionada, sin expresiones ambiguas y con una política explícita para zonas horarias, cambios de hora y días festivos.

### Experiencia de usuario

Dentro del horario ordinario:

```text
Password:
```

Fuera del horario:

```text
Password:
Acceso fuera de horario. Código de autorización docente:
```

Por seguridad operativa, es preferible que el profesor introduzca el código directamente o supervise su uso. Dictarlo al alumno permite que sea reenviado durante su breve periodo de validez.

### Desarrollo

- [x] `SCHEDOVR-01` Definir una lista cerrada de usuarios o grupos sujetos a la política.
- [x] `SCHEDOVR-02` Implementar franjas sin solapamientos ambiguos y con límites exactos.
- [x] `SCHEDOVR-03` Obtener fecha y hora del sistema sin confiar en variables del cliente.
- [x] `SCHEDOVR-04` Exigir un secreto de excepción diferente por cuenta o ámbito autorizado.
- [x] `SCHEDOVR-05` Guardar configuración y secretos únicamente en archivos protegidos por `root`.
- [x] `SCHEDOVR-06` Validar TOTP estándar con una ventana pequeña.
- [x] `SCHEDOVR-07` Mantener antirreplay por usuario, servicio, secreto y contador.
- [x] `SCHEDOVR-08` Aplicar rate limiting a los intentos fuera de horario.
- [x] `SCHEDOVR-09` Registrar usuario, servicio, instante y resultado sin registrar credenciales.
- [x] `SCHEDOVR-10` Definir rotación y revocación inmediata de secretos docentes.
- [x] `SCHEDOVR-11` Probar cambios de hora, reloj adelantado o atrasado y cruces de medianoche.
- [x] `SCHEDOVR-12` Documentar que la política se comprueba al autenticar y no finaliza sesiones ya abiertas.

### Pruebas de aceptación

- [x] A puede entrar por la mañana sin TOTP de excepción.
- [x] B no puede entrar por la mañana usando solo la contraseña compartida.
- [x] B puede entrar por la mañana con el TOTP específico de B.
- [x] El TOTP de A no autoriza a B ni a C.
- [x] Un TOTP aceptado no puede reutilizarse en otro intento o servicio.
- [x] Un secreto ausente, corrupto o con permisos inseguros produce denegación.
- [x] Una configuración horaria solapada, incompleta o inválida produce denegación.
- [x] Los intentos concurrentes no aceptan dos veces el mismo contador.
- [x] Los logs permiten auditar la excepción sin revelar el código.
- [x] Cambiar la hora del cliente no altera la decisión del servidor.

### Ventajas

- Reutiliza aplicaciones TOTP estándar y no necesita red ni daemon.
- Mantiene horarios estables y permite excepciones inmediatas.
- Un secreto por cuenta limita el alcance de una filtración.
- El antirreplay y la auditoría permiten investigar usos excepcionales.
- Es sencillo para un centro con pocas cuentas compartidas o funcionales.

### Inconvenientes y límites

- Una contraseña conocida por todos no identifica a la persona real. Cualquier alumno puede intentar usar cualquier cuenta cuya contraseña conozca.
- El TOTP autoriza una excepción, pero no corrige la falta de atribución causada por las contraseñas compartidas.
- Un código dictado puede reenviarse o utilizarse por otra persona mientras siga vigente.
- El compromiso del teléfono del profesor afecta todas las cuentas enroladas en ese dispositivo.
- Requiere sincronización horaria, protección antirreplay y rate limiting.
- PAM normalmente evalúa la política al iniciar la sesión; no expulsa automáticamente una sesión cuando termina la franja.
- Varios profesores necesitan un procedimiento controlado de enrolamiento, baja y rotación.

### Variante preferible para mayor atribución

Para una versión posterior, una utilidad administrativa podría crear un permiso local de un solo uso, ligado a usuario, servicio, fecha, terminal y expiración. El profesor autorizaría exactamente a B para el examen concreto, evitando que un TOTP genérico pueda reenviarse a otra cuenta. Esta variante añade estado y complejidad, pero expresa mejor una autorización que un TOTP estándar.

### Valor de seguridad

Alto como control de política y autorización excepcional en un entorno pequeño. No debe presentarse como identificación individual mientras las contraseñas sigan siendo compartidas. Su principal beneficio es impedir el acceso fuera de horario sin presencia o autorización del profesor.

---

## Ideas descartadas inicialmente

### TOTP modificado con algoritmos propios

No crear variantes incompatibles de HMAC, truncado dinámico o generación temporal.

El laboratorio debe utilizar TOTP estándar o construcciones claramente separadas alrededor de TOTP.

### Códigos derivados de ubicación o dirección IP

La ubicación, IP, SSID o RSSI pueden utilizarse como política contextual, pero no contienen un secreto y no son factores independientes.

### Aceptar códigos futuros amplios

Una ventana TOTP grande facilita ataques y no debe utilizarse para ocultar problemas de sincronización.

### Secretos incluidos en el binario

Compilar secretos directamente dentro de un módulo no proporciona una protección adecuada y dificulta la rotación.

### Transformaciones mentales no especificadas

Operaciones como sumar fechas, invertir selectivamente números o aplicar reglas personales pueden explorarse como UX, pero no deben describirse como criptografía.

### Ejecución de scripts tras autenticación

Los módulos no construirán ni ejecutarán comandos basándose en datos introducidos por el usuario.

### Aplicación móvil propia durante las primeras fases

Las primeras versiones utilizarán aplicaciones TOTP estándar. Una aplicación personalizada ampliaría demasiado el alcance y dificultaría distinguir los fallos PAM de los fallos del cliente.

---

## Fases de ejecución

### Fase 0 — Componentes reutilizables

- [ ] Extraer un validador común de secretos Base32.
- [ ] Extraer la generación y validación TOTP.
- [ ] Extraer comparación constante.
- [ ] Extraer limpieza segura de memoria.
- [ ] Extraer comprobación de permisos y propietarios.
- [ ] Extraer el almacenamiento antirreplay.
- [ ] Crear un reloj simulado para las pruebas.
- [ ] Crear dobles para conversaciones PAM.
- [ ] Añadir fuzzing de archivos de configuración.
- [ ] Mantener cada módulo enlazable y verificable por separado.

#### Criterio de salida

Los componentes comunes tienen una API pequeña y no cambian el comportamiento de los módulos existentes.

### Fase 1 — Mejoras prácticas

Implementar:

1. `pam_totp_domains`
2. `pam_totp_epoch_guard`

#### Criterio de salida

- Los secretos están separados por servicio.
- El antirreplay sobrevive a reinicios.
- No cambia la experiencia habitual de introducir un TOTP.

### Fase 2 — Múltiples secretos

Implementar:

1. `pam_totp_slot_challenge`
2. `pam_totp_quorum`

#### Criterio de salida

- Los slots no pueden confundirse.
- Un secreto no cuenta varias veces.
- La independencia real de dispositivos queda documentada.

### Fase 3 — Desafíos temporales

Implementar:

1. `pam_totp_rollover`
2. `pam_totp_ladder`

#### Criterio de salida

- El estado concurrente es consistente.
- Los fallos nunca reducen el requisito.
- Los timeouts no dejan autenticaciones parcialmente válidas.

### Fase 4 — Protección del secreto

Implementar:

1. `pam_totp_sealed_seed`

#### Criterio de salida

- Se utilizan bibliotecas criptográficas mantenidas.
- El archivo está autenticado.
- Los secretos temporales se limpian.
- Los parámetros del KDF están limitados.

### Fase 5 — Experimentos de UX y política

Evaluar por separado:

1. `pam_totp_shuffle`
2. `pam_totp_ticket`
3. `pam_totp_duress`
4. `pam_schedule_totp_override`

#### Criterio de salida

Cada README diferencia claramente entre:

- seguridad criptográfica;
- mitigación parcial;
- comodidad;
- ofuscación;
- riesgos operativos.

---

## Checklist por módulo

- [ ] Tiene un modelo de amenazas.
- [ ] Indica explícitamente qué ataques no evita.
- [ ] Usa TOTP estándar.
- [ ] No introduce un proceso residente.
- [ ] No necesita conectividad.
- [ ] Los formatos están versionados y acotados.
- [ ] Comprueba propietario, tipo y permisos de cada archivo.
- [ ] No sigue enlaces simbólicos inseguros.
- [ ] No registra secretos ni respuestas.
- [ ] Limpia memoria sensible.
- [ ] Implementa comparación constante cuando corresponda.
- [ ] Tiene rate limiting o documenta por qué no lo necesita.
- [ ] Tiene protección antirreplay.
- [ ] Tiene pruebas de concurrencia.
- [ ] Tiene pruebas con reloj adelantado y atrasado.
- [ ] Tiene pruebas de archivos truncados y corruptos.
- [ ] Compila con GCC y Clang sin warnings.
- [ ] Pasa sanitizers.
- [ ] Pasa Valgrind cuando sea aplicable.
- [ ] Incluye instalación, desinstalación y recuperación.
- [ ] No se instala automáticamente en el stack PAM principal.

---

## Resultado esperado

El objetivo no es sustituir `pam_strict_totp`, sino crear una colección de módulos comparables:

```text
pam_strict_totp
    └── TOTP endurecido de referencia

pam_totp_domains
    └── separación por servicio

pam_totp_epoch_guard
    └── antirreplay persistente

pam_totp_quorum
    └── varios secretos simultáneos

pam_totp_slot_challenge
    └── selección aleatoria de secreto

pam_totp_rollover
    └── dos periodos consecutivos

pam_totp_sealed_seed
    └── secreto cifrado con contraseña

pam_totp_ladder
    └── dificultad adaptativa

pam_totp_shuffle
    └── transformación de entrada

pam_totp_ticket
    └── caché local limitada

pam_totp_duress
    └── detección local de coacción

pam_schedule_totp_override
    └── excepción horaria autorizada por profesor
```

Cada módulo debe continuar siendo pequeño, local, compilable y comprensible sin depender de una arquitectura externa.
