# TODO: autenticación PAM experimental

Este documento recopila conceptos de autenticación para futuras ampliaciones de
PAM TOTP Lab. Son propuestas de investigación, no mecanismos listos para
producción. Que una combinación parezca original no demuestra que sea inédita ni
que sea segura: antes de implementarla se debe revisar literatura, proyectos y,
si procede, patentes relacionadas.

## Objetivo

Explorar un modelo en el que PAM no se limite a responder «la identidad parece
válida», sino que pueda comprobar intención, integridad del equipo, procedencia
de la sesión y límites concretos de autorización.

El resultado ideal sería una autorización:

- ligada a una acción y un equipo concretos;
- válida durante poco tiempo;
- de un solo uso o con un presupuesto explícito;
- resistente a repetición y confusión entre servicios;
- revocable y recuperable sin crear una puerta trasera.

## Reglas antes de empezar

- [ ] Probar cada módulo únicamente con el harness aislado del repositorio.
- [ ] No instalar un prototipo en `common-auth`, acceso remoto o una cuenta
  administrativa sin una vía de recuperación independiente y ensayada.
- [ ] Mantener el módulo PAM pequeño: sensores, red, TPM y operaciones lentas
  deben vivir en un broker separado con privilegios mínimos.
- [ ] Aplicar *fail closed* ante firmas inválidas, mensajes truncados, versiones
  desconocidas, timeouts o estado anti-replay inconsistente.
- [ ] Limitar tamaños, número de elementos, tiempo y memoria antes de procesar
  cualquier mensaje.
- [ ] No ejecutar una shell ni construir comandos a partir de datos recibidos.
- [ ] No registrar secretos, respuestas, datos biométricos ni capacidades.
- [ ] Comparar valores secretos en tiempo constante y limpiar copias sensibles.
- [ ] Usar nonces impredecibles, caducidad corta y consumo atómico.
- [ ] Vincular cada prueba al usuario, servicio PAM, host, sesión y versión del
  protocolo; no confiar en variables de entorno controlables por el cliente.
- [ ] Documentar el modelo de amenazas y las propiedades que el prototipo no
  ofrece antes de escribir el módulo.
- [ ] Ejecutar `make -C tests verify` y añadir pruebas específicas antes de pasar
  una tarea a completada.

## Arquitectura común propuesta

```text
Aplicación PAM
    │
    ├── módulo PAM: valida contexto, límites y resultado final
    │       │
    │       └── socket Unix autenticado y con timeout
    │               │
    │               └── broker sin privilegios
    │                      ├── TPM / llave física
    │                      ├── dispositivo acompañante
    │                      ├── almacén anti-replay
    │                      └── motor de políticas
    │
    └── vía de recuperación independiente
```

### Trabajo común

- [ ] `CORE-01` Definir un modelo de amenazas común: atacante remoto, proceso
  local sin privilegios, usuario malicioso, relay, replay, reloj manipulado,
  broker caído y administrador que pierde todos sus factores.
- [ ] `CORE-02` Especificar un sobre de mensaje versionado y con codificación
  canónica. Debe contener como mínimo tipo, versión, usuario, servicio, host,
  identificador de sesión, nonce y vencimiento.
- [ ] `CORE-03` Diseñar el socket Unix: ruta fija, propietario y modo estrictos,
  comprobación de credenciales del proceso, timeout y mensajes acotados.
- [ ] `CORE-04` Crear un broker de referencia que arranque sin secretos en la
  línea de comandos, reduzca privilegios y rechace clientes no autorizados.
- [ ] `CORE-05` Reutilizar o ampliar el almacén anti-replay para efectuar una
  transición atómica `pendiente -> consumida`.
- [ ] `CORE-06` Definir códigos de error internos que no revelen si falló una
  identidad, dispositivo, firma o política concreta.
- [ ] `CORE-07` Añadir dobles de prueba para reloj, aleatoriedad, broker, TPM y
  dispositivo externo; ninguna prueba automática debe depender de hardware.
- [ ] `CORE-08` Crear pruebas de protocolo para mensajes vacíos, demasiado
  grandes, duplicados, fuera de orden, con versión futura y con campos repetidos.
- [ ] `CORE-09` Crear pruebas de concurrencia, caída entre escritura y `fsync`,
  cancelación, timeout, reloj atrasado y repetición después de reiniciar.
- [ ] `CORE-10` Documentar instalación, desinstalación y recuperación antes de
  permitir una prueba manual con PAM real.

## Prioridad recomendada

| Orden | Proyecto | Valor de investigación | Complejidad | Dependencias |
| ---: | --- | --- | --- | --- |
| 1 | `pam_intentseal` | Muy alto | Media | `CORE-01..10` |
| 2 | `pam_capability_mint` | Muy alto | Alta | `pam_intentseal` |
| 3 | `pam_boot_and_human` | Alto | Alta | TPM 2.0 simulado |
| 4 | `pam_trust_budget` | Alto | Alta | capacidades consumibles |
| 5 | `pam_causal_chain` | Alto | Muy alta | agente de sesión |
| 6 | `pam_delayed_recovery` | Alto | Alta | estado persistente seguro |
| 7 | `pam_witness_mesh` | Medio | Muy alta | varios firmantes |
| 8 | `pam_private_presence` | Medio | Muy alta | hardware de proximidad |
| 9 | `pam_decay` | Medio | Muy alta | daemon de sesión |
| 10 | `pam_policy_shards` | Experimental | Muy alta | varias anteriores |

---

## 1. `pam_intentseal`: firma explícita de intención

### Idea

El usuario no aprueba un login genérico: firma una descripción canónica de la
acción. Un dispositivo acompañante podría mostrar «autorizar el servicio X en el
host Y» y firmar algo equivalente a:

```text
version | user | pam_service | host | session | action_digest | nonce | expires
```

El texto mostrado y los bytes firmados deben proceder del mismo objeto
canónico. Si la aplicación no entrega de forma autenticada la acción solicitada,
el módulo solo podrá firmar el inicio de sesión o servicio, no inventar ese dato.

### Desarrollo

- [ ] `INTENT-01` Definir qué contexto entrega PAM de forma fiable y qué contexto
  necesita integración específica con la aplicación consumidora.
- [ ] `INTENT-02` Especificar el objeto de intención y su codificación canónica.
- [ ] `INTENT-03` Implementar generador de nonce y registro atómico de desafíos.
- [ ] `INTENT-04` Crear un firmante de laboratorio con claves desechables; no
  empezar por una aplicación móvil real.
- [ ] `INTENT-05` Verificar firma, propósito, host, servicio, vencimiento y estado
  de consumo en el broker.
- [ ] `INTENT-06` Construir `pam_intentseal.so` como cliente fino del broker.
- [ ] `INTENT-07` Añadir confirmación humana que muestre todos los datos relevantes
  y rechace textos recortados o ambiguos.
- [ ] `INTENT-08` Documentar integraciones que solo puedan autenticar servicio y
  aquellas capaces de autenticar una operación concreta.

### Pruebas de aceptación

- [ ] Una firma para otro host, usuario, servicio, acción o versión es rechazada.
- [ ] Dos solicitudes simultáneas no pueden consumir la misma aprobación.
- [ ] Una respuesta válida recibida después del timeout es rechazada.
- [ ] Reiniciar el broker no permite repetir una aprobación consumida.
- [ ] Alterar el texto mostrado o cualquier byte firmado invalida la operación.

### Condición de parada

No conectar a un dispositivo real mientras el formato firmado pueda tener dos
representaciones válidas o la aplicación no pueda suministrar el contexto de
forma autenticada.

## 2. `pam_capability_mint`: capacidades mínimas y consumibles

### Idea

Después de una autenticación fuerte, emitir una capacidad opaca limitada a una
acción, audiencia y vencimiento. Usarla debe consumirla atómicamente; copiarla no
debe otorgar una segunda autorización.

### Desarrollo

- [ ] `CAP-01` Definir emisor, audiencia, propósito, identificador único,
  vencimiento y número máximo de usos.
- [ ] `CAP-02` Decidir entre capacidades firmadas con registro de consumo o
  referencias aleatorias a estado conservado por el broker.
- [ ] `CAP-03` Implementar emisión únicamente después de `pam_intentseal`.
- [ ] `CAP-04` Vincular la capacidad al proceso o sesión cuando el consumidor
  pueda proporcionar esa identidad de forma fiable.
- [ ] `CAP-05` Implementar revocación y consumo transaccional resistente a fallos.
- [ ] `CAP-06` Añadir una herramienta administrativa que solo liste metadatos no
  sensibles y permita revocar, nunca exportar capacidades.

### Pruebas de aceptación

- [ ] Una capacidad no funciona en otro servicio, host o acción.
- [ ] Copiarla antes de usarla no permite dos consumos concurrentes.
- [ ] Una capacidad revocada o vencida no puede reactivarse atrasando el reloj.
- [ ] Un fallo durante el consumo queda en un estado seguro y recuperable.

## 3. `pam_boot_and_human`: integridad del equipo más usuario

### Idea

Combinar una autenticación humana con una prueba fresca del estado medido de la
máquina. El TPM firma una cita ligada al nonce de la sesión; una política decide
si ese estado es aceptable. La atestación identifica el estado del equipo, no a
la persona, por lo que nunca debe usarse sola.

### Desarrollo

- [ ] `BOOT-01` Crear primero un backend simulado de TPM y vectores de prueba.
- [ ] `BOOT-02` Definir qué mediciones se evaluarán y cómo se actualizará la
  política después de cambios legítimos de firmware, kernel o configuración.
- [ ] `BOOT-03` Verificar firma, nonce, selección de mediciones y log de eventos.
- [ ] `BOOT-04` Combinar el resultado con un factor humano independiente.
- [ ] `BOOT-05` Diseñar un modo de recuperación que no convierta cada actualización
  del sistema en un bloqueo permanente.
- [ ] `BOOT-06` Implementar un backend TPM real solo después de pasar el simulador.

### Pruebas de aceptación

- [ ] Una cita antigua, de otro TPM o para otro nonce es rechazada.
- [ ] Cambiar una medición relevante conduce al estado esperado por la política.
- [ ] Un TPM no disponible falla de la forma documentada para cada servicio.
- [ ] Actualizar la política requiere autorización y deja un registro auditable.

## 4. `pam_trust_budget`: presupuesto de privilegios

### Idea

Una autenticación fuerte desbloquea un presupuesto limitado: por ejemplo,
varias operaciones ordinarias y una operación crítica. Cada uso consume una
unidad. La seguridad no debe depender de esconder el contador.

### Desarrollo

- [ ] `BUDGET-01` Modelar presupuestos por usuario, servicio, acción y periodo.
- [ ] `BUDGET-02` Separar autenticación, autorización y recarga del presupuesto.
- [ ] `BUDGET-03` Hacer el decremento atómico y resistente a reinicios.
- [ ] `BUDGET-04` Impedir que intentos fallidos de un atacante agoten el presupuesto
  antes de demostrar control de la capacidad correspondiente.
- [ ] `BUDGET-05` Definir escalado: agotado el presupuesto, exigir una nueva
  autenticación o un segundo aprobador, nunca conceder silenciosamente.
- [ ] `BUDGET-06` Ofrecer consulta de saldo sin revelar capacidades ni secretos.

### Pruebas de aceptación

- [ ] Cien consumos concurrentes nunca superan el presupuesto emitido.
- [ ] Un usuario no puede consultar ni consumir el presupuesto de otro.
- [ ] Un reloj manipulado no recarga anticipadamente el presupuesto.
- [ ] La recuperación tras un fallo no duplica ni pierde unidades sin registro.

## 5. `pam_causal_chain`: prueba de procedencia de la sesión

### Idea

Construir una cadena autenticada entre arranque, login, terminal, shell y
solicitud privilegiada. El objetivo es distinguir una petición nacida de una
sesión legítima de otra inyectada desde un proceso o terminal diferente.

### Desarrollo

- [ ] `CHAIN-01` Definir exactamente qué amenaza se pretende detectar y cuáles
  quedan fuera; un proceso con control total de la sesión puede seguir siendo
  indistinguible del usuario.
- [ ] `CHAIN-02` Crear identificadores no reutilizables para sesión y terminal.
- [ ] `CHAIN-03` Encadenar eventos mediante hashes autenticados y claves efímeras.
- [ ] `CHAIN-04` Obtener identidad de procesos mediante mecanismos del sistema,
  no mediante PID aislado ni datos proporcionados por el cliente.
- [ ] `CHAIN-05` Diseñar cierre, bifurcación, suspensión y restauración de sesión.
- [ ] `CHAIN-06` Integrar la verificación como condición adicional de una
  capacidad, no como prueba humana independiente.

### Pruebas de aceptación

- [ ] Reutilizar un eslabón desde otra sesión o terminal es rechazado.
- [ ] PID reutilizado, procesos huérfanos y bifurcaciones no confunden la cadena.
- [ ] Suspender, reanudar y cerrar sesión invalidan los elementos previstos.
- [ ] La ausencia del agente no produce una concesión por defecto.

## 6. `pam_delayed_recovery`: recuperación retardada y cancelable

### Idea

Permitir iniciar una recuperación cuando se pierden todos los factores, pero
aplicando una espera visible, notificaciones y posibilidad de cancelación. Al
terminar el plazo se emitiría una autorización de recuperación limitada y de un
solo uso, nunca el secreto original.

### Desarrollo

- [ ] `REC-01` Separar el canal de recuperación del stack PAM que se recupera.
- [ ] `REC-02` Definir estados `solicitada`, `notificada`, `cancelada`, `madura`,
  `consumida` y `expirada`, con transiciones atómicas.
- [ ] `REC-03` Diseñar varios métodos de notificación sin incluir secretos.
- [ ] `REC-04` Permitir cancelación con cualquier factor superviviente.
- [ ] `REC-05` Emitir una capacidad limitada a reinscribir factores, no acceso
  administrativo general.
- [ ] `REC-06` Añadir rate limiting y protección contra solicitudes repetidas.

### Pruebas de aceptación

- [ ] Atrasar o adelantar el reloj no evita la espera configurada.
- [ ] Cancelar y solicitar simultáneamente termina en un único estado válido.
- [ ] La autorización madura solo puede reinscribir y solo puede usarse una vez.
- [ ] Una avalancha de solicitudes no oculta la notificación legítima ni bloquea
  indefinidamente la cuenta.

## 7. `pam_witness_mesh`: consenso entre testigos

### Idea

Exigir un umbral de testigos independientes —por ejemplo equipo, llave física y
otro dispositivo— que firmen el mismo desafío contextual. No basta con contar
respuestas: cada testigo debe representar una frontera de confianza diferente.

### Desarrollo

- [ ] `MESH-01` Definir identidad, rol y método de alta/baja de cada testigo.
- [ ] `MESH-02` Implementar una política de umbral explícita y versionada.
- [ ] `MESH-03` Hacer que todos firmen exactamente el mismo objeto de intención.
- [ ] `MESH-04` Evitar que clonar un único dispositivo cree varios votos.
- [ ] `MESH-05` Diseñar rotación, pérdida y revocación sin rebajar el umbral de
  manera silenciosa.
- [ ] `MESH-06` Simular particiones, testigos lentos y respuestas contradictorias.

### Pruebas de aceptación

- [ ] Firmas duplicadas del mismo testigo cuentan una sola vez.
- [ ] Mezclar firmas de desafíos distintos nunca alcanza el umbral.
- [ ] Revocar un testigo invalida respuestas posteriores y pendientes.
- [ ] La indisponibilidad se resuelve según una política documentada, no mediante
  aceptación automática.

## 8. `pam_private_presence`: presencia próxima no rastreable

### Idea

Demostrar que un dispositivo autorizado está físicamente próximo usando
identificadores rotatorios y un desafío fresco, sin emitir una identidad fija
que permita rastrearlo. La proximidad por radio no demuestra por sí sola quién
es el usuario y los ataques de relay son el problema central.

### Desarrollo

- [ ] `PRES-01` Definir el atacante de relay y la precisión temporal necesaria
  antes de seleccionar BLE, NFC, UWB u otro transporte.
- [ ] `PRES-02` Diseñar credenciales rotatorias no enlazables por observadores.
- [ ] `PRES-03` Ejecutar challenge-response con claves protegidas por el dispositivo.
- [ ] `PRES-04` Combinar presencia con `pam_intentseal` u otro factor humano.
- [ ] `PRES-05` No almacenar RSSI ni telemetría de localización salvo que sea
  imprescindible y esté documentado.
- [ ] `PRES-06` Medir falsos rechazos y aceptación mediante relay en un laboratorio.

### Pruebas de aceptación

- [ ] Capturar y retransmitir una sesión anterior no autentica.
- [ ] Observadores pasivos no obtienen un identificador estable.
- [ ] Una pérdida de radio o batería produce el fallo documentado.
- [ ] La presencia nunca concede acceso sin el factor adicional configurado.

## 9. `pam_decay`: confianza con caducidad progresiva

### Idea

La autenticación inicial crea una capacidad corta que un agente de sesión puede
renovar mientras existan pruebas recientes de presencia. PAM inicia y cierra la
sesión; un daemon externo gestiona la continuidad. No se debe presentar como una
función que un módulo PAM aislado pueda realizar por sí solo.

### Desarrollo

- [ ] `DECAY-01` Definir qué privilegio caduca y qué significa bloquear o degradar
  una sesión ya iniciada.
- [ ] `DECAY-02` Emitir capacidades renovables de alcance mínimo.
- [ ] `DECAY-03` Separar señales de comodidad de factores de seguridad reales.
- [ ] `DECAY-04` Implementar renovación sin convertir el agente en una autoridad
  capaz de emitir capacidades nuevas.
- [ ] `DECAY-05` Tratar suspensión, hibernación, cambio de usuario y desconexión.
- [ ] `DECAY-06` Diseñar UX para advertir antes de degradar o bloquear.

### Pruebas de aceptación

- [ ] Matar o falsificar el agente no extiende la confianza.
- [ ] Suspender más allá del límite invalida la renovación prevista.
- [ ] Una sesión no puede renovar capacidades de otra.
- [ ] El bloqueo no destruye trabajo ni crea una vía de bypass documentada como
  «recuperación».

## 10. `pam_policy_shards`: autorización reconstruida por condiciones

### Idea

Distribuir la capacidad de autorizar entre varios componentes: persona, TPM,
dispositivo externo y política contextual. La combinación solo reconstruye una
clave o capacidad efímera. Horario o ubicación no aportan secreto por sí solos y
no deben contarse como factores independientes.

### Desarrollo

- [ ] `SHARD-01` Definir qué participantes poseen secreto criptográfico y cuáles
  son únicamente condiciones de política.
- [ ] `SHARD-02` Seleccionar un esquema de umbral revisado públicamente; no diseñar
  criptografía propia.
- [ ] `SHARD-03` Proteger cada fragmento en reposo y durante reconstrucción.
- [ ] `SHARD-04` Reconstruir solo dentro de memoria controlada y destruir el
  resultado inmediatamente después de emitir la capacidad.
- [ ] `SHARD-05` Diseñar rotación de un participante sin reconstruir de forma
  innecesaria el secreto completo.
- [ ] `SHARD-06` Modelar participantes maliciosos, ausentes y coludidos.

### Pruebas de aceptación

- [ ] Menos del umbral no revela ni permite verificar el secreto reconstruido.
- [ ] Fragmentos de épocas o políticas diferentes no se pueden combinar.
- [ ] Rotación, revocación y recuperación conservan el umbral previsto.
- [ ] Sanitizers y Valgrind no encuentran copias persistentes durante las pruebas.

## Fases de ejecución

### Fase 0 — Especificación y harness

- [ ] Completar `CORE-01..10`.
- [ ] Elegir algoritmos y formatos existentes con implementaciones mantenidas.
- [ ] Añadir fuzzing del protocolo y pruebas de propiedades anti-replay.
- [ ] Criterio de salida: todas las decisiones críticas están documentadas y el
  harness reproduce fallos de broker, almacenamiento y reloj.

### Fase 1 — Firma de intención

- [ ] Completar `INTENT-01..08` con un firmante simulado.
- [ ] Revisar el modelo de amenazas y el código antes de usar hardware real.
- [ ] Criterio de salida: ninguna aprobación puede cambiar de usuario, host,
  servicio, acción o sesión, ni consumirse dos veces.

### Fase 2 — Capacidades y atestación

- [ ] Completar `CAP-01..06`.
- [ ] Completar `BOOT-01..06` primero con TPM simulado.
- [ ] Criterio de salida: las capacidades tienen alcance mínimo, consumo atómico,
  revocación y recuperación probadas.

### Fase 3 — Políticas avanzadas

- [ ] Implementar `pam_trust_budget` y después `pam_causal_chain`.
- [ ] Ejecutar pruebas de estrés, concurrencia y fallos inducidos.
- [ ] Criterio de salida: un fallo nunca amplía privilegios ni duplica capacidad.

### Fase 4 — Factores distribuidos y continuidad

- [ ] Evaluar por separado `pam_witness_mesh`, `pam_private_presence` y
  `pam_decay`; no combinarlos antes de medirlos individualmente.
- [ ] Criterio de salida: están cuantificados los falsos rechazos, los límites de
  relay y el comportamiento sin conectividad.

### Fase 5 — Recuperación y composición

- [ ] Completar `pam_delayed_recovery` antes de cualquier piloto real.
- [ ] Evaluar `pam_policy_shards` únicamente con una construcción criptográfica
  existente y revisada.
- [ ] Criterio de salida: pérdida, revocación, actualización y rollback se han
  ensayado sin acceso permanente ni puertas traseras.

## Checklist obligatoria por pull request

- [ ] El cambio pertenece a una sola fase y tiene alcance limitado.
- [ ] El modelo de amenazas indica la propiedad nueva y sus exclusiones.
- [ ] Los formatos persistentes y de red están versionados y acotados.
- [ ] No aparecen secretos o capacidades en logs, argumentos o entorno.
- [ ] Hay pruebas positivas, negativas, concurrencia y fallos inducidos.
- [ ] Compila sin warnings con GCC y Clang.
- [ ] Pasan análisis estático, sanitizers y Valgrind cuando sean aplicables.
- [ ] Pasa `make -C tests verify` completo.
- [ ] README, configuración, desinstalación y recuperación están actualizados.
- [ ] Un revisor distinto confirma que el cambio no rebaja silenciosamente una
  política existente.

## Fuera de alcance inicialmente

- Reconocimiento facial, huella o voz propios: deben delegarse en componentes
  mantenidos y no almacenar plantillas biométricas en este laboratorio.
- Clasificadores de comportamiento como único factor.
- Criptografía casera o formatos binarios no especificados.
- Autorizaciones basadas exclusivamente en hora, ubicación, dirección IP o RSSI.
- Instalación automática en el stack PAM principal.
- Cualquier mecanismo que conceda acceso cuando el broker no responde.

## Referencias de partida

- [Linux-PAM](https://github.com/linux-pam/linux-pam)
- [pam-u2f](https://developers.yubico.com/pam-u2f/)
- [fprintd](https://fprint.freedesktop.org/)
- [OCRA, RFC 6287](https://datatracker.ietf.org/doc/html/rfc6287)
- [TPM2 Remote Attestation](https://tpm2-software.github.io/tpm2-tss/getting-started/2019/12/18/Remote-Attestation.html)
