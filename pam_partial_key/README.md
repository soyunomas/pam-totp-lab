# PAM Partial Key

Módulo PAM que solicita tres posiciones aleatorias de una clave maestra. El
servidor guarda un hash SHA-256 independiente para cada posición, combinado con
una sal aleatoria, en `~/.partial_key`.

## Compilación e instalación

En Debian o Ubuntu:

```bash
make deps
make build
sudo make install
```

Cada usuario debe generar su fichero ejecutando **sin `sudo`**:

```bash
pk_manager
```

El gestor exige una clave de 8 a 64 caracteres. Genera el contenido completo en
memoria y lo instala mediante un fichero temporal privado y un `rename` atómico.
El resultado pertenece al usuario que ejecuta el programa y tiene permisos
`0600`.

Si el `rename` ya ha reemplazado la clave pero el sistema no puede confirmar la
durabilidad del directorio mediante `fsync`, el gestor termina con error y avisa
explícitamente de que la clave anterior puede haber sido sustituida. En ese
caso, verifica `~/.partial_key` antes de cerrar sesiones activas o repetir la
operación.

## Configuración PAM

Ejemplo para `/etc/pam.d/sshd`:

```pam
auth required pam_partial_key.so
```

Conserva una sesión administrativa abierta mientras pruebas cualquier cambio en
PAM. La ausencia, corrupción, tamaño excesivo, propietario incorrecto, permisos
inseguros o symlinks en `.partial_key` provocan un rechazo.

## Modelo de seguridad y límites

Este mecanismo reduce la cantidad de la clave que se introduce en cada intento,
pero no equivale a MFA ni evita por sí solo el phishing. Un observador que
capture suficientes desafíos y respuestas puede reconstruir posiciones de la
clave; además, la repetición aleatoria de las mismas tres posiciones permite
reutilizar una respuesta observada. Debe combinarse con rate limiting, una pila
PAM adecuada y, para accesos de alto riesgo, un segundo factor resistente al
phishing.

El fichero contiene hashes posicionales, no la clave en texto claro. Aun así,
una clave corta o predecible permite ataques offline por posición si el fichero
se filtra. Usa una clave larga y aleatoria y protege también las copias de
seguridad del directorio personal.

## Formato del fichero

```text
LONGITUD|SAL_HEX|HASH_POSICION_0|HASH_POSICION_1|...
```

El parser acepta entre 8 y 64 posiciones, una sal de 16 bytes y hashes SHA-256
de 32 bytes codificados en hexadecimal.
