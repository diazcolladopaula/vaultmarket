# vaultmarket

[English](README.md) · [Español](README.es.md)

Un mercado de objetos virtuales para la terminal (piensa en skins de cuchillos
de un videojuego) donde todo el estado (cuentas, carteras, inventarios, ofertas,
precios e historial de transacciones) vive en un único fichero cifrado con una
clave derivada de una frase de paso.

Es un proyecto de aprendizaje sobre cómo aplicar criptografía en una aplicación
pequeña pero realista: derivación de claves, cifrado autenticado, hash de
contraseñas y un registro a prueba de manipulaciones. No está pensado para
sostener un mercado real; en [docs/DESIGN.md](docs/DESIGN.md) (en inglés) se explica
con precisión qué protege y qué no.

## Qué hace

- Crear cuentas e iniciar sesión. Las contraseñas se guardan con Argon2id; tras
  cinco intentos fallidos la cuenta se bloquea con una espera creciente.
- Tener una cartera de créditos simulados: añadir fondos y retirarlos.
- Comprar en una tienda que ofrece siete objetos aleatorios de un catálogo de
  240 modelos (8 tipos, 6 materiales, 5 niveles de desgaste).
- Revender objetos a otros jugadores. El mercado cobra una comisión del 5 % y el
  precio de referencia de cada modelo se acerca a lo que realmente se paga, con
  un límite a cuánto puede moverlo una sola operación.
- Cada usuario recibe un par de claves Ed25519 al registrarse. Los depósitos, las
  compras y las ofertas se firman, y una compra entre jugadores queda ligada a la
  oferta firmada por el vendedor.
- Ejecutar `vaultmarket audit` para comprobar el registro de transacciones:
  cadena de hashes, firmas, ofertas y que cada saldo se puede reproducir a partir de él.

## Instalación y uso

Necesita Python 3.10 o superior.

```bash
git clone https://github.com/diazcolladopaula/vaultmarket.git
cd vaultmarket
pip install .
vaultmarket
```

La primera vez pide una frase de paso para el vault (12 caracteres o más) y lo
crea en `~/.vaultmarket/`. Con `--data-dir` o `VAULTMARKET_HOME` se puede cambiar
la ubicación. Crea dos cuentas para probar el mercado entre jugadores.

La interfaz está en inglés. Ejemplo de la comprobación de integridad:

```text
$ vaultmarket audit
Audit OK: 6 ledger entries (4 signed); chain, signatures and balances are consistent.
```

## Cómo se protegen los datos

- **Clave**: se deriva de tu frase de paso con Argon2id (64 MiB, 3 pasadas,
  4 lanes) y una sal aleatoria. No se guarda ningún fichero de clave.
- **Cifrado**: AES-256-GCM. La cabecera del fichero (versión, parámetros del KDF,
  sal) se autentica como datos asociados y cada guardado usa un nonce aleatorio nuevo.
- **Escritura**: un solo fichero, escrito a un temporal y renombrado, de modo
  que un fallo no lo deja a medias. Permisos `600`.
- **Contraseñas**: Argon2id con sal por usuario, en formato PHC estándar. Con
  usuarios inexistentes se hace el mismo trabajo de hash, así que el tiempo de respuesta no revela cuáles existen.
- **Firmas**: la clave privada Ed25519 de cada usuario se guarda en el vault cifrada
  con una clave derivada de *su propia* contraseña, así que conocer la frase de paso
  del vault no basta para firmar en su nombre.
- **Dinero**: siempre en céntimos enteros; valores como `nan`, `inf` o `1e9` se rechazan.

El razonamiento, el formato del fichero y las limitaciones conocidas están en
[docs/DESIGN.md](docs/DESIGN.md).

## Desarrollo

```bash
pip install -e ".[dev]"
pytest          # 112 tests
ruff check . && ruff format --check .
```

Los tests incluyen un vector de prueba oficial de Argon2id (RFC 9106),
manipulación de la cabecera y del texto cifrado, entradas del registro falsificadas o reatribuidas, el bloqueo de cuentas con un reloj
simulado y sesiones completas a través de los menús reales.

## Origen

Nació como una práctica universitaria en pareja de una asignatura de criptografía
aplicada: un mercado de objetos por línea de comandos con ficheros JSON cifrados.
Este repositorio es un rediseño y reescritura de esa idea: otro esquema de
almacenamiento y gestión de claves, código y tests nuevos, y correcciones de los
problemas que encontré en el original. DESIGN.md recoge qué cambió y por qué.

## Licencia

MIT, ver [LICENSE](LICENSE).
