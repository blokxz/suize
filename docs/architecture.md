# Arquitectura de Suize

Suize está organizado en **capas con dependencias en un solo sentido**. La regla es simple: una
capa solo puede importar a las que están debajo. Así la lógica (parsear XML, construir comandos,
correlacionar) se prueba sin terminal, sin Nmap y sin journald, y la interfaz se puede cambiar
sin tocar esa lógica.

```
                 ┌──────────────────────────────────────────┐
                 │  cli.py        (orquesta todo)           │
                 └───────┬──────────────┬───────────────────┘
                         │              │
          ┌──────────────▼───┐   ┌──────▼──────────────┐
          │  ui/             │   │  config/            │
          │  menús y tablas  ├──►│  TOML + env         │
          └──────┬───────────┘   └─────────────────────┘
                 │
          ┌──────▼───────────────────────────────────────┐
          │  core/   ejecutar, parsear, correlacionar    │   (nunca importa ui/)
          └──────┬───────────────────────────────────────┘
                 │
          ┌──────▼───────────────────────────────────────┐
          │  utils/  shell, validación, tiempo, permisos │
          └──────┬───────────────────────────────────────┘
                 │
          ┌──────▼───────────────────────────────────────┐
          │  models/ dataclasses (no importa nada)       │
          └──────────────────────────────────────────────┘
```

| Capa      | Puede importar                        | Nunca                         |
|-----------|---------------------------------------|-------------------------------|
| `models/` | solo stdlib                           | nada del proyecto             |
| `utils/`  | `models/`, stdlib                     | `core/`, `ui/`, `config/`     |
| `core/`   | `models/`, `utils/`, stdlib           | `ui/`, `config/`              |
| `ui/`     | `core/`, `models/`, `utils/`, `config/` | —                           |
| `cli.py`  | todo                                  | —                             |

`config/` es una hoja: solo usa stdlib (`tomllib`) y lo consumen `ui/` y `cli.py`. `core/`
recibe los valores que necesita (timeouts, líneas, perfil) como **argumentos**, nunca lee la
configuración por su cuenta.

## Estructura

```
suize/
├── pyproject.toml            # metadatos, entry point `suize`, config de pytest/ruff/mypy
├── requirements.txt          # questionary, rich
├── .env.example              # variables SUIZE_*
├── src/suize/
│   ├── __init__.py           # __version__
│   ├── __main__.py           # python -m suize
│   ├── cli.py                # argparse, subcomandos, códigos de salida
│   ├── config/
│   │   ├── default.toml      # valores por defecto documentados
│   │   └── settings.py       # Settings, load_settings() (TOML → usuario → env)
│   ├── models/
│   │   ├── host.py           # Host, Port
│   │   └── log_entry.py      # LogEntry, LogSummary, PRIORITY_NAMES
│   ├── utils/
│   │   ├── shell.py          # ÚNICO punto que llama a subprocess (run y stream)
│   │   ├── deps.py           # ¿están nmap/journalctl/systemctl? ¿corre systemd?
│   │   ├── permissions.py    # root, grupos del journal, avisos
│   │   ├── validators.py     # objetivos, fechas, prioridades, unidades
│   │   └── time_filter.py    # TimeRange, presets, --since/--until
│   ├── core/
│   │   ├── nmap_runner.py    # construye y lanza `nmap -sV -oX`
│   │   ├── nmap_parser.py    # XML → list[Host]
│   │   ├── journal_reader.py # construye y lanza `journalctl --output=json`
│   │   ├── journal_parser.py # JSON → list[LogEntry], LogSummary
│   │   └── correlator.py     # puertos → unidades systemd
│   └── ui/
│       ├── theme.py          # colores por prioridad, iconos, consola
│       ├── pager.py          # envía a less las salidas que no caben en pantalla
│       ├── prompts.py        # preguntas questionary reutilizables
│       ├── render_nmap.py    # tablas de puertos y de correlación
│       ├── render_logs.py    # panel de resumen y tabla de logs
│       ├── export.py         # serialización a JSON y CSV
│       └── menus.py          # menú principal y flujos
├── tests/
│   ├── conftest.py           # FakeSystem: simula nmap/journalctl/systemctl
│   ├── fixtures/             # nmap_scan.xml, journal_sample.json reales
│   ├── unit/                 # parsers, time_filter, validators, correlator
│   └── integration/          # CLI de punta a punta con monkeypatch
├── docs/
└── scripts/                  # run.sh, lint.sh
```

## Flujo de datos

### Escaneo

```
target (usuario) ──► validators.validate_target ──► nmap_runner.build_command
                                                        │  ["nmap",("-6"),"-sV","-oX",<tmp>,...,target]
                                                        ▼
                                                 shell.run (which + timeout)
                                                        │  XML en un directorio temporal
                                                        ▼
                                             nmap_parser.parse_nmap_xml
                                                        │  list[Host]
                                                        ▼
                                  render_nmap.render_hosts   ó   JSON (--json)
```

### Logs

```
filtros ──► validators / time_filter ──► JournalQuery ──► journal_reader.build_command
                                                             │  ["journalctl","--output=json",
                                                             │   "--no-pager","--quiet","-u",...]
                                                             ▼
                                                        shell.run
                                                             │  una línea JSON por entrada
                                                             ▼
                                               journal_parser.parse_journal_json
                                                             │  list[LogEntry]
                                                             ▼
                                   LogSummary.from_entries ──► render_logs (panel + tabla)
```

### Correlación

```
list[Host] ──► correlator.candidate_units(port)       22 → ssh, sshd · "http" → nginx, apache2...
                     │
systemctl list-units ─► correlator.parse_unit_list    {"ssh", "nginx", "cron", ...}
                     │
                     ▼
            correlator.correlate  ──► list[Correlation] (candidatos + unidades existentes)
                     │
                     ▼
            units_to_query ──► ["nginx.service", "ssh.service"] ──► JournalQuery(units=...)
```

Los candidatos salen de dos tablas: `PORT_TO_UNITS` (por número de puerto) y `SERVICE_TO_UNITS`
(por el nombre que detecta Nmap, para servicios en puertos no estándar como SSH en el 2222).
Solo se consultan las unidades que **existen** en `systemctl list-units --all`, así nunca se
le pide a journalctl una unidad inventada. También se aceptan instancias de plantilla:
`postgresql` coincide con `postgresql@16-main`.

La correlación siempre usa el journal **local**. Si el objetivo no es loopback, Suize avisa que
el resultado es orientativo.

## Decisiones de diseño

**Un único punto de contacto con el sistema (`utils/shell.py`).** Toda ejecución externa pasa
por `shell.run()`, que:

- verifica el binario con `shutil.which` antes de lanzarlo y, si falta, lanza `CommandError`
  con un mensaje claro en vez de un `FileNotFoundError`;
- nunca usa `shell=True`: los argumentos van en una lista, así que un objetivo como
  `127.0.0.1; rm -rf ~` no se interpreta;
- aplica siempre un `timeout` y convierte `TimeoutExpired` en `CommandError`;
- acepta `ok_codes` para programas donde un código distinto de 0 no es error (journalctl con
  `--grep` devuelve 1 cuando no hay coincidencias).

Como es el único punto, a los tests les basta con reemplazar `subprocess.run` y `shutil.which`
dentro de ese módulo (con `monkeypatch`) para que todo el resto del código corra de verdad.

**Defensa contra inyección de argumentos.** `validate_target` rechaza objetivos que empiecen por
`-` (Nmap los tomaría como opciones, p. ej. `-oN /etc/passwd`) y solo acepta IPs, redes CIDR,
rangos de Nmap (`192.168.1.1-50`) y hostnames válidos. `validate_unit` hace lo mismo con los
nombres de unidad.

**IPv6 automático.** Nmap rechaza los objetivos IPv6 si no se le pasa `-6` (los ignora y
escanea cero hosts), así que Suize añade la opción por su cuenta. La decisión está partida en
dos para no mezclar lógica pura con acceso a la red: `nmap_runner.needs_ipv6` resuelve el caso
—consultando el DNS solo si el objetivo es un nombre de host, nunca para una IP, red o rango—
y `build_command` se limita a recibir el resultado como un booleano. Por eso construir el
comando sigue siendo comprobable sin red, y los tests del resolutor inyectan un doble en lugar
de depender del DNS. Un nombre con registros A y AAAA no activa `-6`: Nmap usa IPv4 y funciona;
y si el nombre no resuelve, quien informa del error es Nmap con su propio mensaje.

**Opciones globales en dos posiciones.** `--config`, `--no-color` y `--no-pager` se registran
en el parser principal y se repiten dentro de cada subcomando con `default=SUPPRESS`. Sin ese
`SUPPRESS`, argparse aplicaría el valor por defecto del subparser al terminar de analizar y
borraría lo que el usuario escribió antes del subcomando, que es el error clásico de este
patrón; con él, la opción solo aparece en el resultado si se indicó de verdad.

**Un proceso que no termina.** `shell.run` está construido sobre `subprocess.run`: espera a que
el programa acabe y le aplica un tiempo máximo. `journalctl --follow` no acaba nunca, así que
el seguimiento necesitó una segunda puerta, `shell.stream`, que entrega las líneas según llegan
y no impone timeout —el final lo decide quien consume el generador, con un `break` o un Ctrl+C—.
Lo delicado no es leer, sino limpiar: al salir del bucle por cualquier vía, un bloque `finally`
termina el proceso hijo y, si no atiende al SIGTERM, lo mata. Sin eso, cortar un `suize logs -f
| head` dejaría un journalctl huérfano escribiendo a una tubería que ya nadie lee. El hijo se
lanza además en su propia sesión, para que el Ctrl+C de la terminal llegue a Suize y sea este
quien decida cómo parar, en vez de que el hijo muera a mitad de una línea.

**Paginación decidida a posteriori.** `ui/pager.py` no puede saber cuánto ocupará una salida
antes de generarla, así que captura el bloque en memoria, cuenta sus líneas y solo entonces
decide: si cabe en la pantalla lo reescribe tal cual (sin volver a pasarlo por `print`, que
reinterpretaría los corchetes de un mensaje de log como marcado), y si no lo manda al
paginador. El envoltorio se aplica alrededor de las llamadas de renderizado, nunca alrededor de
la lógica que las precede: capturar una pregunta interactiva o un indicador de progreso dejaría
al usuario ante una pantalla en blanco. Por eso en los flujos del menú se paginan las secciones
por separado, mientras que en los subcomandos, donde no hay preguntas de por medio, todo el
informe cabe en un único paginador.

**Los parsers no imprimen.** `nmap_parser` y `journal_parser` reciben texto y devuelven
dataclasses o lanzan una excepción propia (`NmapParseError`, `JournalParseError`). No saben que
existe una terminal, por eso se reutilizan tal cual para `--json`.

**Parser del journal tolerante.** journald guarda algunos campos como arrays de bytes (mensajes
no UTF-8) o como listas (campos repetidos). `_as_text` los normaliza. El timestamp se toma de
`__REALTIME_TIMESTAMP` (microsegundos → `datetime.fromtimestamp(ts / 1_000_000)`) y la unidad de
`_SYSTEMD_UNIT`, con `SYSLOG_IDENTIFIER` como alternativa (mensajes del kernel, scripts con
`logger`). Una línea corrupta se descarta sin invalidar el resto (con `strict=True`, falla).

**Rangos temporales como objetos.** `TimeRange` resuelve los presets a fechas absolutas en el
momento de la consulta (`since`/`until` como `datetime`) y los traduce a `--since=`/`--until=`.
Resolverlos en Python —en lugar de pasarle `"1 hour ago"` a journalctl— permite mostrar el rango
exacto en el resumen y probarlo con un `now` fijo.

**Arranque tolerante.** `deps.check_dependencies()` corre al inicio y nunca aborta: el menú
deshabilita las opciones que no se pueden usar (y dice por qué), y los subcomandos devuelven el
código 3 solo si les falta algo que realmente necesitan.

**Sin efectos al importar.** Ningún módulo lee configuración, consulta el sistema ni crea
consolas al importarse; todo ocurre dentro de `main()`. Esto hace que los tests sean
predecibles y que `import suize` sea barato.

**Configuración en capas.** `default.toml` viaja dentro del paquete (se lee con
`importlib.resources`), el usuario solo escribe las claves que cambia y las variables `SUIZE_*`
tienen la última palabra. Los tipos se validan al cargar y un error se reporta con la clave
exacta (código de salida 2).

## Tests

- **Unitarios** (`tests/unit/`): parsers contra fixtures reales, `time_filter` con un `now` fijo,
  validadores (incluidos intentos de inyección) y correlador.
- **Integración** (`tests/integration/`): ejecutan `cli.main([...])` completo. El fixture
  `FakeSystem` de `conftest.py` reemplaza `subprocess.run` y `shutil.which` dentro de
  `utils/shell.py`, y responde con los fixtures según el comando recibido. Permite probar también dependencias faltantes, timeouts,
  errores de systemd y el menú (con respuestas de questionary simuladas).

Ningún test necesita nmap, journalctl, systemd ni root.
