# Suize

[![CI](https://github.com/TU-USUARIO/suize/actions/workflows/ci.yml/badge.svg)](https://github.com/TU-USUARIO/suize/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue)
![Plataforma](https://img.shields.io/badge/plataforma-Linux-lightgrey)
[![Licencia](https://img.shields.io/badge/licencia-MIT-green)](LICENSE)

Herramienta de línea de comandos para Linux que combina **escaneos de red con Nmap** y
**consulta de logs de systemd con journalctl**, y los **correlaciona**: detecta qué servicios
escuchan en un host y muestra directamente los logs de las unidades systemd que los atienden.

Diagnosticar un servicio suele requerir dos pasos separados: comprobar qué puertos están
abiertos y después buscar los logs del proceso correspondiente. Suize une ambos en un solo
flujo, con un menú interactivo para el uso diario y subcomandos con salida JSON para scripts.

```
$ suize scan 127.0.0.1 --correlate --since 1h

127.0.0.1  localhost
╭────────┬───────────┬────────┬──────────┬─────────────────────────────────────────────╮
│ Puerto │ Protocolo │ Estado │ Servicio │ Versión                                     │
├────────┼───────────┼────────┼──────────┼─────────────────────────────────────────────┤
│     22 │ tcp       │ open   │ ssh      │ OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu    │
│        │           │        │          │ Linux; protocol 2.0)                        │
│     80 │ tcp       │ open   │ http     │ nginx 1.24.0 (Ubuntu)                       │
│   3306 │ tcp       │ open   │ mysql    │ MySQL 8.0.36-0ubuntu0.24.04.1               │
╰────────┴───────────┴────────┴──────────┴─────────────────────────────────────────────╯

╭───────────┬──────────┬──────────┬───────────────────────┬──────────────────────────╮
│ Host      │   Puerto │ Servicio │ Candidatos            │ Unidades en este sistema │
├───────────┼──────────┼──────────┼───────────────────────┼──────────────────────────┤
│ 127.0.0.1 │   22/tcp │ ssh      │ ssh, sshd             │ ssh                      │
│ 127.0.0.1 │   80/tcp │ http     │ nginx, apache2, httpd │ nginx                    │
│ 127.0.0.1 │ 3306/tcp │ mysql    │ mysql, mariadb        │ — ninguna —              │
╰───────────┴──────────┴──────────┴───────────────────────┴──────────────────────────╯

  Fecha y hora          Prioridad   Unidad          Mensaje
 ──────────────────────────────────────────────────────────────────────────────────────
  2026-01-15 10:30:30    NOTICE     ssh.service     Failed password for invalid user
                                                    admin from 203.0.113.45 port 51234
                                                    ssh2
  2026-01-15 10:31:00    ERR        nginx.service   2026/01/15 10:31:00 [emerg]
                                                    1201#1201: bind() to 0.0.0.0:80
                                                    failed (98: Address already in
                                                    use)
```

*Extracto de la salida. En la terminal, cada prioridad de log se muestra con su propio color.*

## Contenido

- [Características](#características)
- [Requisitos](#requisitos)
- [Instalación](#instalación)
- [Autocompletado](#autocompletado)
- [Uso rápido](#uso-rápido)
- [Menú interactivo](#menú-interactivo)
- [Subcomandos](#subcomandos)
- [Correlación de puertos y servicios](#correlación-de-puertos-y-servicios)
- [Salida JSON](#salida-json)
- [Configuración](#configuración)
- [Permisos](#permisos)
- [Solución de problemas](#solución-de-problemas)
- [Limitaciones conocidas](#limitaciones-conocidas)
- [Desarrollo](#desarrollo)
- [Uso responsable](#uso-responsable)
- [Licencia](#licencia)

## Características

- **Dos interfaces sobre la misma lógica**: un menú interactivo (sin argumentos) y los
  subcomandos `scan` y `logs` para scripts, cron o CI.
- **Escaneo con detección de versiones** (`nmap -sV`), con tres perfiles de alcance y soporte
  para IPv4, IPv6, redes CIDR, rangos y nombres de host.
- **Logs de journalctl con filtros combinables** por unidad, prioridad, rango temporal y
  expresión regular, más un resumen previo con el total de entradas, el conteo por prioridad
  y las unidades más activas.
- **Rangos temporales legibles**: `15m`, `1h`, `today`, `yesterday` o fechas exactas,
  resueltos a fechas absolutas y mostrados en el resumen.
- **Correlación puerto-servicio**: asocia cada puerto abierto con sus unidades systemd,
  verificando que existan en el sistema antes de consultar sus logs.
- **Salida JSON** en ambos subcomandos, pensada para procesarse con `jq`.
- **Arranque tolerante**: si falta `nmap` o `journalctl`, se desactiva solo la función que lo
  necesita y se indica cómo instalarlo.
- **Seguro por diseño**: nunca invoca una shell, valida los objetivos contra la inyección de
  opciones en Nmap y no usa `sudo` por su cuenta.

## Requisitos

| Componente       | Versión / detalle                          | Para qué se usa                        |
|------------------|--------------------------------------------|----------------------------------------|
| Linux con systemd | Ubuntu, Debian, Linux Mint, Fedora, Arch... | Logs y correlación                    |
| Python           | 3.11 o superior (probado en 3.11 a 3.14)   | Ejecutar Suize                         |
| Nmap             | Cualquier versión reciente                 | Escaneos                               |
| journalctl       | Incluido con systemd                       | Lectura de logs                        |
| systemctl        | Incluido con systemd                       | Listar servicios para la correlación   |

Dependencias de Python: únicamente [`rich`](https://github.com/Textualize/rich) (tablas y
colores) y [`questionary`](https://github.com/tmbo/questionary) (menús). Se instalan solas.

**Windows**: funciona dentro de WSL2 con systemd activado (ver
[Solución de problemas](#systemd-no-está-en-ejecución-wsl-o-contenedores)). **Contenedores
Docker**: el escaneo funciona, pero normalmente no hay systemd y los logs estarán vacíos.

## Instalación

### 1. Paquetes del sistema

```bash
# Debian, Ubuntu, Linux Mint
sudo apt update && sudo apt install nmap python3-venv git

# Fedora
sudo dnf install nmap python3 git

# Arch Linux
sudo pacman -S nmap python git
```

Comprueba la versión de Python:

```bash
python3 --version
```

Si es inferior a 3.11 (por ejemplo, Ubuntu 22.04 o Linux Mint 21 traen 3.10), instala una
versión compatible en paralelo, sin reemplazar la del sistema, y usa `python3.11` en lugar
de `python3` en el paso siguiente:

```bash
sudo apt install python3.11 python3.11-venv
```

### 2. Descargar e instalar

```bash
git clone https://github.com/TU-USUARIO/suize.git
cd suize
python3 -m venv .venv
.venv/bin/pip install -e .
```

Se instala dentro de un entorno virtual (`.venv/`) porque las distribuciones actuales
bloquean `pip install` sobre el Python del sistema (error `externally-managed-environment`,
[PEP 668](https://peps.python.org/pep-0668/)). La opción `-e` (modo editable) hace que
cualquier cambio en el código, o un `git pull`, se aplique sin reinstalar.

### 3. Dejar el comando disponible en cualquier terminal

```bash
mkdir -p ~/.local/bin
ln -s "$PWD/.venv/bin/suize" ~/.local/bin/suize
```

Cierra la sesión y vuelve a entrar: la mayoría de las distribuciones añaden `~/.local/bin`
al `PATH` al iniciar sesión, pero solo si la carpeta ya existe. El ejecutable del entorno
virtual usa siempre el Python de ese entorno, así que no hace falta activarlo.

Verifica la instalación:

```bash
which suize        # /home/<usuario>/.local/bin/suize
suize --version    # suize 0.1.0
```

### Alternativa: instalación con pipx

Si solo vas a usar la herramienta (sin modificar el código),
[pipx](https://pipx.pypa.io/) crea el entorno aislado y el acceso directo en un paso:

```bash
sudo apt install pipx && pipx ensurepath    # cierra la sesión y vuelve a entrar
pipx install git+https://github.com/TU-USUARIO/suize.git
```

### Actualizar y desinstalar

| Método de instalación | Actualizar                                   | Desinstalar                              |
|-----------------------|----------------------------------------------|------------------------------------------|
| Entorno virtual       | `git pull` en la carpeta del proyecto        | `rm ~/.local/bin/suize` y borrar la carpeta |
| pipx                  | `pipx install --force git+https://github.com/TU-USUARIO/suize.git` | `pipx uninstall suize` |

Si una actualización cambia las dependencias (`pyproject.toml`), repite
`.venv/bin/pip install -e .` después del `git pull`.

## Autocompletado

El repositorio incluye completados para zsh y bash en `completions/`. No hacen falta
dependencias. Además de subcomandos y opciones, completan los valores de `--profile`,
`--format`, `-p` y `--since`, y las unidades systemd **reales de tu equipo** en `-u`:

```
$ suize logs -u ngi<Tab>
$ suize logs -u nginx.service
```

### zsh

```bash
mkdir -p ~/.local/share/zsh/site-functions
cp completions/_suize ~/.local/share/zsh/site-functions/_suize
```

Si el directorio no está en tu `$fpath`, añade esta línea a `~/.zshrc` **antes** de la llamada
a `compinit`:

```zsh
fpath=(~/.local/share/zsh/site-functions $fpath)
```

Abre una terminal nueva. Si el completado no aparece, borra la caché con
`rm -f ~/.zcompdump*` y vuelve a abrirla.

### bash

```bash
sudo cp completions/suize.bash /etc/bash_completion.d/suize
```

O sin privilegios, añadiendo a `~/.bashrc`:

```bash
source ~/suize/completions/suize.bash
```

Requiere el paquete `bash-completion`, que viene instalado en Ubuntu y Linux Mint.

## Uso rápido

```bash
suize                                    # menú interactivo
suize scan 192.168.1.1                   # puertos y versiones de un equipo
suize scan 127.0.0.1 --correlate         # escaneo + logs de los servicios detectados
suize logs -p err --since today          # errores de hoy
suize logs -u ssh --since 1h             # logs de SSH de la última hora
suize --help                             # ayuda general
suize logs --help                        # ayuda de un subcomando
```

## Menú interactivo

Se abre al ejecutar `suize` sin argumentos. Requiere una terminal interactiva; en pipes,
cron o CI hay que usar los subcomandos.

| Opción                                 | Qué pregunta                                                         | Resultado                                               |
|----------------------------------------|----------------------------------------------------------------------|---------------------------------------------------------|
| Escanear host con Nmap                 | Objetivo y perfil de escaneo                                         | Tabla de puertos; si hay puertos abiertos, ofrece ver sus logs |
| Analizar logs del sistema              | Rango temporal, prioridad, unidad, expresión regular y cantidad máxima | Resumen y tabla de logs                               |
| Escanear + ver logs correlacionados    | Objetivo, perfil y rango temporal                                    | Puertos, tabla de correlación y logs de esos servicios  |
| Salir                                  | —                                                                    | —                                                       |

Cada pregunta tiene un valor por defecto: pulsar Enter repetidamente da un resultado
razonable (por ejemplo, todos los logs de la última hora).

| Tecla            | Acción                                                           |
|------------------|------------------------------------------------------------------|
| Flechas y Enter  | Elegir una opción                                                |
| Tab              | Autocompletar el nombre de la unidad systemd                     |
| Ctrl+C           | Cancelar la operación en curso y volver al menú (en el menú principal, salir) |

Las respuestas se validan mientras se escriben: una fecha mal formada o un objetivo inválido
no permiten continuar.

## Subcomandos

### `suize scan`

```
suize scan [TARGET] [--profile {fast,standard,full}] [--correlate] [--since RANGO]
           [--save-xml ARCHIVO] [--json] [-q]
```

| Opción              | Descripción                                                                       |
|---------------------|-----------------------------------------------------------------------------------|
| `TARGET`            | Objetivo del escaneo. Si se omite, se usa `scan.default_target` de la configuración (por defecto `127.0.0.1`). |
| `--profile`         | Alcance del escaneo (ver tabla de perfiles). Por defecto, `standard`.             |
| `--correlate`       | Después del escaneo, muestra la correlación y los logs de los servicios encontrados. |
| `--since RANGO`     | Rango temporal de los logs de `--correlate`. Por defecto, el preset configurado (`1h`). |
| `-Pn`, `--no-ping`  | Omite el descubrimiento de hosts: escanea aunque el equipo no responda.           |
| `--save-xml ARCHIVO`| Guarda una copia del XML original de Nmap.                                        |
| `--format`          | `table` (por defecto), `json` o `csv`. Ver [Exportar resultados](#exportar-resultados). |
| `-o`, `--output ARCHIVO` | Escribe el resultado en un archivo en lugar de la salida estándar.           |
| `--json`            | Atajo de `--format json`.                                                         |
| `-q`, `--quiet`     | Oculta los avisos informativos (los errores se muestran siempre).                 |

| Perfil     | Argumentos de Nmap | Puertos analizados              | Uso típico                          |
|------------|--------------------|---------------------------------|-------------------------------------|
| `fast`     | `-sV -F`           | Los 100 más comunes             | Redes completas, primer vistazo     |
| `standard` | `-sV`              | Los 1000 más comunes            | Un equipo concreto                  |
| `full`     | `-sV -p-`          | Los 65535 puertos TCP           | Auditoría completa (puede tardar mucho) |

**Objetivos válidos**

| Tipo             | Ejemplo                           | Nota                                          |
|------------------|-----------------------------------|-----------------------------------------------|
| Dirección IPv4   | `192.168.1.10`                    |                                               |
| Dirección IPv6   | `::1`, `fe80::1`                  | Suize añade `-6` a Nmap automáticamente       |
| Nombre solo IPv6 | `ipv6.ejemplo.com`                | También añade `-6`, tras resolver el nombre   |
| Red CIDR         | `192.168.1.0/24`, `2001:db8::/64` |                                               |
| Rango de Nmap    | `10.0.0.1-20`, `"192.168.1.*"`    | El comodín `*` debe ir entre comillas en la shell |
| Nombre de host   | `servidor.lan`, `scanme.nmap.org` |                                               |

Por seguridad, se rechaza cualquier objetivo que empiece por `-`: Nmap lo interpretaría como
una opción (por ejemplo, `-iL /etc/shadow` leería ese archivo como lista de objetivos).

```bash
suize scan 192.168.1.0/24 --profile fast
suize scan servidor.lan --profile full --save-xml servidor.xml
suize scan 127.0.0.1 --correlate --since 6h
```

### `suize logs`

```
suize logs [-u UNIDAD] [-p PRIORIDAD] [--since RANGO] [--until FECHA]
           [-g REGEX] [-n N] [--json] [-q]
```

| Opción                  | Descripción                                                              |
|-------------------------|--------------------------------------------------------------------------|
| `-u`, `--unit UNIDAD`   | Unidad systemd. Se puede repetir para consultar varias. `ssh` equivale a `ssh.service`. |
| `-p`, `--priority PRIO` | Prioridad máxima (incluye todas las más graves) o un rango `DESDE..HASTA`. |
| `--since RANGO`         | Inicio del intervalo (ver formatos más abajo).                           |
| `--until FECHA`         | Fin del intervalo, como fecha exacta.                                    |
| `-g`, `--grep REGEX`    | Solo mensajes que coincidan con la expresión regular.                    |
| `-n`, `--lines N`       | Número máximo de entradas. Por defecto, `logs.lines` (200).              |
| `-f`, `--follow`        | Deja la consulta abierta y muestra las entradas nuevas según llegan.     |
| `--format`              | `table` (por defecto), `json` o `csv`.                                   |
| `-o`, `--output ARCHIVO`| Escribe el resultado en un archivo en lugar de la salida estándar.       |
| `--json`                | Atajo de `--format json`.                                                |
| `-q`, `--quiet`         | Oculta los avisos informativos.                                          |

Todos los filtros se combinan entre sí (se deben cumplir todos). Sin `--since` ni `--until`
no se aplica filtro temporal: se muestran las últimas `N` entradas, igual que `journalctl -n`.

```bash
suize logs -u ssh -p warning --since today
suize logs -u nginx -u php8.3-fpm --since 1h
suize logs -p 0..3 --since 7d
suize logs -g "Failed password|Invalid user" -u ssh --since 24h
suize logs --since "2026-01-15 08:00" --until "2026-01-15 09:30"
```

### Seguir el journal en vivo

Con `-f` la consulta no termina: cada entrada nueva aparece en cuanto se escribe en el journal,
igual que `journalctl -f`. Es lo que quieres mientras reproduces un problema.

```bash
suize logs -f                     # todo lo que vaya llegando
suize logs -f -u nginx -p err     # solo los errores de nginx
suize logs -f --since 15m         # arranca con lo reciente y sigue desde ahí
```

Se para con `Ctrl+C`, que es la forma normal de terminar: Suize sale con código 0 y dice
cuántas entradas mostró. Los filtros funcionan igual que en una consulta normal.

No se combina con `--json`, `--format csv` ni `--output`, porque el seguimiento no termina y no
hay un documento que cerrar; si quieres guardarlo, redirige la salida con `>`. Tampoco con
`--until`, que le pondría una fecha final a algo que por definición no la tiene. En los tres
casos Suize lo explica en vez de fallar a medias.

Antes de la tabla se muestra un resumen de las entradas encontradas:

```
╭───────────────────────────── Resumen ──────────────────────────────╮
│ Total: 10 entradas   ·   2026-01-15 10:30:00 → 2026-01-15 10:34:30 │
│ Filtro temporal: Últimas 24 horas (2026-01-14 10:40:00 → ahora)    │
│                                                                    │
│ Prioridad  Nº                              Top unidades   Nº       │
│  CRIT       1  █████                       ssh.service     3       │
│  ERR        1  █████                       nginx.service   2       │
│  WARN       1  █████                       kernel          1       │
│  NOTICE     1  █████                       cron.service    1       │
│  INFO       5  ████████████████████████    backup-script   1       │
│  DEBUG      1  █████                                               │
╰────────────────────────────────────────────────────────────────────╯
```

**Formatos de tiempo** para `--since`:

| Valor                       | Significado                                   |
|-----------------------------|-----------------------------------------------|
| `15m`, `1h`, `6h`, `24h`, `7d` | Presets: últimos 15 minutos, 1 hora, etc.  |
| `30s`, `90m`, `2d`, `1w`    | Cualquier duración en segundos, minutos, horas, días o semanas |
| `today` o `hoy`             | Desde las 00:00 de hoy                        |
| `yesterday` o `ayer`        | El día de ayer completo (00:00 a 00:00)       |
| `AAAA-MM-DD [HH:MM[:SS]]`   | Fecha exacta (también el formato de `--until`) |

Los rangos relativos se convierten en fechas absolutas en el momento de la consulta, y el
resumen muestra el intervalo exacto que se usó.

**Prioridades** (niveles de syslog, del más grave al menos grave):

| Nivel | Nombre    | Color en la tabla        |
|-------|-----------|--------------------------|
| 0     | `emerg`   | Blanco sobre fondo rojo  |
| 1     | `alert`   | Blanco sobre fondo rojo  |
| 2     | `crit`    | Rojo intenso             |
| 3     | `err`     | Rojo                     |
| 4     | `warning` | Amarillo                 |
| 5     | `notice`  | Cian                     |
| 6     | `info`    | Verde                    |
| 7     | `debug`   | Atenuado                 |

`-p` acepta el número o el nombre. Un valor único incluye todos los niveles más graves:
`-p warning` muestra los niveles 0 a 4. Para un intervalo concreto se usa `DESDE..HASTA`,
con números o nombres: `-p 0..3`, `-p warning..info`.

### Opciones globales

`--config`, `--no-color` y `--no-pager` funcionan en cualquiera de las dos posiciones, antes o
después del subcomando: `suize --no-color logs --since 1h` y `suize logs --since 1h --no-color`
son equivalentes. `--version` y `--help` sin subcomando muestran la información general;
después de uno, `--help` muestra la ayuda de ese subcomando.

| Opción              | Descripción                                          |
|---------------------|------------------------------------------------------|
| `--config ARCHIVO`  | Usa un archivo de configuración TOML propio          |
| `--no-color`        | Desactiva los colores                                |
| `--no-pager`        | No envía las salidas largas a `less`                 |
| `--no-emoji`        | Usa marcas de texto en vez de iconos                 |
| `-V`, `--version`   | Muestra la versión                                   |
| `-h`, `--help`      | Muestra la ayuda                                     |

### Códigos de salida

| Código | Significado                                                          |
|--------|----------------------------------------------------------------------|
| `0`    | Ejecución correcta (también cuando no hay resultados)                |
| `1`    | Error de ejecución: Nmap o journalctl fallaron, tiempo agotado, XML inválido |
| `2`    | Uso incorrecto o configuración inválida (se indica qué valor falla)  |
| `3`    | Falta una dependencia necesaria para el subcomando                   |
| `130`  | Interrumpido con Ctrl+C                                              |

## Correlación de puertos y servicios

La correlación sigue cuatro pasos:

1. **Puertos abiertos**: se toman del resultado del escaneo.
2. **Unidades candidatas**: para cada puerto se proponen nombres de unidad según el número de
   puerto y según el servicio que identificó Nmap. El segundo criterio cubre servicios en
   puertos no estándar, como SSH en el 2222 o nginx en el 8080.
3. **Verificación**: se listan los servicios del sistema con
   `systemctl list-units --type=service --all` y se descartan las candidatas que no existen.
   También se reconocen instancias de plantilla: `postgresql` coincide con `postgresql@16-main`.
4. **Consulta**: se piden a journalctl los logs de las unidades verificadas.

| Puerto   | Servicio de Nmap | Unidades candidatas           |
|----------|------------------|-------------------------------|
| 22       | `ssh`            | `ssh`, `sshd`                 |
| 80, 443  | `http`, `https`  | `nginx`, `apache2`, `httpd`   |
| 3306     | `mysql`          | `mysql`, `mariadb`            |
| 5432     | `postgresql`     | `postgresql`                  |
| 6379     | `redis`          | `redis`, `redis-server`       |
| 27017    | `mongodb`        | `mongod`, `mongodb`           |
| 631      | `ipp`            | `cups`                        |
| 139, 445 | `netbios-ssn`    | `smbd`                        |
| 25, 587  | `smtp`           | `postfix`, `exim4`            |
| 2049     | `nfs`            | `nfs-server`                  |
| 9090     | —                | `cockpit`                     |

Y algunos más: FTP, rpcbind, xrdp, MQTT y memcached. La lista completa está en
`src/suize/config/default.toml`.

### Reconocer tus propios servicios

Las tablas están en la configuración, no en el código, así que se amplían sin tocar Python.
Añade lo que necesites a `~/.config/suize/config.toml`:

```toml
[correlation.ports]
8006 = ["pveproxy"]          # un servicio propio
3306 = ["mariadb"]           # sustituye los candidatos de un puerto
27017 = []                   # desactiva un puerto de la tabla

[correlation.services]
http-alt = ["mi-servicio"]   # por el nombre que detecta Nmap, sea cual sea el puerto
```

Se combinan **entrada por entrada** con las que trae Suize: solo hay que escribir las que
cambias, no la tabla completa. Los nombres van sin el sufijo `.service` y se validan al
arrancar, así que una errata se detecta con un mensaje claro en vez de fallar luego al
consultar los logs.

Si un puerto aparece como `— ninguna —`, el servicio está escuchando pero no hay una unidad
systemd con ese nombre. Es habitual con servicios que corren en contenedores, cuyos logs se
consultan con `docker logs`.

La correlación usa siempre el journal **de la máquina local**. Si el objetivo es otro equipo,
Suize lo advierte, porque los logs mostrados no pertenecen a ese equipo.

## Paginación

Cuando el resultado no cabe en la pantalla, Suize lo envía a `less` (o al paginador de
`$PAGER`), igual que hace `journalctl`. Sales con `q` y buscas con `/`.

Solo ocurre si hay una terminal interactiva y el contenido supera la altura de la ventana: una
consulta de tres líneas se imprime directamente, y una salida redirigida a un archivo o a una
tubería nunca se pagina, para no romper los scripts.

```bash
suize logs --since 7d                # se pagina si hay muchas entradas
suize logs --since 7d --no-pager     # de corrido, como antes
suize logs --since 7d > informe.txt  # a un archivo: nunca se pagina
```

Los colores se conservan dentro del paginador. Si defines tus propias opciones en `$LESS`,
Suize las respeta; si no, usa `FRX`. Con `--format json` o `csv` no interviene: esos formatos
están pensados para procesarse.

## Exportar resultados

Ambos subcomandos aceptan `--format` y `--output`:

| Formato | Contenido                                                              |
|---------|------------------------------------------------------------------------|
| `table` | Tablas con color para leer en la terminal (por defecto)                |
| `json`  | Estructura completa, pensada para `jq` y scripts                       |
| `csv`   | Una fila por puerto o por entrada de log, para hojas de cálculo        |

```bash
suize scan 192.168.1.0/24 --format csv -o puertos.csv
suize logs -p err --since 7d --format csv -o errores.csv
suize scan 127.0.0.1 --format csv          # por stdout, para encadenar
```

Sin `--output`, el resultado sale por la salida estándar; con él, se escribe en el archivo y
se confirma por la salida de error (se puede silenciar con `-q`).

**Estructura del CSV de `scan`**: una fila por puerto, repitiendo en cada una las columnas del
host (`direccion`, `hostname`, `estado_host`, `mac`), seguidas de las del puerto (`puerto`,
`protocolo`, `estado`, `servicio`, `producto`, `version`, `info_extra`). Los hosts sin puertos
conservan una fila con esas celdas vacías, para que no desaparezcan del archivo. Con
`--correlate` se añade una columna `unidades` con las unidades systemd asociadas, separadas
por punto y coma.

**Estructura del CSV de `logs`**: una fila por entrada, con las columnas `fecha` (en formato
ISO), `prioridad`, `prioridad_nombre`, `unidad`, `hostname`, `pid` y `mensaje`.

Los archivos se escriben en UTF-8, con comas como separador y saltos de línea Unix. Si vas a
abrirlos en Excel y los acentos se ven mal, importa el archivo indicando UTF-8 en lugar de
abrirlo con doble clic.

## Salida JSON

Con `--json`, el resultado se imprime en JSON por la salida estándar y los avisos van a la
salida de error, así que el JSON se puede procesar directamente.

**`suize scan --json`**

```json
{
  "target": "127.0.0.1",
  "hosts": [
    {
      "address": "127.0.0.1",
      "address_type": "ipv4",
      "hostnames": ["localhost"],
      "status": "up",
      "mac": "",
      "ports": [
        {
          "number": 22,
          "protocol": "tcp",
          "state": "open",
          "service": "ssh",
          "product": "OpenSSH",
          "version": "9.6p1 Ubuntu 3ubuntu13.5",
          "extra_info": "Ubuntu Linux; protocol 2.0"
        }
      ]
    }
  ]
}
```

A diferencia de la tabla, `ports` incluye todos los puertos que informó Nmap, también los
`closed` y `filtered`. Con `--correlate` se añaden las claves `correlations`, `units`, `logs`
y `error` (`null` si la correlación funcionó).

**`suize logs --json`** devuelve tres claves: `query` (los filtros aplicados), `summary`
(totales) y `entries` (las entradas). Cada entrada tiene esta forma:

```json
{
  "timestamp": "2026-01-15T10:31:00",
  "priority": 3,
  "unit": "nginx.service",
  "message": "2026/01/15 10:31:00 [emerg] 1201#1201: bind() to 0.0.0.0:80 failed (98: Address already in use)",
  "hostname": "suize-lab",
  "pid": 1201,
  "priority_name": "err"
}
```

Ejemplos con [jq](https://jqlang.org/):

```bash
# Puertos abiertos como "ip:puerto servicio producto"
suize scan 192.168.1.0/24 --json -q \
  | jq -r '.hosts[] | .address as $ip | .ports[] | select(.state == "open")
           | "\($ip):\(.number) \(.service) \(.product)"'

# Errores de hoy, uno por línea
suize logs -p err --since today --json -q \
  | jq -r '.entries[] | "\(.timestamp) \(.unit): \(.message)"'

# Número de entradas por prioridad en la última semana
suize logs --since 7d --json -q | jq '.summary.by_priority'
```

## Configuración

La configuración se combina en tres capas; cada una sobrescribe a la anterior:

1. Valores por defecto: `src/suize/config/default.toml`, comentado clave por clave.
2. Archivo del usuario: la ruta de `--config`, o si no la de `$SUIZE_CONFIG`, o si no
   `~/.config/suize/config.toml`.
3. Variables de entorno `SUIZE_*`.

El archivo del usuario solo necesita las claves que quieras cambiar:

```toml
# ~/.config/suize/config.toml
[scan]
default_target = "192.168.1.0/24"
profile = "fast"

[logs]
lines = 500
default_time_preset = "today"
```

| Clave TOML                  | Variable de entorno      | Por defecto | Descripción                                   |
|-----------------------------|--------------------------|-------------|-----------------------------------------------|
| `scan.default_target`       | `SUIZE_DEFAULT_TARGET`   | `127.0.0.1` | Objetivo propuesto en el menú y en `scan` sin argumento |
| `scan.profile`              | `SUIZE_SCAN_PROFILE`     | `standard`  | Perfil de escaneo por defecto                 |
| `scan.timeout`              | `SUIZE_SCAN_TIMEOUT`     | `600`       | Tiempo máximo de un escaneo, en segundos      |
| `logs.lines`                | `SUIZE_LOG_LINES`        | `200`       | Número máximo de entradas por consulta        |
| `logs.timeout`              | `SUIZE_JOURNAL_TIMEOUT`  | `60`        | Tiempo máximo de una consulta, en segundos    |
| `logs.default_time_preset`  | `SUIZE_TIME_PRESET`      | `1h`        | Rango preseleccionado en el menú y en `--correlate` |
| `logs.top_units`            | —                        | `5`         | Unidades que se muestran en el resumen        |
| `correlation.ports`         | —                        | 7 servicios | Puerto → unidades systemd candidatas          |
| `correlation.services`      | —                        | 7 servicios | Servicio de Nmap → unidades systemd candidatas |
| `logs.time_presets`         | —                        | 8 presets   | Rangos que ofrece el menú (lista de `key` y `label`) |

Los valores se validan al arrancar. Un tipo incorrecto o un perfil inexistente terminan con
el código `2` y un mensaje que indica la clave afectada.

El archivo `.env.example` documenta las variables de entorno. Suize no lee `.env` por sí mismo;
`scripts/run.sh` lo carga si existe, o se puede exportar con `set -a; source .env; set +a`.

## Permisos

### Lectura del journal

journald solo permite leer los logs de todo el sistema a `root` y a los miembros de los grupos
`systemd-journal`, `adm` o `wheel`. Sin esos permisos, journalctl devuelve únicamente los logs
del propio usuario. Suize lo detecta al arrancar y lo avisa.

En Ubuntu y Linux Mint, el usuario creado durante la instalación ya pertenece a `adm`; en
Debian y otras distribuciones hay que añadirlo. Para comprobarlo y, si hace falta, corregirlo:

```bash
groups                                    # debe incluir adm o systemd-journal
sudo usermod -aG systemd-journal "$USER"  # después, cerrar la sesión y volver a entrar
```

### Nmap con y sin privilegios

Suize funciona sin privilegios. Ejecutarlo como root cambia el tipo de escaneo:

| Aspecto                  | Usuario normal                                   | root                                 |
|--------------------------|--------------------------------------------------|--------------------------------------|
| Técnica de escaneo       | TCP connect (`-sT`): completa la conexión TCP    | SYN (`-sS`): no completa la conexión, es más rápido |
| Direcciones MAC          | No disponibles                                   | Visibles en la red local             |
| Detección de versiones   | Igual en ambos casos                             | Igual en ambos casos                 |

`sudo` restablece el `PATH` por seguridad y no encuentra `~/.local/bin`, así que hay que
indicar la ruta completa:

```bash
sudo ~/.local/bin/suize scan 192.168.1.0/24 --profile fast
```

Suize nunca solicita ni ejecuta `sudo` por su cuenta.

## Solución de problemas

### `error: externally-managed-environment` al instalar

El sistema impide instalar paquetes sobre el Python global. Instala dentro de un entorno
virtual, como se indica en [Instalación](#instalación), o con pipx.

### `ERROR: Package 'suize' requires a different Python: 3.10.x not in '>=3.11'`

El entorno virtual se creó con una versión de Python anterior a la 3.11. Bórralo
(`rm -rf .venv`), créalo de nuevo con `python3.11 -m venv .venv` o una versión superior y
repite la instalación.

### `suize: command not found`

- Si se instaló con entorno virtual: comprueba que existe el enlace (`ls -l ~/.local/bin/suize`)
  y que `~/.local/bin` está en el `PATH` (`echo $PATH`). Si no aparece, cierra la sesión y
  vuelve a entrar.
- Si se instaló con pipx: ejecuta `pipx ensurepath` y abre una terminal nueva.
- Sin instalar: `.venv/bin/suize` desde la carpeta del proyecto, o `scripts/run.sh`.

### `sudo: suize: command not found`

Se explica en [Nmap con y sin privilegios](#nmap-con-y-sin-privilegios): usa la ruta completa.

### journalctl solo muestra mis propios logs

Falta pertenecer a un grupo con acceso al journal. Ver [Lectura del journal](#lectura-del-journal).

### systemd no está en ejecución (WSL o contenedores)

En WSL2, systemd está desactivado por defecto. Añade esto a `/etc/wsl.conf` dentro de la
distribución:

```ini
[boot]
systemd=true
```

Después ejecuta `wsl --shutdown` desde PowerShell y vuelve a abrir la distribución. En un
contenedor Docker no suele haber systemd: el escaneo funciona, pero los logs y la correlación
no tendrán datos.

### Un equipo encendido aparece como `down`

Antes de escanear puertos, Nmap comprueba si el equipo responde. Muchos cortafuegos (por
ejemplo, el de Windows con su configuración por defecto) bloquean esas pruebas y el equipo se
da por apagado. Usa `-Pn` para saltarse esa comprobación:

```bash
suize scan 192.168.1.40 -Pn
```

Cuando ningún host responde, Suize lo sugiere por su cuenta; en el menú interactivo, ofrece
directamente repetir el escaneo sin descubrimiento.

El escaneo tarda más, porque Nmap prueba todos los puertos de un equipo que quizá ni exista.
Con una red entera (`-Pn` sobre un `/24`) la diferencia es notable.

### El escaneo tarda mucho o se interrumpe por tiempo

Usa `--profile fast` para redes grandes; el perfil `full` analiza los 65535 puertos de cada
equipo. Si necesitas más tiempo, aumenta `scan.timeout` o `SUIZE_SCAN_TIMEOUT`.

### `El menú interactivo necesita una terminal`

Se ejecutó `suize` sin argumentos desde un pipe, cron o CI. Usa un subcomando, idealmente
con `--json`.

### El menú muestra cuadrados en lugar de iconos

La terminal no tiene una fuente con esos símbolos. Tienes dos salidas: instalar la fuente
(`sudo apt install fonts-noto-color-emoji` en Debian, Ubuntu o Linux Mint, y reabrir la
terminal), o desactivarlos con `--no-emoji`, que sustituye los iconos por marcas de texto.

## Limitaciones conocidas

- **Solo TCP**: no se realizan escaneos UDP (`-sU`).
- **Correlación local**: los logs corresponden siempre a la máquina donde se ejecuta Suize.
- **Asociaciones predefinidas**: la correlación reconoce los servicios de la tabla anterior;
  para otros hay que añadirlos a la configuración.

## Desarrollo

### Entorno

```bash
git clone https://github.com/TU-USUARIO/suize.git
cd suize
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"      # pytest, ruff, mypy, pytest-cov y pre-commit
```

### Tests y calidad

```bash
pytest -v                    # tests unitarios y de integración
ruff check .                 # linter
ruff format --check .        # formato
mypy src                     # tipos, en modo estricto
scripts/lint.sh              # todo lo anterior en un solo comando
scripts/lint.sh --fix        # aplica las correcciones automáticas de ruff
```

La cobertura se mide junto con los tests, con un umbral del 90 % que comparten `scripts/lint.sh`
y la CI:

```bash
pytest --cov                 # informe por módulo, con las líneas sin cubrir
```

### Comprobaciones antes de cada commit

Opcional, pero recomendable: `pre-commit` ejecuta ruff y mypy sobre lo que vas a confirmar, así
los fallos aparecen antes del push y no en la CI.

La herramienta viene con las dependencias de desarrollo; solo falta activarla:

```bash
pre-commit install           # una sola vez, dentro del entorno virtual
pre-commit run --all-files   # para pasarlo a mano sobre todo el proyecto
```

Las versiones de las herramientas están fijadas en `.pre-commit-config.yaml` a las mismas que
usa la CI. Si actualizas ruff en `pyproject.toml`, actualiza también el `rev` de ese archivo.

Los tests no necesitan Nmap, journalctl, systemd ni permisos de root: sustituyen las llamadas
al sistema por respuestas grabadas en `tests/fixtures/` (un XML real de Nmap y una salida real
de `journalctl -o json`).

### Integración continua

`.github/workflows/ci.yml` se ejecuta en cada push a `main` y en cada pull request:

| Job        | Qué comprueba                                                              |
|------------|----------------------------------------------------------------------------|
| `lint`     | `ruff check`, `ruff format --check` y `mypy src`                           |
| `test`     | `pytest` en Python 3.11, 3.12, 3.13 y 3.14, con cobertura en 3.12          |
| `package`  | Construye el wheel, verifica que incluye `default.toml`, lo instala en un entorno limpio y ejecuta `suize --help` |

### Publicar una versión

Los cambios de cada versión se registran en el [CHANGELOG](CHANGELOG.md), en formato
[Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/).

El proyecto usa [versionado semántico](https://semver.org/lang/es/). Dado `MAYOR.MENOR.PARCHE`:

| Parte     | Se sube cuando...                                                          | Ejemplo                                        |
|-----------|----------------------------------------------------------------------------|------------------------------------------------|
| `PARCHE`  | Solo hay correcciones: el comportamiento previsto no cambia                | Un objetivo válido que se rechazaba por error  |
| `MENOR`   | Hay funcionalidad nueva compatible con lo anterior                          | La opción `--format csv`                       |
| `MAYOR`   | Algo que funcionaba deja de funcionar igual                                 | Renombrar una opción o cambiar el formato del JSON |

Para una herramienta de línea de comandos, la interfaz pública son los nombres de las opciones,
los formatos de salida (`--json`, `--format csv`) y los códigos de salida. Cambiar cualquiera de
esos rompe los scripts de quien la use, así que cuentan como cambio mayor. La organización
interna del código, en cambio, no: mover la serialización a `ui/export.py` no le afecta a nadie
desde fuera.

Mientras la versión mayor sea `0`, la interfaz se considera todavía inestable y un cambio
incompatible solo sube la versión menor.

Los cambios se anotan en el apartado **Sin publicar** del [CHANGELOG](CHANGELOG.md) según se van
haciendo, no al final de golpe. Para publicar:

```bash
# 1. Renombrar "Sin publicar" con la versión y la fecha, dejando un nuevo
#    apartado "Sin publicar" vacío arriba, y actualizar los enlaces del final.
$EDITOR CHANGELOG.md

# 2. Subir la versión en el código (una sola fuente de verdad: pyproject la lee de aquí).
$EDITOR src/suize/__init__.py

# 3. Comprobar que todo cuadra: hay un test que compara ambas.
scripts/lint.sh

# 4. Commit, etiqueta y publicación.
git commit -am "Versión 0.2.0"
git tag -a v0.2.0 -m "Versión 0.2.0"
git push && git push --tags
gh release create v0.2.0 --notes-from-tag
```

Si el paso 3 falla con `assert '0.2.0' == '0.1.0'`, es que falta uno de los dos primeros pasos.

### Estructura del proyecto

```
suize/
├── pyproject.toml              Metadatos, dependencias y configuración de las herramientas
├── src/suize/
│   ├── cli.py                  Punto de entrada: argumentos, subcomandos y códigos de salida
│   ├── config/                 default.toml y carga de la configuración en capas
│   ├── models/                 Dataclasses del dominio: Host, Port, LogEntry, LogSummary
│   ├── utils/                  subprocess, validación, rangos de tiempo, dependencias, permisos
│   ├── core/                   Ejecución y parseo de Nmap/journalctl, correlación
│   └── ui/                     Menús (questionary), tablas (rich), paginador y exportación
├── tests/
│   ├── fixtures/               Salidas reales de Nmap y journalctl
│   ├── unit/                   Parsers, validadores, rangos de tiempo, correlación
│   └── integration/            La CLI completa con el sistema simulado
├── docs/
│   ├── architecture.md         Capas, flujo de datos y decisiones de diseño
│   └── examples.md             Ejemplos detallados y recetas
└── scripts/
    ├── run.sh                  Ejecuta Suize sin instalarlo (carga .env si existe)
    └── lint.sh                 Lint, formato, tipos y tests
```

El código se organiza en capas con dependencias en un solo sentido:
`models` <- `utils` <- `core` <- `ui` <- `cli`. La lógica de `core` nunca importa la interfaz,
y todas las llamadas a programas externos pasan por un único módulo (`utils/shell.py`), que no
usa una shell, verifica que el programa exista y aplica siempre un tiempo máximo. El detalle
está en [docs/architecture.md](docs/architecture.md).

### Contribuir

Las mejores previstas están en [ROADMAP.md](ROADMAP.md) y las [issues abiertas](https://github.com/alejandrocsharp/suize/issues), etiquetadas por prioridad.

1. Crea una rama a partir de `main`.
2. Añade tests para el cambio (los fixtures de `tests/fixtures/` sirven como base).
3. Ejecuta `scripts/lint.sh` antes de abrir el pull request; la CI aplica las mismas
   comprobaciones.

## Uso responsable

Escanea únicamente equipos y redes propios o para los que tengas autorización expresa.
Escanear sistemas ajenos sin permiso puede ser ilegal, y los escaneos quedan registrados en
los logs del equipo analizado.

## Licencia

Distribuido bajo la licencia MIT. Ver [LICENSE](LICENSE).
