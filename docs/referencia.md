# Referencia

Detalle completo de opciones, formatos y configuración. Para empezar, el
[README](../README.md) tiene lo esencial.

## Contenido

- [Subcomandos](#subcomandos)
- [Exportar resultados](#exportar-resultados)
- [Salida JSON](#salida-json)
- [Paginación](#paginación)
- [Autocompletado](#autocompletado)
- [Configuración](#configuración)

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
| `udp`      | `-sV -sU -F`       | Los 100 puertos UDP más comunes | DNS, DHCP, SNMP, NTP (requiere root, muy lento) |

**Escaneos UDP.** El perfil `udp` cubre los servicios que no se ven en TCP: DNS, DHCP, SNMP,
NTP o mDNS.

```bash
sudo ~/.local/bin/suize scan 192.168.1.10 --profile udp
```

Dos diferencias respecto a TCP que conviene tener presentes. Necesita **root**, porque Nmap
tiene que enviar paquetes en crudo; si no lo tienes, Suize lo dice antes de empezar en vez de
dejar que Nmap aborte con un escueto "QUITTING!". Y es **mucho más lento**: como UDP no
confirma la recepción, Nmap espera un tiempo por cada puerto que no contesta. Cien puertos
pueden llevar un par de minutos; si te quedas corto, sube `scan.timeout`.

Verás muchos puertos como `open|filtered`. No es un fallo: significa que no llegó respuesta, y
Nmap no puede distinguir si el puerto está abierto y el servicio calla, o si un cortafuegos
descartó la sonda. Es el resultado más habitual en UDP, así que Suize los muestra como abiertos;
descartarlos dejaría casi cualquier escaneo UDP con la tabla vacía.

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
