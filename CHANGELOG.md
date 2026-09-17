# Registro de cambios

Todos los cambios relevantes de Suize se documentan aquí.

El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/) y el proyecto usa
[versionado semántico](https://semver.org/lang/es/): `MAYOR.MENOR.PARCHE`. Ver
[Publicar una versión](README.md#publicar-una-versión) para el proceso.

## [Sin publicar]

## [0.3.0] - 2026-09-16

### Añadido

- Aviso al pedir `-Pn` sobre una red de 1024 direcciones o más: sin descubrimiento, Nmap prueba
  los puertos de todas, existan o no, y el escaneo puede tardar horas.

### Corregido

- El seguimiento en vivo podía colgarse indefinidamente. `stream()` abría una tubería para
  `stderr` que nadie leía: al llenarse su búfer (unos 64 KB) el proceso hijo se bloqueaba al
  escribir, sin error ni salida. Ahora va a un archivo temporal, que además permite explicar
  por qué falló el programa en vez de terminar en silencio.

### Cambiado

- El menú consulta `systemctl list-units` una sola vez por sesión, en lugar de una al
  autocompletar unidades y otra al correlacionar.

### Añadido

- Seguimiento del journal en vivo con `-f`/`--follow`: las entradas aparecen según se escriben,
  con los mismos filtros que una consulta normal. Se para con `Ctrl+C`, que sale con código 0.
- Perfil de escaneo `udp` (`--profile udp`), para los servicios que no se ven en TCP: DNS,
  DHCP, SNMP, NTP o mDNS. Requiere root, y Suize lo comprueba antes de lanzar Nmap para poder
  explicar cómo repetirlo con sudo.
- Opción `-Pn`/`--no-ping` en `scan`, que omite el descubrimiento de hosts y escanea los
  puertos aunque el equipo no responda (habitual con el cortafuegos de Windows). Cuando ningún
  host responde, Suize lo sugiere; en el menú interactivo ofrece repetir el escaneo sin
  descubrimiento.
- Autocompletado de shell para zsh y bash, en `completions/`. Además de subcomandos y opciones,
  completa los valores de `--profile`, `--format`, `-p/--priority` y `--since`, y las unidades
  systemd reales del equipo en `-u/--unit`. No añade dependencias.
- Las tablas de correlación (puerto y servicio → unidades systemd) pasan a la configuración,
  en `[correlation.ports]` y `[correlation.services]`. Se combinan entrada por entrada con las
  que trae Suize, así que reconocer un servicio propio ya no exige tocar el código. Una lista
  vacía desactiva una entrada.
- Más servicios reconocidos de fábrica por la correlación: CUPS (631), Samba, Postfix, NFS,
  rpcbind, xrdp, Cockpit, FTP, MQTT y memcached.
- Opción global `--no-emoji`, para terminales sin una fuente que incluya los iconos. Los del
  menú desaparecen y los de los mensajes se sustituyen por marcas de texto (`[i]`, `[ok]`,
  `[!]`, `[x]`), que siguen distinguiendo un error de un aviso.

### Corregido

- Los puertos `open|filtered` se daban por cerrados, así que no aparecían en la tabla ni en la
  correlación. Es el estado más habitual en UDP: ahora cuentan como abiertos.
- El panel de dependencias y el error de fecha inválida escribían su símbolo a mano en vez de
  usar la función común, así que ignoraban cualquier cambio de formato de los mensajes.

## [0.2.0] - 2026-09-12

### Añadido

- Exportación a CSV y escritura a archivo: `--format {table,json,csv}` y `-o/--output` en
  `scan` y en `logs`. El CSV de `scan` lleva una fila por puerto, y con `--correlate` añade una
  columna `unidades`; el de `logs`, una fila por entrada. `--json` se mantiene como atajo de
  `--format json`.
- Paginación automática de las salidas largas: cuando hay una terminal y el resultado no cabe
  en pantalla, se envía a `less` (o al paginador de `$PAGER`), conservando los colores. La
  nueva opción `--no-pager` lo desactiva. Las salidas redirigidas a un archivo o a una tubería
  nunca se paginan.
- Detección de objetivos IPv6 indicados por nombre de host: si el nombre solo resuelve a
  direcciones IPv6, se le pasa `-6` a Nmap automáticamente. Un nombre con registros A y AAAA
  no lo activa, porque Nmap funciona con IPv4.

### Cambiado

- El README se reorganiza en torno a la correlación, que es lo que distingue a Suize: el
  ejemplo de punta a punta pasa al principio y la referencia exhaustiva de opciones,
  configuración y solución de problemas se traslada a `docs/`. De 941 a 427 líneas.
- Nueva tabla de sistemas compatibles, que distingue lo comprobado de lo que debería
  funcionar.

- Las opciones globales `--config`, `--no-color` y `--no-pager` se aceptan tanto antes como
  después del subcomando: `suize logs --since 1h --no-color` ya no da error.

## [0.1.0] - 2026-09-11

Primera versión.

### Añadido

- Menú interactivo con cuatro acciones: escanear con Nmap, analizar logs, escanear y
  correlacionar, y salir.
- Subcomandos `scan` y `logs` para scripts y cron, con salida JSON.
- Escaneo con detección de versiones (`nmap -sV`) y tres perfiles: `fast`, `standard` y `full`.
  Soporte para IPv4, IPv6 literal, redes CIDR, rangos de Nmap y nombres de host.
- Consulta de logs con filtros combinables por unidad, prioridad, rango temporal y expresión
  regular, con presets de tiempo legibles y resumen previo (total, conteo por prioridad y
  unidades más activas).
- Correlación de puertos abiertos con unidades systemd, verificadas contra
  `systemctl list-units` antes de consultar sus logs.
- Configuración en capas: `default.toml`, archivo del usuario y variables de entorno `SUIZE_*`.
- Comprobación de dependencias y permisos al arrancar, sin abortar: se desactiva solo lo que no
  se puede usar y se explica por qué.
- Validación de objetivos y unidades contra la inyección de argumentos en Nmap y journalctl.

[Sin publicar]: https://github.com/TU-USUARIO/suize/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/TU-USUARIO/suize/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/TU-USUARIO/suize/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/TU-USUARIO/suize/releases/tag/v0.1.0
