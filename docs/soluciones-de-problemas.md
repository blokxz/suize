# Solución de problemas

Errores frecuentes y cómo resolverlos, más el detalle de los permisos que
necesita Suize.

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
