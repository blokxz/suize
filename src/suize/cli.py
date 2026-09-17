"""Punto de entrada de Suize.

* Sin argumentos → menú interactivo (requiere una terminal).
* Con subcomandos → modo no interactivo para scripts y cron::

      suize scan 192.168.1.10 [--profile fast] [--correlate] [--json]
      suize logs -u ssh -p err --since 1h [--json]

Es el único módulo que orquesta todas las capas. No hace nada al importarse:
toda la lógica de arranque vive en :func:`main`.
"""

import argparse
import os
import sys
from collections.abc import Mapping, Sequence
from dataclasses import asdict
from pathlib import Path
from typing import Any

from rich.console import Console

from suize import __version__
from suize.config.settings import ConfigError, Settings, load_settings
from suize.core import correlator, nmap_runner
from suize.core.correlator import Correlation
from suize.core.journal_reader import JournalQuery
from suize.models.host import Host
from suize.models.log_entry import LogEntry, LogSummary
from suize.ui import menus
from suize.ui.export import (
    OUTPUT_FORMATS,
    correlation_to_json,
    dump_json,
    entry_to_json,
    open_output,
    units_by_port,
    write_logs_csv,
    write_scan_csv,
)
from suize.ui.pager import paged
from suize.ui.render_nmap import render_correlations, render_hosts
from suize.ui.theme import configure_icons, make_console, message
from suize.utils.deps import (
    Dependency,
    check_dependencies,
    is_systemd_running,
    missing,
    systemd_hint,
)
from suize.utils.permissions import PermissionStatus, check_permissions, journal_hint, nmap_hint
from suize.utils.time_filter import TimeRange, parse_range, resolve_preset
from suize.utils.validators import is_loopback, parse_priority, validate_target, validate_unit

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_MISSING_DEPENDENCY = 3
EXIT_INTERRUPTED = 130

EPILOG = """\
ejemplos:
  suize                                   menú interactivo
  suize scan 192.168.1.10                 escaneo con detección de versiones
  suize scan 127.0.0.1 --correlate        escaneo + logs de los servicios detectados
  suize logs -u ssh -p err --since 1h     errores de SSH de la última hora
  suize logs --since yesterday --json     logs de ayer en JSON (para jq)

códigos de salida: 0 ok · 1 error de ejecución · 2 uso/config inválidos ·
3 falta una dependencia · 130 interrumpido
"""


# --------------------------------------------------------------------------- argparse


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{value}' no es un número entero") from None
    if number <= 0:
        raise argparse.ArgumentTypeError("debe ser mayor que 0")
    return number


#: Opciones válidas tanto antes como después del subcomando.
GLOBAL_OPTION_HELP = {
    "--config": "archivo TOML de configuración propio",
    "--no-color": "salida sin colores",
    "--no-pager": "no enviar las salidas largas a less",
    "--no-emoji": "usa marcas de texto en vez de iconos",
}


def _add_global_options(parser: argparse.ArgumentParser, *, inherit: bool = False) -> None:
    """Añade las opciones globales a ``parser``.

    Con ``inherit`` se preparan para repetirlas dentro de cada subcomando: sin
    ayuda (ya aparecen en la general) y con ``SUPPRESS`` como valor por defecto,
    imprescindible para que el subparser no pise con un ``False`` lo que el
    usuario indicó antes del subcomando.
    """
    default = argparse.SUPPRESS if inherit else None
    for flag, help_text in GLOBAL_OPTION_HELP.items():
        help_shown = argparse.SUPPRESS if inherit else help_text
        if flag == "--config":
            parser.add_argument(
                flag,
                type=Path,
                metavar="ARCHIVO",
                default=default,
                help=help_shown,
            )
        else:
            parser.add_argument(
                flag,
                action="store_true",
                default=default if inherit else False,
                help=help_shown,
            )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="suize",
        description="Navaja suiza de terminal: escaneos con Nmap y logs de journalctl.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    _add_global_options(parser)
    # Las mismas opciones, repetidas en cada subcomando para aceptarlas también
    # después de él: 'suize logs --no-pager' es lo que uno escribe por instinto.
    # default=SUPPRESS es imprescindible: sin él, el subparser sobrescribiría con
    # su propio valor por defecto lo que se indicó antes del subcomando.
    inherited = argparse.ArgumentParser(add_help=False)
    _add_global_options(inherited, inherit=True)
    sub = parser.add_subparsers(dest="command", metavar="{scan,logs}")

    scan = sub.add_parser(
        "scan",
        parents=[inherited],
        help="escanea un objetivo con Nmap (-sV)",
        description="Escanea un objetivo con `nmap -sV` y muestra los puertos abiertos.",
    )
    scan.add_argument(
        "target",
        nargs="?",
        help="IP, hostname, red CIDR o rango de Nmap (por defecto, el de la configuración)",
    )
    scan.add_argument(
        "--profile",
        choices=sorted(nmap_runner.SCAN_PROFILES),
        help="fast (-F) · standard (1000 puertos) · full (-p-)",
    )
    scan.add_argument(
        "-Pn",
        "--no-ping",
        dest="skip_ping",
        action="store_true",
        help="omite el descubrimiento de hosts: escanea aunque el equipo no responda",
    )
    scan.add_argument(
        "--correlate",
        action="store_true",
        help="muestra también los logs de las unidades systemd de los puertos abiertos",
    )
    scan.add_argument(
        "--since", metavar="RANGO", help="rango temporal para --correlate (por defecto, el preset)"
    )
    scan.add_argument("--save-xml", type=Path, metavar="ARCHIVO", help="guarda una copia del XML")
    scan.add_argument(
        "--format",
        choices=OUTPUT_FORMATS,
        default="table",
        help="formato de salida (por defecto: table)",
    )
    scan.add_argument(
        "-o",
        "--output",
        type=Path,
        metavar="ARCHIVO",
        help="escribe el resultado en un archivo en vez de stdout",
    )
    scan.add_argument("--json", action="store_true", help="atajo de --format json")
    scan.add_argument("-q", "--quiet", action="store_true", help="oculta avisos informativos")

    logs = sub.add_parser(
        "logs",
        parents=[inherited],
        help="consulta los logs del sistema con journalctl",
        description="Consulta journalctl con filtros combinables.",
    )
    logs.add_argument(
        "-u",
        "--unit",
        action="append",
        default=[],
        metavar="UNIDAD",
        help="unidad systemd (se puede repetir)",
    )
    logs.add_argument(
        "-p", "--priority", metavar="PRIO", help="0-7, nombre (err, warning...) o rango 0..4"
    )
    logs.add_argument(
        "--since",
        metavar="RANGO",
        help="15m, 1h, 6h, 24h, 7d, today, yesterday, cualquier duración o 'AAAA-MM-DD HH:MM'",
    )
    logs.add_argument("--until", metavar="FECHA", help="fecha exacta 'AAAA-MM-DD [HH:MM[:SS]]'")
    logs.add_argument("-g", "--grep", metavar="REGEX", help="filtra mensajes por expresión regular")
    logs.add_argument(
        "-n", "--lines", type=_positive_int, metavar="N", help="máximo de entradas a mostrar"
    )
    logs.add_argument(
        "-f",
        "--follow",
        action="store_true",
        help="deja la consulta abierta y muestra las entradas nuevas según llegan",
    )
    logs.add_argument(
        "--format",
        choices=OUTPUT_FORMATS,
        default="table",
        help="formato de salida (por defecto: table)",
    )
    logs.add_argument(
        "-o",
        "--output",
        type=Path,
        metavar="ARCHIVO",
        help="escribe el resultado en un archivo en vez de stdout",
    )
    logs.add_argument("--json", action="store_true", help="atajo de --format json")
    logs.add_argument("-q", "--quiet", action="store_true", help="oculta avisos informativos")
    return parser


# --------------------------------------------------------------------------- utilidades


def _is_interactive_terminal() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def _resolve_format(args: argparse.Namespace) -> str:
    """``--json`` se mantiene como sinónimo de ``--format json``."""
    return "json" if args.json else str(args.format)


def _report_written(err: Console, path: Path | None, rows: int, quiet: bool) -> None:
    if path is not None and not quiet:
        plural = "fila" if rows == 1 else "filas"
        err.print(message("info", f"Escrito {path} ({rows} {plural})."))


def _check_required(err: Console, deps: Mapping[str, Dependency], names: Sequence[str]) -> bool:
    absent = missing(deps, names)
    if absent:
        err.print(menus.build_dependency_panel(absent))
        return False
    return True


def _validate_settings(settings: Settings) -> None:
    if settings.scan_profile not in nmap_runner.SCAN_PROFILES:
        valid = ", ".join(nmap_runner.SCAN_PROFILES)
        raise ConfigError(
            f"scan.profile='{settings.scan_profile}' no es válido. Opciones: {valid}."
        )


# --------------------------------------------------------------------------- subcomandos


def _cmd_scan(
    args: argparse.Namespace,
    settings: Settings,
    deps: Mapping[str, Dependency],
    permissions: PermissionStatus,
    out: Console,
    err: Console,
) -> int:
    try:
        target = validate_target(args.target or settings.default_target)
        time_range: TimeRange | None = None
        if args.correlate:
            time_range = parse_range(args.since) or resolve_preset(settings.default_time_preset)
    except ValueError as exc:
        err.print(message("error", str(exc)))
        return EXIT_USAGE

    required = ["nmap", "journalctl", "systemctl"] if args.correlate else ["nmap"]
    if not _check_required(err, deps, required):
        return EXIT_MISSING_DEPENDENCY
    if not args.quiet and (hint := nmap_hint(permissions)):
        err.print(message("info", hint))
    if args.correlate and not args.quiet and not is_loopback(target):
        err.print(message("warning", menus.REMOTE_CORRELATION_WARNING))

    if not args.quiet and (aviso := menus.large_network_warning(target, skip_ping=args.skip_ping)):
        err.print(message("warning", aviso))

    profile = args.profile or settings.scan_profile
    if (hint := menus.root_required_hint(profile)) is not None:
        err.print(message("error", hint))
        return EXIT_USAGE

    try:
        hosts: list[Host] = menus.execute_scan(
            err,
            target,
            profile=profile,
            timeout=settings.scan_timeout,
            save_xml=args.save_xml,
            skip_ping=args.skip_ping,
        )
    except menus.USER_ERRORS as exc:
        err.print(message("error", str(exc)))
        return EXIT_ERROR

    # Si la correlación falla (p. ej. systemd no está activo) el escaneo sigue siendo
    # válido: se muestra igualmente y se sale con código 1.
    correlations: list[Correlation] = []
    units: list[str] = []
    entries: list[LogEntry] = []
    correlation_error: Exception | None = None
    if args.correlate and any(host.open_ports for host in hosts):
        try:
            correlations = menus.find_correlations(
                err,
                hosts,
                timeout=settings.journal_timeout,
                tables=menus.correlation_tables(settings),
            )
            units = correlator.units_to_query(correlations)
            if units:
                query = JournalQuery(
                    units=tuple(units), time_range=time_range, lines=settings.log_lines
                )
                entries = menus.execute_logs(err, query, timeout=settings.journal_timeout)
        except menus.USER_ERRORS as exc:
            correlation_error = exc

    output_format = _resolve_format(args)
    if output_format != "table":
        try:
            with open_output(args.output) as stream:
                if output_format == "json":
                    payload: dict[str, Any] = {
                        "target": target,
                        "hosts": [asdict(host) for host in hosts],
                    }
                    if args.correlate:
                        payload["correlations"] = [
                            correlation_to_json(item) for item in correlations
                        ]
                        payload["units"] = units
                        payload["logs"] = [entry_to_json(entry) for entry in entries]
                        payload["error"] = str(correlation_error) if correlation_error else None
                    dump_json(payload, stream)
                    rows = len(hosts)
                else:
                    # La correlación solo añade una columna si se pidió --correlate.
                    correlated = units_by_port(correlations) if args.correlate else None
                    rows = write_scan_csv(hosts, stream, correlated=correlated)
        except BrokenPipeError:
            # Tubería cerrada por el consumidor (p. ej. `suize ... | head`).
            # Es un OSError, pero lo gestiona main(); aquí solo se deja pasar.
            raise
        except OSError as exc:
            err.print(message("error", f"No se pudo escribir {args.output}: {exc}"))
            return EXIT_ERROR
        _report_written(err, args.output, rows, args.quiet)
    else:
        # Aquí no hay preguntas de por medio, así que todo el informe cabe en
        # un único paginador en lugar de uno por sección.
        with paged(out, enabled=not args.no_pager):
            render_hosts(out, hosts, target=target)
            if args.correlate and correlation_error is None:
                render_correlations(out, correlations)
                if units:
                    menus.show_logs(
                        out,
                        entries,
                        settings=settings,
                        permissions=permissions,
                        time_range=time_range,
                        title=f"Logs de {', '.join(units)}",
                        limit=settings.log_lines,
                    )
                elif correlations:
                    out.print(
                        message(
                            "info", "Ninguna unidad systemd coincide con los servicios detectados."
                        )
                    )

    # Después de la tabla: leerlo antes del resultado despista.
    if not args.quiet and not args.skip_ping and menus.nothing_responded(hosts):
        err.print(message("warning", menus.SKIP_PING_HINT))

    if correlation_error is not None:
        err.print(message("error", f"No se pudo correlacionar con los logs: {correlation_error}"))
        return EXIT_ERROR
    return EXIT_OK


def _follow_conflict(args: argparse.Namespace) -> str | None:
    """Combinaciones incompatibles con ``--follow``; ``None`` si todo encaja."""
    if _resolve_format(args) != "table":
        return (
            "--follow no se combina con --json ni --format csv: el seguimiento no "
            "termina, así que no hay un documento que cerrar. Redirige la salida de "
            "'suize logs --follow' si quieres guardarla."
        )
    if args.output is not None:
        return (
            "--follow no se combina con --output: redirige la salida con '>' si la "
            "quieres en un archivo."
        )
    if args.until is not None:
        return "--follow no se combina con --until: seguir el journal no tiene fecha final."
    return None


def _cmd_logs(
    args: argparse.Namespace,
    settings: Settings,
    deps: Mapping[str, Dependency],
    permissions: PermissionStatus,
    out: Console,
    err: Console,
) -> int:
    try:
        units = tuple(validate_unit(unit) for unit in args.unit)
        priority = parse_priority(args.priority) if args.priority else None
        time_range = parse_range(args.since, args.until)
    except ValueError as exc:
        err.print(message("error", str(exc)))
        return EXIT_USAGE

    if args.follow:
        conflicto = _follow_conflict(args)
        if conflicto is not None:
            err.print(message("error", conflicto))
            return EXIT_USAGE

    if not _check_required(err, deps, ["journalctl"]):
        return EXIT_MISSING_DEPENDENCY
    if not args.quiet:
        if not is_systemd_running():
            err.print(message("warning", systemd_hint()))
        elif hint := journal_hint(permissions):
            err.print(message("warning", hint))

    query = JournalQuery(
        units=units,
        priority=priority,
        time_range=time_range,
        grep=args.grep or None,
        lines=args.lines or settings.log_lines,
    )
    if args.follow:
        return menus.follow_logs(out, err, query, quiet=args.quiet)

    try:
        entries = menus.execute_logs(err, query, timeout=settings.journal_timeout)
    except menus.USER_ERRORS as exc:
        err.print(message("error", str(exc)))
        return EXIT_ERROR

    output_format = _resolve_format(args)
    if output_format != "table":
        try:
            with open_output(args.output) as stream:
                if output_format == "json":
                    summary = LogSummary.from_entries(entries, top_n=settings.top_units)
                    dump_json(
                        {
                            "query": {
                                "units": list(units),
                                "priority": priority,
                                "since": time_range.since if time_range else None,
                                "until": time_range.until if time_range else None,
                                "grep": query.grep,
                                "lines": query.lines,
                            },
                            "summary": asdict(summary),
                            "entries": [entry_to_json(entry) for entry in entries],
                        },
                        stream,
                    )
                else:
                    write_logs_csv(entries, stream)
        except BrokenPipeError:
            # Tubería cerrada por el consumidor (p. ej. `suize ... | head`).
            # Es un OSError, pero lo gestiona main(); aquí solo se deja pasar.
            raise
        except OSError as exc:
            err.print(message("error", f"No se pudo escribir {args.output}: {exc}"))
            return EXIT_ERROR
        _report_written(err, args.output, len(entries), args.quiet)
        return EXIT_OK

    with paged(out, enabled=not args.no_pager):
        menus.show_logs(
            out,
            entries,
            settings=settings,
            permissions=permissions,
            time_range=time_range,
            title=f"Logs de {', '.join(units)}" if units else "Logs del sistema",
            limit=query.lines,
        )
    return EXIT_OK


def _cmd_interactive(
    settings: Settings,
    deps: Mapping[str, Dependency],
    permissions: PermissionStatus,
    out: Console,
    err: Console,
    *,
    pager: bool = True,
) -> int:
    if not _is_interactive_terminal():
        err.print(
            message(
                "error",
                "El menú interactivo necesita una terminal. Usa un subcomando, "
                "p. ej. 'suize scan 127.0.0.1' o 'suize logs --since 1h' (ver 'suize --help').",
            )
        )
        return EXIT_USAGE
    ctx = menus.AppContext(
        console=out,
        settings=settings,
        deps=deps,
        permissions=permissions,
        pager=pager,
    )
    return menus.run_menu(ctx)


# --------------------------------------------------------------------------- main


def main(argv: Sequence[str] | None = None) -> int:
    """Punto de entrada (script ``suize`` y ``python -m suize``). Devuelve el código de salida."""
    args = build_parser().parse_args(argv)
    # Antes de crear nada que imprima: fija los iconos para todo el proceso.
    configure_icons(emoji=not args.no_emoji)
    out = make_console(no_color=args.no_color)
    err = make_console(no_color=args.no_color, stderr=True)

    try:
        settings = load_settings(args.config)
        _validate_settings(settings)
    except ConfigError as exc:
        err.print(message("error", f"Configuración inválida: {exc}"))
        return EXIT_USAGE

    deps = check_dependencies()
    permissions = check_permissions()
    try:
        if args.command == "scan":
            return _cmd_scan(args, settings, deps, permissions, out, err)
        if args.command == "logs":
            return _cmd_logs(args, settings, deps, permissions, out, err)
        return _cmd_interactive(settings, deps, permissions, out, err, pager=not args.no_pager)
    except KeyboardInterrupt:
        err.print(message("warning", "Interrumpido por el usuario."))
        return EXIT_INTERRUPTED
    except BrokenPipeError:
        # El consumidor de la tubería cerró antes de tiempo (p. ej. `suize ... | head`).
        # Se redirige stdout a /dev/null para que Python no falle otra vez al vaciarlo.
        _silence_stdout()
        return EXIT_ERROR


def _silence_stdout() -> None:
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
    except (OSError, ValueError):
        pass
