"""Menú principal, submenús interactivos y acciones compartidas con los subcomandos."""

import ipaddress
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from questionary import Choice
from rich.console import Console, Group
from rich.panel import Panel
from rich.text import Text

from suize import __version__
from suize.config.settings import Settings
from suize.core import correlator, journal_parser, journal_reader, nmap_parser, nmap_runner
from suize.core.correlator import Correlation
from suize.core.journal_reader import JournalQuery
from suize.models.host import Host
from suize.models.log_entry import LogEntry
from suize.ui import prompts
from suize.ui.pager import paged
from suize.ui.render_logs import build_live_line, render_logs
from suize.ui.render_nmap import render_correlations, render_hosts
from suize.ui.theme import APP_NAME, ICONS, TAGLINE, icon, icons_enabled, message
from suize.utils.deps import Dependency, is_systemd_running, systemd_hint
from suize.utils.permissions import (
    PermissionStatus,
    check_permissions,
    journal_hint,
    nmap_hint,
)
from suize.utils.shell import CommandError
from suize.utils.time_filter import TimeRange
from suize.utils.validators import is_loopback

ACTION_SCAN = "scan"
ACTION_LOGS = "logs"
ACTION_CORRELATE = "correlate"
ACTION_EXIT = "exit"

#: Errores esperables que se muestran al usuario sin traceback.
USER_ERRORS: tuple[type[Exception], ...] = (CommandError, ValueError, OSError)


@dataclass(slots=True)
class AppContext:
    """Todo lo que necesitan los flujos interactivos."""

    console: Console
    settings: Settings
    deps: Mapping[str, Dependency]
    permissions: PermissionStatus
    pager: bool = True
    #: Unidades systemd ya consultadas en esta sesión. Cada consulta lanza un
    #: proceso y devuelve la lista entera, y el menú la necesita dos veces: al
    #: autocompletar una unidad y al correlacionar. Se guarda la primera.
    _units: set[str] | None = field(default=None, repr=False)

    def has(self, *names: str) -> bool:
        """``True`` si todas las dependencias indicadas están instaladas."""
        return all((dep := self.deps.get(name)) is not None and dep.available for name in names)

    def system_units(self, *, timeout: float) -> set[str]:
        """Unidades del sistema, consultando ``systemctl`` una sola vez por sesión."""
        if self._units is None:
            self._units = correlator.list_system_services(timeout=timeout)
        return self._units


# --------------------------------------------------------------------------- avisos


def render_banner(console: Console) -> None:
    body = Text.assemble((f"{APP_NAME} v{__version__}", "title"), "\n", (TAGLINE, "muted"))
    console.print(Panel(body, border_style="cyan", expand=False, padding=(0, 2)))


def build_dependency_panel(missing: Sequence[Dependency]) -> Panel:
    lines: list[Text] = []
    for dep in missing:
        lines.append(
            message(
                "warning",
                f"{dep.name} no está instalado: se necesita para {dep.purpose}.",
            )
        )
        if dep.install_hint:
            lines.append(Text(f"   {dep.install_hint}", style="muted"))
    return Panel(Group(*lines), title="Dependencias", border_style="yellow", expand=False)


def render_startup_warnings(
    console: Console, deps: Mapping[str, Dependency], permissions: PermissionStatus
) -> None:
    """Avisos de arranque: dependencias ausentes y permisos (nunca aborta)."""
    missing = [dep for dep in deps.values() if not dep.available]
    if missing:
        console.print(build_dependency_panel(missing))
    journal = deps.get("journalctl")
    if journal is not None and journal.available:
        if not is_systemd_running():
            console.print(message("warning", systemd_hint()))
        elif hint := journal_hint(permissions):
            console.print(message("warning", hint))
    nmap = deps.get("nmap")
    if nmap is not None and nmap.available and (hint := nmap_hint(permissions)):
        console.print(message("info", hint))


# --------------------------------------------------------------------------- acciones


def root_required_hint(profile: str) -> str | None:
    """Mensaje si el perfil necesita privilegios y no los hay; ``None`` si todo bien.

    Nmap, sin root, se limita a decir "You requested a scan type which requires
    root privileges" y aborta. Se comprueba antes para poder decir además cómo
    resolverlo.
    """
    scan_profile = nmap_runner.SCAN_PROFILES.get(profile)
    if scan_profile is None or not scan_profile.requires_root:
        return None
    if check_permissions().is_root:
        return None
    return (
        f"El perfil '{profile}' necesita privilegios de root: Nmap no puede enviar "
        "paquetes UDP en crudo sin ellos. Repite el escaneo con sudo, indicando la "
        "ruta completa (p. ej. 'sudo ~/.local/bin/suize scan ... --profile udp'), "
        "porque sudo no hereda tu PATH."
    )


def execute_scan(
    status_console: Console,
    target: str,
    *,
    profile: str,
    timeout: float,
    save_xml: Path | None = None,
    skip_ping: bool = False,
) -> list[Host]:
    """Escanea con Nmap (mostrando un spinner) y devuelve los hosts parseados."""
    with status_console.status(f"Escaneando {target} con Nmap… (Ctrl+C para cancelar)"):
        xml_text = nmap_runner.run_scan(
            target,
            profile=profile,
            timeout=timeout,
            save_xml_to=save_xml,
            skip_ping=skip_ping,
        )
    return nmap_parser.parse_nmap_xml(xml_text)


#: Sugerencia cuando el descubrimiento de hosts no encuentra nada.
SKIP_PING_HINT = (
    "Ningún host respondió a las pruebas de descubrimiento. Si sabes que está encendido, "
    "puede estar bloqueándolas (típico del cortafuegos de Windows): reintenta con -Pn."
)


#: A partir de cuántos hosts un escaneo sin descubrimiento se vuelve costoso.
#: Un /22 son 1024 direcciones; por debajo, la espera sigue siendo tolerable.
LARGE_NETWORK_HOSTS = 1024


def large_network_warning(target: str, *, skip_ping: bool) -> str | None:
    """Aviso si se pide ``-Pn`` sobre una red grande; ``None`` si no procede.

    Sin descubrimiento, Nmap no descarta ninguna dirección: prueba todos los
    puertos de todas ellas, aunque no exista nadie. El coste se multiplica por
    el número de direcciones del rango, así que conviene decirlo antes.
    """
    if not skip_ping or "/" not in target:
        return None
    try:
        network = ipaddress.ip_network(target.strip(), strict=False)
    except ValueError:
        return None
    if network.num_addresses < LARGE_NETWORK_HOSTS:
        return None
    return (
        f"-Pn sobre {target} son {network.num_addresses} direcciones, y sin descubrimiento "
        "Nmap prueba los puertos de todas, existan o no. Puede tardar horas: considera "
        "acotar el rango o usar --profile fast."
    )


def nothing_responded(hosts: Sequence[Host]) -> bool:
    """``True`` si Nmap no devolvió hosts o todos figuran como caídos."""
    return not any(host.is_up for host in hosts)


def correlation_tables(settings: Settings) -> correlator.CorrelationTables:
    """Traduce la configuración a las tablas que usa el correlador."""
    return correlator.CorrelationTables(
        ports=settings.correlation_ports,
        services=settings.correlation_services,
    )


def find_correlations(
    status_console: Console,
    hosts: Sequence[Host],
    *,
    timeout: float,
    tables: correlator.CorrelationTables,
    units_provider: Callable[..., set[str]] | None = None,
) -> list[Correlation]:
    """Correlaciona los puertos abiertos con las unidades systemd del sistema.

    ``units_provider`` permite reutilizar una consulta ya hecha (la caché del
    menú); sin él se consulta ``systemctl`` directamente, que es lo que hace el
    subcomando, donde no hay nada que reaprovechar.
    """
    with status_console.status("Buscando unidades systemd…"):
        services = (
            units_provider(timeout=timeout)
            if units_provider is not None
            else correlator.list_system_services(timeout=timeout)
        )
    return correlator.correlate(hosts, services, tables)


def execute_logs(status_console: Console, query: JournalQuery, *, timeout: float) -> list[LogEntry]:
    """Consulta journalctl (mostrando un spinner) y devuelve las entradas parseadas."""
    with status_console.status("Consultando journalctl…"):
        raw = journal_reader.read_journal(query, timeout=timeout)
    return journal_parser.parse_journal_json(raw)


#: Lo que se imprime al empezar a seguir el journal.
FOLLOW_BANNER = "Siguiendo el journal. Ctrl+C para parar."


def follow_logs(
    console: Console,
    err: Console,
    query: JournalQuery,
    *,
    quiet: bool = False,
) -> int:
    """Sigue el journal en vivo hasta que el usuario corta con Ctrl+C.

    Devuelve el código de salida que usará ``cli``: 0 si se paró con Ctrl+C (es la
    forma normal de terminar, no un error) y 1 si journalctl falló.
    """
    if not quiet:
        err.print(message("info", FOLLOW_BANNER))
    seen = 0
    try:
        for entry in journal_reader.follow_journal(query):
            console.print(build_live_line(entry))
            seen += 1
    except KeyboardInterrupt:
        # Salida esperada: el seguimiento no termina de ninguna otra forma.
        pass
    except USER_ERRORS as exc:
        err.print(message("error", str(exc)))
        return 1
    if not quiet:
        err.print(message("info", f"Seguimiento detenido ({seen} entradas)."))
    return 0


def show_logs(
    console: Console,
    entries: Sequence[LogEntry],
    *,
    settings: Settings,
    permissions: PermissionStatus,
    time_range: TimeRange | None,
    title: str,
    limit: int | None,
) -> None:
    render_logs(
        console,
        entries,
        time_range=time_range,
        title=title,
        limit=limit,
        top_units=settings.top_units,
        empty_hint=journal_hint(permissions),
    )


# --------------------------------------------------------------------------- flujos


#: Aviso cuando se correlaciona un objetivo que no es esta máquina.
REMOTE_CORRELATION_WARNING = (
    "Los logs que se muestran son los de ESTA máquina. Si el objetivo es otro equipo, "
    "la correlación solo es orientativa."
)


def _scan_step(ctx: AppContext) -> tuple[str, list[Host]]:
    target = prompts.ask_target(ctx.settings.default_target)
    profile = prompts.ask_scan_profile(nmap_runner.SCAN_PROFILES, ctx.settings.scan_profile)
    if (hint := root_required_hint(profile)) is not None:
        # En el menú no se puede reintentar con sudo por su cuenta: se explica y se vuelve.
        ctx.console.print(message("error", hint))
        raise prompts.Cancelled
    hosts = execute_scan(ctx.console, target, profile=profile, timeout=ctx.settings.scan_timeout)
    with paged(ctx.console, enabled=ctx.pager):
        render_hosts(ctx.console, hosts, target=target)

    # En vez de preguntar por -Pn en cada escaneo, se ofrece solo cuando hace falta.
    if nothing_responded(hosts):
        ctx.console.print(message("warning", SKIP_PING_HINT))
        if prompts.confirm("¿Reintentar sin descubrimiento de hosts (-Pn)?", default=True):
            hosts = execute_scan(
                ctx.console,
                target,
                profile=profile,
                timeout=ctx.settings.scan_timeout,
                skip_ping=True,
            )
            with paged(ctx.console, enabled=ctx.pager):
                render_hosts(ctx.console, hosts, target=target)
    return target, hosts


def _correlation_step(ctx: AppContext, target: str, hosts: Sequence[Host]) -> None:
    if not is_loopback(target):
        ctx.console.print(message("warning", REMOTE_CORRELATION_WARNING))
    correlations = find_correlations(
        ctx.console,
        hosts,
        timeout=ctx.settings.journal_timeout,
        tables=correlation_tables(ctx.settings),
        units_provider=ctx.system_units,
    )
    with paged(ctx.console, enabled=ctx.pager):
        render_correlations(ctx.console, correlations)
    units = correlator.units_to_query(correlations)
    if not units:
        ctx.console.print(
            message("info", "Ninguna unidad systemd de este sistema coincide con esos servicios.")
        )
        return
    time_range = prompts.ask_time_range(ctx.settings.time_presets, ctx.settings.default_time_preset)
    query = JournalQuery(units=tuple(units), time_range=time_range, lines=ctx.settings.log_lines)
    entries = execute_logs(ctx.console, query, timeout=ctx.settings.journal_timeout)
    with paged(ctx.console, enabled=ctx.pager):
        show_logs(
            ctx.console,
            entries,
            settings=ctx.settings,
            permissions=ctx.permissions,
            time_range=time_range,
            title=f"Logs de {', '.join(units)}",
            limit=query.lines,
        )


def scan_flow(ctx: AppContext) -> None:
    """🔍 Escanear host y, si hay puertos abiertos, ofrecer ver sus logs."""
    target, hosts = _scan_step(ctx)
    if not any(host.open_ports for host in hosts) or not ctx.has("journalctl", "systemctl"):
        return
    if prompts.confirm("¿Ver los logs de los servicios detectados?", default=False):
        _correlation_step(ctx, target, hosts)


def logs_flow(ctx: AppContext) -> None:
    """📋 Analizar logs con filtros combinables."""
    time_range = prompts.ask_time_range(ctx.settings.time_presets, ctx.settings.default_time_preset)
    priority = prompts.ask_priority()
    unit = prompts.ask_unit(_known_units(ctx))
    grep = prompts.ask_grep()
    lines = prompts.ask_lines(ctx.settings.log_lines)
    query = JournalQuery(
        units=(unit,) if unit else (),
        priority=priority,
        time_range=time_range,
        grep=grep,
        lines=lines,
    )
    entries = execute_logs(ctx.console, query, timeout=ctx.settings.journal_timeout)
    with paged(ctx.console, enabled=ctx.pager):
        show_logs(
            ctx.console,
            entries,
            settings=ctx.settings,
            permissions=ctx.permissions,
            time_range=time_range,
            title=f"Logs de {unit}" if unit else "Logs del sistema",
            limit=lines,
        )


def correlate_flow(ctx: AppContext) -> None:
    """🔗 Escanear y ver directamente los logs correlacionados."""
    target, hosts = _scan_step(ctx)
    if not any(host.open_ports for host in hosts):
        ctx.console.print(message("info", "No hay puertos abiertos que correlacionar."))
        return
    _correlation_step(ctx, target, hosts)


def _known_units(ctx: AppContext) -> list[str]:
    """Servicios del sistema para el autocompletado (lista vacía si no se pueden obtener)."""
    if not ctx.has("systemctl"):
        return []
    try:
        return sorted(ctx.system_units(timeout=10))
    except CommandError:
        return []


FLOWS: dict[str, Callable[[AppContext], None]] = {
    ACTION_SCAN: scan_flow,
    ACTION_LOGS: logs_flow,
    ACTION_CORRELATE: correlate_flow,
}


def _main_choices(ctx: AppContext) -> list[str | Choice]:
    def disabled(*names: str) -> str | None:
        absent = [name for name in names if not ctx.has(name)]
        return f"requiere {', '.join(absent)}" if absent else None

    return [
        Choice(
            f"{icon('scan')}Escanear host con Nmap", value=ACTION_SCAN, disabled=disabled("nmap")
        ),
        Choice(
            f"{icon('logs')}Analizar logs del sistema",
            value=ACTION_LOGS,
            disabled=disabled("journalctl"),
        ),
        Choice(
            f"{icon('correlate')}Escanear + ver logs correlacionados",
            value=ACTION_CORRELATE,
            disabled=disabled("nmap", "journalctl", "systemctl"),
        ),
        Choice(f"{icon('exit')}Salir", value=ACTION_EXIT),
    ]


def run_menu(ctx: AppContext) -> int:
    """Bucle del menú principal. Devuelve el código de salida."""
    render_banner(ctx.console)
    render_startup_warnings(ctx.console, ctx.deps, ctx.permissions)
    while True:
        try:
            action = prompts.select("¿Qué quieres hacer?", _main_choices(ctx))
        except prompts.Cancelled:
            break
        if action == ACTION_EXIT:
            break
        try:
            FLOWS[action](ctx)
        except (prompts.Cancelled, KeyboardInterrupt):
            ctx.console.print(Text("Operación cancelada.", style="muted"))
        except USER_ERRORS as exc:
            ctx.console.print(message("error", str(exc)))
        ctx.console.print()
    farewell = f"¡Hasta luego! {ICONS['bye']}" if icons_enabled() else "¡Hasta luego!"
    ctx.console.print(Text(farewell, style="muted"))
    return 0
