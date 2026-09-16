"""Consulta a journalctl con filtros combinables.

:func:`read_journal` hace una consulta puntual y devuelve toda la salida.
:func:`follow_journal` deja journalctl abierto y va entregando cada entrada
según se escribe en el journal.
"""

from collections.abc import Iterator
from dataclasses import dataclass

from suize.core.journal_parser import parse_line
from suize.models.log_entry import LogEntry
from suize.utils import shell
from suize.utils.time_filter import TimeRange
from suize.utils.validators import parse_priority, validate_unit

JOURNALCTL_BINARY = "journalctl"
DEFAULT_JOURNAL_TIMEOUT = 60.0


@dataclass(frozen=True, slots=True)
class JournalQuery:
    """Filtros de una consulta; los que quedan vacíos simplemente no se aplican."""

    units: tuple[str, ...] = ()
    priority: str | None = None
    time_range: TimeRange | None = None
    grep: str | None = None
    lines: int | None = 200


def build_command(query: JournalQuery) -> list[str]:
    """Traduce una :class:`JournalQuery` a argumentos de journalctl.

    Equivalencias: ``--output=json`` (``-o json``), ``--unit`` (``-u``),
    ``--priority`` (``-p``), ``--since``/``--until``, ``--grep`` y ``--lines`` (``-n``).
    Se usa siempre la forma ``--opcion=valor`` para que un valor nunca pueda
    confundirse con otra opción. ``--quiet`` suprime avisos informativos (los permisos
    se comprueban aparte en ``utils.permissions``) y ``--no-pager`` evita abrir ``less``.

    Raises:
        ValueError: unidad, prioridad o número de líneas inválidos.
    """
    cmd = [JOURNALCTL_BINARY, "--output=json", "--no-pager", "--quiet"]
    cmd.extend(f"--unit={validate_unit(unit)}" for unit in query.units)
    if query.priority:
        cmd.append(f"--priority={parse_priority(query.priority)}")
    if query.time_range is not None:
        cmd.extend(query.time_range.to_journalctl_args())
    if query.grep:
        cmd.append(f"--grep={query.grep}")
    if query.lines is not None:
        if query.lines <= 0:
            raise ValueError("El número de líneas debe ser mayor que 0.")
        cmd.append(f"--lines={query.lines}")
    return cmd


def build_follow_command(query: JournalQuery) -> list[str]:
    """Como :func:`build_command`, más ``--follow``.

    Un rango temporal con final (``--until``) no tiene sentido siguiendo el
    journal en vivo: journalctl se pararía al alcanzarlo. Se conserva el
    ``--since``, que sí sirve para arrancar mostrando lo reciente.
    """
    cmd = build_command(query)
    return [*cmd, "--follow"]


def follow_journal(query: JournalQuery) -> Iterator[LogEntry]:
    """Entrega cada entrada del journal según aparece, sin fin.

    El bucle solo termina cuando quien consume el generador lo corta (un
    ``break`` o un Ctrl+C), o si journalctl muere por su cuenta. Las líneas que
    no se pueden interpretar se descartan en silencio: en vivo no hay a quién
    informar del error sin ensuciar la pantalla, y una línea suelta corrupta no
    justifica cortar el seguimiento.

    Raises:
        ValueError: filtros inválidos.
        CommandError: journalctl no existe o no puede lanzarse.
    """
    for line in shell.stream(build_follow_command(query)):
        entry = parse_line(line)
        if entry is not None:
            yield entry


def read_journal(query: JournalQuery, *, timeout: float = DEFAULT_JOURNAL_TIMEOUT) -> str:
    """Ejecuta journalctl y devuelve su salida (un objeto JSON por línea).

    Raises:
        ValueError: filtros inválidos.
        CommandError: journalctl no existe, falla o excede el timeout.
    """
    cmd = build_command(query)
    result = shell.run(cmd, timeout=timeout, ok_codes=(0, 1))
    if result.returncode == 0:
        return result.stdout
    # Con --grep, journalctl sale con 1 si no hay coincidencias (igual que grep).
    if not result.stdout.strip() and not result.stderr.strip():
        return ""
    detail = result.stderr.strip() or "error desconocido"
    if "pattern matching" in detail.lower() or "pcre" in detail.lower():
        detail += " (esta build de journalctl no soporta --grep: filtra por unidad o prioridad)"
    raise shell.CommandError(
        f"journalctl terminó con código 1: {detail}", cmd=cmd, returncode=1, stderr=result.stderr
    )
