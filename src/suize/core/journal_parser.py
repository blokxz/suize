"""Parser de ``journalctl -o json`` a dataclasses :class:`LogEntry` / :class:`LogSummary`.

No imprime nada ni ejecuta procesos: recibe texto o una ruta y devuelve modelos.
"""

import json
from collections.abc import Iterable, Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from suize.models.log_entry import DEFAULT_PRIORITY, LogEntry, LogSummary

UNKNOWN_UNIT = "desconocido"


class JournalParseError(ValueError):
    """Una línea no es JSON válido (solo en modo ``strict``)."""


def parse_journal_json(text: str, *, strict: bool = False) -> list[LogEntry]:
    """Parsea la salida de ``journalctl -o json`` (un objeto JSON por línea).

    También acepta un array JSON (``[{...}, {...}]``). Las líneas vacías se ignoran;
    las inválidas se descartan salvo con ``strict=True``, que lanza
    :class:`JournalParseError`.
    """
    stripped = text.strip()
    if not stripped:
        return []
    if stripped.startswith("["):
        try:
            records = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise JournalParseError(f"Array JSON inválido: {exc.msg}.") from exc
        return _entries_from_records(records if isinstance(records, list) else [], strict)

    records_from_lines: list[Any] = []
    for lineno, raw_line in enumerate(stripped.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            records_from_lines.append(json.loads(line))
        except json.JSONDecodeError as exc:
            if strict:
                raise JournalParseError(f"Línea {lineno}: JSON inválido ({exc.msg}).") from exc
    return _entries_from_records(records_from_lines, strict)


def parse_line(line: str) -> LogEntry | None:
    """Parsea una sola línea de ``journalctl -o json``.

    Devuelve ``None`` si la línea está vacía, no es JSON válido o no tiene una
    fecha utilizable. Es la entrada que usa el seguimiento en vivo, donde cada
    línea llega suelta y no se puede esperar al final de la salida.
    """
    text = line.strip()
    if not text:
        return None
    try:
        record = json.loads(text)
    except json.JSONDecodeError:
        return None
    return parse_record(record) if isinstance(record, Mapping) else None


def parse_journal_file(path: Path | str, *, strict: bool = False) -> list[LogEntry]:
    """Igual que :func:`parse_journal_json` pero leyendo desde un archivo."""
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise JournalParseError(f"No se pudo leer {path}: {exc.strerror or exc}") from exc
    return parse_journal_json(text, strict=strict)


def parse_record(record: Mapping[str, Any]) -> LogEntry | None:
    """Convierte un objeto del journal en :class:`LogEntry` (``None`` si no tiene fecha válida)."""
    try:
        micros = int(_as_text(record.get("__REALTIME_TIMESTAMP")))
        # El journal guarda microsegundos desde la época Unix.
        timestamp = datetime.fromtimestamp(micros / 1_000_000)
    except (ValueError, OverflowError, OSError):
        return None

    unit = (
        _as_text(record.get("_SYSTEMD_UNIT"))
        or _as_text(record.get("SYSLOG_IDENTIFIER"))
        or _as_text(record.get("_COMM"))
        or UNKNOWN_UNIT
    )
    return LogEntry(
        timestamp=timestamp,
        priority=_as_priority(record.get("PRIORITY")),
        unit=unit,
        message=_as_text(record.get("MESSAGE")).rstrip(),
        hostname=_as_text(record.get("_HOSTNAME")),
        pid=_as_int(record.get("_PID")),
    )


def summarize(entries: Iterable[LogEntry], top_n: int = 5) -> LogSummary:
    """Atajo de :meth:`LogSummary.from_entries`."""
    return LogSummary.from_entries(entries, top_n=top_n)


# --------------------------------------------------------------------------- internos


def _entries_from_records(records: Iterable[Any], strict: bool) -> list[LogEntry]:
    entries: list[LogEntry] = []
    for index, record in enumerate(records, start=1):
        if not isinstance(record, Mapping):
            if strict:
                raise JournalParseError(f"Registro {index}: se esperaba un objeto JSON.")
            continue
        entry = parse_record(record)
        if entry is not None:
            entries.append(entry)
    return entries


def _as_text(value: object) -> str:
    """Normaliza un campo del journal a texto.

    journalctl representa los campos no UTF-8 o binarios como listas de bytes
    (``[72, 111, ...]``) y los campos repetidos como listas de valores.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        if value and all(isinstance(item, int) and 0 <= item <= 255 for item in value):
            return bytes(value).decode("utf-8", errors="replace")
        return _as_text(value[0]) if value else ""
    return str(value)


def _as_int(value: object) -> int | None:
    try:
        return int(_as_text(value))
    except ValueError:
        return None


def _as_priority(value: object) -> int:
    number = _as_int(value)
    if number is None:
        return DEFAULT_PRIORITY
    return min(max(number, 0), 7)
