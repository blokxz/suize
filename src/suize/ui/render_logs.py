"""Tablas Rich para logs del journal y su resumen."""

from collections.abc import Sequence

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from suize.models.log_entry import LogEntry, LogSummary
from suize.ui.theme import (
    TIMESTAMP_FORMAT,
    icon,
    message,
    priority_label,
    priority_style,
)
from suize.utils.time_filter import TimeRange

_BAR_WIDTH = 24


def build_summary_panel(summary: LogSummary, *, time_range: TimeRange | None = None) -> Panel:
    """Panel con total, rango, conteo por prioridad (con barras) y top de unidades."""
    header = Text.assemble(("Total: ", "bold"), (f"{summary.total} entradas", "title"))
    if summary.first and summary.last:
        header.append(
            f"   ·   {summary.first.strftime(TIMESTAMP_FORMAT)} → "
            f"{summary.last.strftime(TIMESTAMP_FORMAT)}",
            style="muted",
        )
    if time_range is not None:
        header.append(f"\nFiltro temporal: {time_range.describe()}", style="muted")

    priorities = Table(box=None, show_header=True, header_style="bold", pad_edge=False)
    priorities.add_column("Prioridad")
    priorities.add_column("Nº", justify="right")
    priorities.add_column("")
    highest = max(summary.by_priority.values(), default=1)
    for level, count in summary.by_priority.items():
        style = priority_style(level)
        bar = "█" * max(1, round(count / highest * _BAR_WIDTH))
        priorities.add_row(
            Text(f" {priority_label(level)} ", style=style),
            str(count),
            Text(bar, style=style.replace("on red", "").strip() or "white"),
        )

    units = Table(box=None, show_header=True, header_style="bold", pad_edge=False)
    units.add_column("Top unidades")
    units.add_column("Nº", justify="right")
    for unit, count in summary.top_units:
        units.add_row(Text(unit, style="accent"), str(count))

    grid = Table.grid(padding=(0, 4))
    grid.add_row(priorities, units)
    return Panel(Group(header, Text(""), grid), title="Resumen", border_style="cyan", expand=False)


def build_live_line(entry: LogEntry) -> Text:
    """Una entrada como línea suelta, para el seguimiento en vivo.

    En vivo no cabe una tabla: no se sabe de antemano cuántas entradas habrá ni
    cuánto ocupará cada columna, y redibujarla en cada línea haría parpadear la
    pantalla. Se imprime una línea por entrada, como hace journalctl.
    """
    style = priority_style(entry.priority)
    message_style = style if entry.priority <= 4 or entry.priority == 7 else ""
    return Text.assemble(
        (entry.timestamp.strftime(TIMESTAMP_FORMAT), "muted"),
        "  ",
        (f"{priority_label(entry.priority):<8}", style),
        (f"{entry.unit or '-'}  ", "muted"),
        (entry.message, message_style),
    )


def build_logs_table(entries: Sequence[LogEntry], *, title: str = "", caption: str = "") -> Table:
    """Tabla de entradas coloreadas según su prioridad."""
    table = Table(
        title=title or None,
        title_justify="left",
        caption=caption or None,
        caption_justify="left",
        box=box.SIMPLE_HEAD,
        header_style="bold",
        expand=True,
    )
    table.add_column("Fecha y hora", no_wrap=True, style="muted")
    table.add_column("Prioridad", no_wrap=True)
    table.add_column("Unidad", no_wrap=True, max_width=24, overflow="ellipsis")
    table.add_column("Mensaje", overflow="fold", ratio=1)
    for entry in entries:
        style = priority_style(entry.priority)
        # Los mensajes graves (0-4) y los de debug (7) heredan el color; info/notice
        # quedan en el color normal para que la tabla sea legible.
        message_style = style if entry.priority <= 4 or entry.priority == 7 else ""
        table.add_row(
            entry.timestamp.strftime(TIMESTAMP_FORMAT),
            Text(f" {priority_label(entry.priority)} ", style=style),
            Text(entry.unit, style="accent"),
            Text(entry.message, style=message_style),  # Text: nunca se interpreta markup
        )
    return table


def render_logs(
    console: Console,
    entries: Sequence[LogEntry],
    *,
    summary: LogSummary | None = None,
    time_range: TimeRange | None = None,
    title: str = "Logs del sistema",
    limit: int | None = None,
    top_units: int = 5,
    empty_hint: str | None = None,
) -> None:
    """Muestra el resumen y, a continuación, la tabla de entradas."""
    if not entries:
        console.print(message("warning", "No hay entradas de log para esos filtros."))
        if empty_hint:
            console.print(message("info", empty_hint))
        return
    summary = summary or LogSummary.from_entries(entries, top_n=top_units)
    console.print(build_summary_panel(summary, time_range=time_range))
    caption = ""
    if limit is not None and len(entries) >= limit:
        caption = f"Mostrando las últimas {limit} entradas (límite configurado)."
    console.print(build_logs_table(entries, title=f"{icon('logs')}{title}", caption=caption))
