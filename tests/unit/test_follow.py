"""Tests del seguimiento del journal en vivo (``--follow``).

La parte delicada es :func:`suize.utils.shell.stream`: un proceso que no
termina solo. Se prueba con procesos reales y cortos (el propio intérprete de
Python), no con dobles, porque lo que interesa comprobar es justo lo que un
doble no reproduce: que el hijo muere cuando se corta el bucle.
"""

import sys
import time
from datetime import datetime
from pathlib import Path

import pytest

from suize.core import journal_reader
from suize.core.journal_parser import parse_line
from suize.core.journal_reader import JournalQuery, build_follow_command, follow_journal
from suize.models.log_entry import LogEntry
from suize.ui.render_logs import build_live_line
from suize.utils import shell
from suize.utils.shell import CommandError, stream


def _python(script: str) -> list[str]:
    """Comando que ejecuta un script corto con el intérprete actual.

    Se usa la ruta absoluta de ``sys.executable``, no su nombre: dentro de un
    entorno virtual el ejecutable se llama ``python``, que no tiene por qué
    estar en el PATH si el entorno no está activado (es justo lo que hace
    ``scripts/lint.sh``, que invoca ``.venv/bin/python`` directamente).
    """
    return [sys.executable, "-c", script]


# ------------------------------------------------------------------------- shell.stream


def test_lines_arrive_one_by_one() -> None:
    lines = list(stream(_python("print('uno'); print('dos'); print('tres')")))

    assert lines == ["uno", "dos", "tres"]


def test_blank_lines_are_skipped() -> None:
    """Una línea vacía no es una entrada de log: no debe llegar al parser."""
    lines = list(stream(_python("print('a'); print(''); print('b')")))

    assert lines == ["a", "b"]


def test_output_arrives_before_the_process_ends() -> None:
    """Lo que distingue a stream() de run(): no espera al final para entregar.

    El hijo escribe una línea, espera, y escribiría una segunda. Si stream()
    esperase a que terminara, la primera línea no llegaría hasta pasada la
    espera completa.
    """
    script = (
        "import sys, time\n"
        "print('primera', flush=True)\n"
        "time.sleep(30)\n"
        "print('segunda', flush=True)\n"
    )
    inicio = time.monotonic()

    for line in stream(_python(script)):
        assert line == "primera"
        break  # corta el seguimiento, como haría un Ctrl+C

    assert time.monotonic() - inicio < 10, "la primera línea debería llegar sin esperar al final"


def test_the_child_is_killed_when_the_loop_is_cut(tmp_path: Path) -> None:
    """Sin esto quedaría un journalctl huérfano escribiendo a una tubería muerta."""
    testigo = tmp_path / "siguio-vivo.txt"
    script = (
        "import time, pathlib\n"
        "print('arranco', flush=True)\n"
        "time.sleep(3)\n"
        f"pathlib.Path({str(testigo)!r}).write_text('el hijo sobrevivió')\n"
    )

    for _ in stream(_python(script)):
        break

    time.sleep(4)  # más que el sleep del hijo
    assert not testigo.exists(), "el proceso hijo siguió vivo tras cortar el bucle"


def test_a_missing_program_is_reported() -> None:
    with pytest.raises(CommandError, match="No se encontró"):
        list(stream(["no-existe-este-programa-xyz"]))


def test_an_empty_command_is_rejected() -> None:
    with pytest.raises(CommandError, match="ningún comando"):
        list(stream([]))


def test_the_child_runs_in_its_own_session() -> None:
    """El Ctrl+C de la terminal debe llegar a Suize, no matar al hijo a media línea."""
    script = "import os; print(os.getpid() == os.getsid(0))"

    assert list(stream(_python(script))) == ["True"]


def test_a_failing_program_does_not_raise_by_itself() -> None:
    """El seguimiento no interpreta el código de salida: solo entrega lo que llega."""
    lines = list(stream(_python("import sys; print('algo'); sys.exit(1)")))

    assert lines == ["algo"]


# ---------------------------------------------------------------------------- parse_line


def _record(**extra: object) -> str:
    import json

    base = {
        "__REALTIME_TIMESTAMP": "1768473000123456",
        "PRIORITY": "3",
        "_SYSTEMD_UNIT": "nginx.service",
        "MESSAGE": "bind() failed",
        "_HOSTNAME": "suize-lab",
    }
    return json.dumps({**base, **extra})


def test_a_valid_line_becomes_an_entry() -> None:
    entry = parse_line(_record())

    assert entry is not None
    assert entry.unit == "nginx.service"
    assert entry.priority == 3


@pytest.mark.parametrize(
    "line",
    ["", "   ", "\n", "no es json", "{roto", "[1, 2, 3]", '"solo texto"', "null"],
)
def test_an_unusable_line_is_discarded(line: str) -> None:
    """En vivo, una línea corrupta se descarta: no justifica cortar el seguimiento."""
    assert parse_line(line) is None


def test_a_line_without_timestamp_is_discarded() -> None:
    import json

    assert parse_line(json.dumps({"MESSAGE": "sin fecha"})) is None


def test_trailing_whitespace_does_not_matter() -> None:
    assert parse_line(f"  {_record()}  \n") is not None


# -------------------------------------------------------------------- build_follow_command


def test_the_follow_flag_is_added() -> None:
    cmd = build_follow_command(JournalQuery())

    assert cmd[0] == "journalctl"
    assert "--follow" in cmd


def test_the_filters_are_kept() -> None:
    cmd = build_follow_command(JournalQuery(units=("ssh",), priority="3", grep="Failed"))

    assert "--unit=ssh" in cmd
    assert "--priority=3" in cmd
    assert "--grep=Failed" in cmd
    assert "--follow" in cmd


def test_the_json_output_is_kept() -> None:
    """Sin --output=json el parser no podría leer las líneas."""
    assert "--output=json" in build_follow_command(JournalQuery())


# ------------------------------------------------------------------------- follow_journal


def test_entries_are_yielded_as_lines_arrive(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(shell, "stream", lambda cmd: iter([_record(), _record(PRIORITY="6")]))
    monkeypatch.setattr(journal_reader.shell, "stream", lambda cmd: iter([_record()]))

    entries = list(follow_journal(JournalQuery()))

    assert len(entries) == 1
    assert entries[0].priority == 3


def test_unusable_lines_are_skipped_without_stopping(monkeypatch: pytest.MonkeyPatch) -> None:
    lines = ["basura", _record(), "", "{roto", _record(PRIORITY="6")]
    monkeypatch.setattr(journal_reader.shell, "stream", lambda cmd: iter(lines))

    entries = list(follow_journal(JournalQuery()))

    assert [entry.priority for entry in entries] == [3, 6]


def test_invalid_filters_are_rejected_before_launching(monkeypatch: pytest.MonkeyPatch) -> None:
    """Un filtro mal escrito debe fallar antes de abrir el proceso."""
    llamadas: list[object] = []
    monkeypatch.setattr(
        journal_reader.shell, "stream", lambda cmd: llamadas.append(cmd) or iter([])
    )

    with pytest.raises(ValueError, match="Prioridad inválida"):
        list(follow_journal(JournalQuery(priority="banana")))

    assert llamadas == []


# ------------------------------------------------------------------------ build_live_line


def _entry(**extra: object) -> LogEntry:
    base: dict[str, object] = {
        "timestamp": datetime(2026, 1, 15, 10, 31, 5),
        "priority": 3,
        "unit": "nginx.service",
        "message": "bind() failed",
        "hostname": "suize-lab",
        "pid": 1201,
    }
    return LogEntry(**{**base, **extra})  # type: ignore[arg-type]


def test_the_live_line_has_the_four_fields() -> None:
    line = str(build_live_line(_entry()))

    assert "2026-01-15 10:31:05" in line
    assert "ERR" in line
    assert "nginx.service" in line
    assert "bind() failed" in line


def test_an_entry_without_unit_shows_a_dash() -> None:
    assert "-" in str(build_live_line(_entry(unit="")))


def test_the_message_is_not_truncated() -> None:
    """En vivo no hay tabla que recorte: el mensaje va entero."""
    largo = "x" * 300

    assert largo in str(build_live_line(_entry(message=largo)))


def test_brackets_in_the_message_survive() -> None:
    """Un mensaje de nginx trae corchetes; no deben tomarse por marcado de rich."""
    assert "[emerg]" in str(build_live_line(_entry(message="[emerg] bind() failed")))
