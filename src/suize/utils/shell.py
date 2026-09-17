"""Wrapper centralizado de ``subprocess``.

Todas las llamadas a programas externos (nmap, journalctl, systemctl) pasan por
:func:`run`, que:

* comprueba antes con :func:`shutil.which` que el ejecutable existe,
* nunca usa ``shell=True`` (los argumentos viajan como lista),
* aplica un *timeout*,
* y traduce cualquier fallo a :class:`CommandError` con un mensaje claro.

:func:`run` espera a que el programa termine. Para un proceso que no termina
por sí solo —``journalctl --follow``— está :func:`stream`, que va entregando
las líneas según llegan y se asegura de matar al hijo al salir.
"""

import shutil
import signal
import subprocess
import tempfile
from collections.abc import Collection, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass

DEFAULT_TIMEOUT = 60.0
_DETAIL_LIMIT = 600


class CommandError(Exception):
    """Fallo al ejecutar un comando externo: no encontrado, timeout o código inesperado."""

    def __init__(
        self,
        message: str,
        *,
        cmd: Sequence[str] = (),
        returncode: int | None = None,
        stderr: str = "",
    ) -> None:
        super().__init__(message)
        self.message = message
        self.cmd: tuple[str, ...] = tuple(cmd)
        self.returncode = returncode
        self.stderr = stderr


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Resultado de un comando ejecutado con :func:`run`."""

    cmd: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


def run(
    cmd: Sequence[str],
    *,
    timeout: float | None = DEFAULT_TIMEOUT,
    ok_codes: Collection[int] = (0,),
) -> CommandResult:
    """Ejecuta ``cmd`` y devuelve su salida capturada.

    Args:
        cmd: programa y argumentos. ``cmd[0]`` se resuelve con ``shutil.which``.
        timeout: segundos máximos de ejecución (``None`` = sin límite).
        ok_codes: códigos de salida que se consideran correctos.

    Raises:
        CommandError: si el programa no existe, excede el timeout, no puede
            lanzarse o termina con un código fuera de ``ok_codes``.
    """
    if not cmd:
        raise CommandError("No se indicó ningún comando para ejecutar.")
    program = cmd[0]
    executable = shutil.which(program)
    if executable is None:
        raise CommandError(
            f"No se encontró '{program}' en el PATH. Instálalo o revisa tu variable PATH.",
            cmd=cmd,
        )

    try:
        completed = subprocess.run(
            [executable, *cmd[1:]],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise CommandError(
            f"'{program}' superó el tiempo máximo de {exc.timeout:g} s y se canceló.", cmd=cmd
        ) from exc
    except OSError as exc:
        raise CommandError(
            f"No se pudo ejecutar '{program}': {exc.strerror or exc}", cmd=cmd
        ) from exc

    result = CommandResult(
        cmd=tuple(cmd),
        returncode=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
    )
    if result.returncode not in ok_codes:
        detail = _tail(result.stderr) or _tail(result.stdout) or "sin mensajes de error"
        raise CommandError(
            f"'{program}' terminó con código {result.returncode}: {detail}",
            cmd=cmd,
            returncode=result.returncode,
            stderr=result.stderr,
        )
    return result


#: Margen para que el proceso hijo termine por las buenas antes de matarlo.
_KILL_GRACE = 3.0


def _resolve(cmd: Sequence[str]) -> tuple[str, str]:
    """Comprueba el comando y devuelve ``(programa, ruta ejecutable)``."""
    if not cmd:
        raise CommandError("No se indicó ningún comando para ejecutar.")
    program = cmd[0]
    executable = shutil.which(program)
    if executable is None:
        raise CommandError(
            f"No se encontró '{program}' en el PATH. Instálalo o revisa tu variable PATH.",
            cmd=cmd,
        )
    return program, executable


@contextmanager
def _terminating(process: "subprocess.Popen[str]") -> Iterator[None]:
    """Garantiza que el hijo muere al salir del bloque, pase lo que pase.

    Sin esto, un Ctrl+C dejaría un journalctl huérfano escribiendo en una
    tubería que ya nadie lee.
    """
    try:
        yield
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=_KILL_GRACE)
            except subprocess.TimeoutExpired:
                # No atendió al SIGTERM: no queda otra que SIGKILL.
                process.kill()
                process.wait()
        if process.stdout is not None:
            process.stdout.close()


def stream(cmd: Sequence[str]) -> Iterator[str]:
    """Ejecuta ``cmd`` y va entregando sus líneas de salida según llegan.

    Pensado para procesos que no terminan solos (``journalctl --follow``): no
    hay *timeout*, porque el final lo decide quien consume el generador, con un
    ``break`` o un Ctrl+C. Al salir del bucle, por la razón que sea, el proceso
    hijo se termina.

    El hijo se lanza en su propio grupo de procesos para que el Ctrl+C de la
    terminal llegue solo a Suize: así se decide aquí cómo y cuándo pararlo, en
    vez de que el hijo muera por su cuenta a mitad de una línea.

    ``stderr`` va a un archivo temporal, no a una tubería. Con una tubería que
    nadie lee, el hijo se bloquea en cuanto llena su búfer (unos 64 KB) y el
    seguimiento se cuelga sin dar ningún error: un journal corrupto o una
    rotación bastan para provocarlo. El archivo, además, permite explicar por
    qué falló el programa si termina mal.

    Raises:
        CommandError: si el programa no existe, no puede lanzarse, o termina
            con un código distinto de cero.
    """
    program, executable = _resolve(cmd)
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8", errors="replace") as errors:
        try:
            process = subprocess.Popen(
                [executable, *cmd[1:]],
                stdout=subprocess.PIPE,
                stderr=errors,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,  # por líneas: sin esto la salida llegaría a bloques
                start_new_session=True,
            )
        except OSError as exc:
            raise CommandError(
                f"No se pudo ejecutar '{program}': {exc.strerror or exc}", cmd=cmd
            ) from exc

        completed = False
        with _terminating(process):
            assert process.stdout is not None
            for line in process.stdout:
                text = line.rstrip("\n")
                if text:
                    yield text
            completed = True

        # Solo se comprueba el resultado si la salida se agotó por su cuenta: si
        # quien consume cortó el bucle, el proceso murió por orden nuestra y su
        # código de salida no dice nada útil.
        if completed and process.returncode:
            errors.seek(0)
            detail = _tail(errors.read()) or "sin mensajes de error"
            raise CommandError(
                f"'{program}' terminó con código {process.returncode}: {detail}",
                cmd=cmd,
                returncode=process.returncode,
            )


def interrupt_signal() -> int:
    """La señal con la que se pide a un hijo que pare (útil en los tests)."""
    return signal.SIGTERM


def _tail(text: str, limit: int = _DETAIL_LIMIT) -> str:
    """Últimos ``limit`` caracteres de ``text`` (los errores suelen estar al final)."""
    text = text.strip()
    return text if len(text) <= limit else "…" + text[-limit:]
