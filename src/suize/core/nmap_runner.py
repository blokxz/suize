"""Ejecución de Nmap: construye el comando, lo lanza y devuelve el XML generado."""

import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from suize.utils import shell
from suize.utils.validators import (
    Resolver,
    is_hostname_target,
    is_ipv6_target,
    resolves_only_to_ipv6,
    validate_target,
)

NMAP_BINARY = "nmap"
DEFAULT_SCAN_TIMEOUT = 600.0


@dataclass(frozen=True, slots=True)
class ScanProfile:
    """Argumentos extra de Nmap agrupados bajo un nombre."""

    name: str
    args: tuple[str, ...]
    description: str
    #: Nmap rechaza algunas técnicas sin privilegios. Es un dato del perfil, no
    #: una comprobación: quién mira si hay root es la capa que lo va a ejecutar,
    #: para que construir el comando siga sin depender del estado del proceso.
    requires_root: bool = False


SCAN_PROFILES: dict[str, ScanProfile] = {
    "fast": ScanProfile("fast", ("-F",), "Rápido: los 100 puertos más comunes"),
    "standard": ScanProfile("standard", (), "Estándar: los 1000 puertos más comunes"),
    "full": ScanProfile("full", ("-p-",), "Completo: los 65535 puertos TCP (lento)"),
    "udp": ScanProfile(
        "udp",
        ("-sU", "-F"),
        "UDP: los 100 puertos UDP más comunes (requiere root, muy lento)",
        requires_root=True,
    ),
}
DEFAULT_PROFILE = "standard"


def build_command(
    target: str,
    xml_path: Path,
    *,
    profile: str = DEFAULT_PROFILE,
    extra_args: Sequence[str] = (),
    force_ipv6: bool = False,
    skip_ping: bool = False,
) -> list[str]:
    """Construye ``nmap [-6] -sV [perfil] -oX <archivo> <target>``.

    El objetivo se valida antes para impedir que un valor como ``-iL /etc/shadow``
    llegue a Nmap como opción (inyección de argumentos).

    ``-6`` se añade cuando el objetivo es una dirección o red IPv6 literal, o cuando
    ``force_ipv6`` lo indica. ``skip_ping`` añade ``-Pn``, que omite el descubrimiento
    de hosts y escanea los puertos aunque el equipo no responda a las pruebas previas.

    Esta función no consulta el DNS: quien decide sobre un
    nombre de host es :func:`needs_ipv6`, para que construir el comando siga siendo
    una operación pura y comprobable sin red.

    Raises:
        ValueError: si el objetivo o el perfil no son válidos.
    """
    clean_target = validate_target(target)
    try:
        scan_profile = SCAN_PROFILES[profile]
    except KeyError:
        valid = ", ".join(SCAN_PROFILES)
        raise ValueError(
            f"Perfil de escaneo desconocido: '{profile}'. Opciones: {valid}."
        ) from None
    return [
        NMAP_BINARY,
        # Nmap solo acepta objetivos IPv6 si se le pide explícitamente con -6.
        *(["-6"] if force_ipv6 or is_ipv6_target(clean_target) else []),
        # -Pn da por activo todo objetivo y va directo a los puertos.
        *(["-Pn"] if skip_ping else []),
        "-sV",
        *scan_profile.args,
        *extra_args,
        "-oX",
        str(xml_path),
        clean_target,
    ]


def needs_ipv6(target: str, *, resolver: Resolver | None = None) -> bool:
    """``True`` si hay que pasarle ``-6`` a Nmap para este objetivo.

    Resuelve el nombre solo cuando hace falta: una IP, una red o un rango se
    deciden sin tocar el DNS. ``resolver`` existe para inyectar un doble en los
    tests.
    """
    clean_target = target.strip()
    if is_ipv6_target(clean_target):
        return True
    if not is_hostname_target(clean_target):
        return False
    return resolves_only_to_ipv6(clean_target, resolver=resolver)


def run_scan(
    target: str,
    *,
    profile: str = DEFAULT_PROFILE,
    timeout: float = DEFAULT_SCAN_TIMEOUT,
    extra_args: Sequence[str] = (),
    save_xml_to: Path | None = None,
    skip_ping: bool = False,
) -> str:
    """Ejecuta Nmap sobre ``target`` y devuelve el XML de resultados como texto.

    El XML se escribe en un directorio temporal que se borra al terminar; si se pasa
    ``save_xml_to`` también se guarda una copia ahí.

    Raises:
        ValueError: objetivo o perfil inválidos.
        CommandError: Nmap no está instalado, falla, excede el timeout o no genera XML.
        OSError: no se pudo escribir ``save_xml_to``.
    """
    with tempfile.TemporaryDirectory(prefix="suize-nmap-") as tmp:
        xml_path = Path(tmp) / "scan.xml"
        cmd = build_command(
            target,
            xml_path,
            profile=profile,
            extra_args=extra_args,
            force_ipv6=needs_ipv6(target),
            skip_ping=skip_ping,
        )
        shell.run(cmd, timeout=timeout)
        if not xml_path.is_file() or xml_path.stat().st_size == 0:
            raise shell.CommandError(
                "Nmap terminó sin generar el archivo XML de resultados.", cmd=cmd
            )
        xml_text = xml_path.read_text(encoding="utf-8", errors="replace")
    if save_xml_to is not None:
        save_xml_to.write_text(xml_text, encoding="utf-8")
    return xml_text
