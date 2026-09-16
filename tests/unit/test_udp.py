"""Tests del escaneo UDP.

El fixture ``udp_scan.xml`` es la salida de un ``nmap -sU -sV -F`` real contra
cuatro servicios UDP levantados a propósito. Incluye los dos estados que
importan en UDP: ``open`` cuando el servicio contesta y ``open|filtered``
cuando no, que es el resultado más habitual y la diferencia principal con TCP.
"""

from pathlib import Path

import pytest

from suize.core.nmap_parser import parse_nmap_file
from suize.core.nmap_runner import SCAN_PROFILES, build_command
from suize.models.host import Host
from suize.ui import menus
from suize.utils.permissions import PermissionStatus

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "udp_scan.xml"
XML = Path("/tmp/scan.xml")


# ------------------------------------------------------------------------------- perfil


def test_the_udp_profile_exists() -> None:
    assert "udp" in SCAN_PROFILES


def test_the_udp_profile_asks_nmap_for_a_udp_scan() -> None:
    cmd = build_command("127.0.0.1", XML, profile="udp")

    assert "-sU" in cmd


def test_the_udp_profile_limits_the_ports() -> None:
    """Sin -F serían 1000 puertos UDP, que tardan una eternidad."""
    assert "-F" in build_command("127.0.0.1", XML, profile="udp")


def test_version_detection_is_kept() -> None:
    assert "-sV" in build_command("127.0.0.1", XML, profile="udp")


def test_only_the_udp_profile_requires_root() -> None:
    assert SCAN_PROFILES["udp"].requires_root is True
    for name in ("fast", "standard", "full"):
        assert SCAN_PROFILES[name].requires_root is False


def test_the_description_warns_about_root_and_speed() -> None:
    """La descripción es lo único que se ve al elegir perfil en el menú."""
    description = SCAN_PROFILES["udp"].description.lower()

    assert "root" in description
    assert "lento" in description


def test_the_udp_profile_combines_with_other_options() -> None:
    cmd = build_command("::1", XML, profile="udp", skip_ping=True)

    assert {"-6", "-Pn", "-sU"} <= set(cmd)


# ------------------------------------------------------------------------- privilegios


def _as_root(monkeypatch: pytest.MonkeyPatch, root: bool) -> None:
    monkeypatch.setattr(
        menus,
        "check_permissions",
        lambda: PermissionStatus(is_root=root, groups=frozenset(), journal_groups=frozenset()),
    )


def test_without_root_the_udp_profile_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    _as_root(monkeypatch, False)

    hint = menus.root_required_hint("udp")

    assert hint is not None
    assert "root" in hint


def test_the_message_explains_how_to_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    """Nmap solo dice que hacen falta privilegios; el aviso debe decir qué hacer."""
    _as_root(monkeypatch, False)

    hint = menus.root_required_hint("udp")

    assert hint is not None
    assert "sudo" in hint


def test_as_root_there_is_no_complaint(monkeypatch: pytest.MonkeyPatch) -> None:
    _as_root(monkeypatch, True)

    assert menus.root_required_hint("udp") is None


@pytest.mark.parametrize("profile", ["fast", "standard", "full"])
def test_the_tcp_profiles_never_complain(monkeypatch: pytest.MonkeyPatch, profile: str) -> None:
    _as_root(monkeypatch, False)

    assert menus.root_required_hint(profile) is None


def test_an_unknown_profile_is_not_this_check_s_problem(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """De un perfil inexistente se queja build_command, con su propio mensaje."""
    _as_root(monkeypatch, False)

    assert menus.root_required_hint("no-existe") is None


# ------------------------------------------------------------------ parseo de resultados


def _ports() -> dict[int, tuple[str, str]]:
    hosts: list[Host] = parse_nmap_file(FIXTURE)
    return {port.number: (port.protocol, port.state) for host in hosts for port in host.ports}


def test_the_fixture_ports_are_all_udp() -> None:
    assert {protocol for protocol, _ in _ports().values()} == {"udp"}


def test_a_service_that_answers_is_open() -> None:
    assert _ports()[53] == ("udp", "open")


def test_a_service_that_stays_quiet_is_open_or_filtered() -> None:
    """El resultado típico de UDP: Nmap no puede distinguir abierto de filtrado."""
    assert _ports()[161] == ("udp", "open|filtered")


def test_the_service_name_is_parsed() -> None:
    hosts = parse_nmap_file(FIXTURE)
    services = {port.number: port.service for host in hosts for port in host.ports}

    assert services[53] == "domain"
    assert services[123] == "ntp"


def test_open_filtered_ports_count_as_open() -> None:
    """Se muestran igualmente: en UDP, descartarlos ocultaría casi todo el resultado."""
    hosts = parse_nmap_file(FIXTURE)

    assert len(hosts[0].open_ports) == 4


@pytest.mark.parametrize(
    ("state", "expected"),
    [
        ("open", True),
        ("open|filtered", True),
        ("closed", False),
        ("filtered", False),
        ("closed|filtered", False),
        ("unfiltered", False),
    ],
)
def test_which_states_count_as_open(state: str, expected: bool) -> None:
    """'filtered' a secas sigue siendo cerrado: solo lo que empieza por 'open' cuenta."""
    from suize.models.host import Port

    assert Port(number=1, protocol="udp", state=state).is_open is expected
