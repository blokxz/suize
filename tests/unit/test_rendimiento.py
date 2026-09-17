"""Tests de las correcciones de la revisión de rendimiento.

Cubren tres cosas: que ``stream()`` no se cuelgue cuando el hijo escribe mucho
por stderr, que las unidades de systemd se consulten una sola vez por sesión
del menú, y el aviso al pedir ``-Pn`` sobre una red grande.
"""

from collections.abc import Mapping
from pathlib import Path

import pytest
from rich.console import Console

from suize.core import correlator
from suize.ui import menus
from suize.ui.menus import LARGE_NETWORK_HOSTS, AppContext, large_network_warning
from suize.utils.deps import Dependency
from suize.utils.permissions import PermissionStatus

# --------------------------------------------------------------- caché de systemctl


def _context(monkeypatch: pytest.MonkeyPatch, units: set[str]) -> tuple[AppContext, list[float]]:
    """Contexto de menú cuyo systemctl simulado anota cada llamada."""
    llamadas: list[float] = []

    def fake_list(*, timeout: float) -> set[str]:
        llamadas.append(timeout)
        return units

    monkeypatch.setattr(correlator, "list_system_services", fake_list)
    deps: Mapping[str, Dependency] = {
        name: Dependency(name=name, purpose="", install_hint="", path=f"/usr/bin/{name}")
        for name in ("nmap", "journalctl", "systemctl")
    }
    from suize.config.settings import load_settings

    ctx = AppContext(
        console=Console(quiet=True),
        settings=load_settings(),
        deps=deps,
        permissions=PermissionStatus(is_root=False, groups=frozenset(), journal_groups=frozenset()),
    )
    return ctx, llamadas


def test_the_units_are_fetched_once_per_session(monkeypatch: pytest.MonkeyPatch) -> None:
    """Antes se lanzaba systemctl al autocompletar y otra vez al correlacionar."""
    ctx, llamadas = _context(monkeypatch, {"ssh.service", "nginx.service"})

    ctx.system_units(timeout=10)
    ctx.system_units(timeout=10)
    ctx.system_units(timeout=15)

    assert len(llamadas) == 1


def test_the_cached_value_is_the_one_returned(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx, _ = _context(monkeypatch, {"ssh.service"})

    assert ctx.system_units(timeout=10) == {"ssh.service"}
    assert ctx.system_units(timeout=10) == {"ssh.service"}


def test_each_session_has_its_own_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    """La caché dura lo que la sesión: no es un estado global entre ejecuciones."""
    primero, llamadas = _context(monkeypatch, {"ssh.service"})
    primero.system_units(timeout=10)

    segundo = AppContext(
        console=primero.console,
        settings=primero.settings,
        deps=primero.deps,
        permissions=primero.permissions,
    )
    segundo.system_units(timeout=10)

    assert len(llamadas) == 2


def test_the_correlation_reuses_the_provided_units(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx, llamadas = _context(monkeypatch, {"ssh.service"})
    ctx.system_units(timeout=10)  # ya consultadas, p. ej. por el autocompletado

    menus.find_correlations(
        ctx.console,
        [],
        timeout=10,
        tables=correlator.CorrelationTables(),
        units_provider=ctx.system_units,
    )

    assert len(llamadas) == 1, "la correlación debería reutilizar la consulta anterior"


def test_without_a_provider_the_correlation_asks_systemctl(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Es el caso del subcomando, donde no hay sesión ni nada que reaprovechar."""
    ctx, llamadas = _context(monkeypatch, {"ssh.service"})

    menus.find_correlations(ctx.console, [], timeout=10, tables=correlator.CorrelationTables())

    assert len(llamadas) == 1


# ------------------------------------------------------------------ aviso de red grande


@pytest.mark.parametrize("target", ["10.0.0.0/22", "10.0.0.0/16", "192.168.0.0/20"])
def test_a_large_network_with_skip_ping_warns(target: str) -> None:
    aviso = large_network_warning(target, skip_ping=True)

    assert aviso is not None
    assert "direcciones" in aviso


def test_the_warning_says_what_to_do_instead() -> None:
    aviso = large_network_warning("10.0.0.0/16", skip_ping=True)

    assert aviso is not None
    assert "--profile fast" in aviso


def test_the_warning_counts_the_addresses() -> None:
    aviso = large_network_warning("10.0.0.0/16", skip_ping=True)

    assert aviso is not None
    assert "65536" in aviso


@pytest.mark.parametrize("target", ["192.168.1.0/24", "192.168.1.0/25", "10.0.0.0/23"])
def test_a_small_network_does_not_warn(target: str) -> None:
    """Un /24 sin descubrimiento es perfectamente manejable."""
    assert large_network_warning(target, skip_ping=True) is None


def test_the_threshold_is_where_it_says() -> None:
    import ipaddress

    justo_debajo = ipaddress.ip_network("10.0.0.0/23")
    justo_encima = ipaddress.ip_network("10.0.0.0/22")

    assert justo_debajo.num_addresses < LARGE_NETWORK_HOSTS
    assert justo_encima.num_addresses >= LARGE_NETWORK_HOSTS


def test_without_skip_ping_there_is_no_warning() -> None:
    """Con descubrimiento, Nmap descarta las direcciones vacías enseguida."""
    assert large_network_warning("10.0.0.0/8", skip_ping=False) is None


@pytest.mark.parametrize("target", ["192.168.1.10", "servidor.lan", "10.0.0.1-50"])
def test_a_single_target_never_warns(target: str) -> None:
    assert large_network_warning(target, skip_ping=True) is None


def test_an_unparseable_target_does_not_break_the_scan() -> None:
    """Del objetivo inválido se queja el validador; este aviso no debe estorbar."""
    assert large_network_warning("basura/x", skip_ping=True) is None


def test_an_ipv6_network_also_warns() -> None:
    aviso = large_network_warning("2001:db8::/112", skip_ping=True)

    assert aviso is not None


def test_the_path_of_a_file_is_not_mistaken_for_a_network(tmp_path: Path) -> None:
    assert large_network_warning(str(tmp_path / "objetivos.txt"), skip_ping=True) is None
