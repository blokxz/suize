"""Tests de sincronía entre el parser y los scripts de autocompletado.

Los completados de `completions/` están escritos a mano, así que pueden
quedarse atrás cuando se añade una opción a ``cli.py``. Estos tests comparan
ambas cosas: si añades una opción y olvidas el completado, falla aquí y no
seis meses después, cuando alguien note que el Tab no la ofrece.

Se apoyan en atributos internos de argparse (``_actions``,
``_name_parser_map``) porque no expone otra forma de enumerar las opciones.
Es aceptable en un test: si una versión de Python los cambiara, fallaría la
comprobación, no el programa.
"""

import argparse
from pathlib import Path

import pytest

from suize import cli

ROOT = Path(__file__).resolve().parents[2]
COMPLETIONS = ROOT / "completions"
ZSH = COMPLETIONS / "_suize"
BASH = COMPLETIONS / "suize.bash"

#: Opciones que ningún completado necesita ofrecer.
IGNORED = {"-h", "--help", "-V", "--version"}


def options_of(parser: argparse.ArgumentParser) -> set[str]:
    """Todas las banderas de un parser, sin las ignoradas."""
    flags = {flag for action in parser._actions for flag in action.option_strings}
    return flags - IGNORED


def subparsers() -> dict[str, argparse.ArgumentParser]:
    """Los parsers de ``scan`` y ``logs``, por nombre."""
    for action in cli.build_parser()._actions:
        if isinstance(action, argparse._SubParsersAction):
            return dict(action._name_parser_map)
    raise AssertionError("el parser no tiene subcomandos")


def all_options() -> set[str]:
    every = options_of(cli.build_parser())
    for parser in subparsers().values():
        every |= options_of(parser)
    return every


def choices_of(subcommand: str, flag: str) -> list[str]:
    for action in subparsers()[subcommand]._actions:
        if flag in action.option_strings and action.choices:
            return list(action.choices)
    raise AssertionError(f"{subcommand} {flag} no tiene valores fijos")


# ------------------------------------------------------------------------------ archivos


def test_the_zsh_script_declares_the_command_it_completes() -> None:
    assert ZSH.read_text(encoding="utf-8").startswith("#compdef suize")


def test_the_bash_script_registers_the_completion() -> None:
    assert "complete -F _suize suize" in BASH.read_text(encoding="utf-8")


# -------------------------------------------------------------------------------- opciones


@pytest.mark.parametrize("script", [ZSH, BASH], ids=["zsh", "bash"])
def test_every_option_of_the_parser_is_in_the_completions(script: Path) -> None:
    """Si falla: añadiste una opción a cli.py y falta en completions/."""
    text = script.read_text(encoding="utf-8")
    missing = sorted(flag for flag in all_options() if flag not in text)

    assert not missing, f"faltan en {script.name}: {missing}"


@pytest.mark.parametrize("script", [ZSH, BASH], ids=["zsh", "bash"])
def test_the_subcommands_are_in_the_completions(script: Path) -> None:
    text = script.read_text(encoding="utf-8")

    assert set(subparsers()) <= {"scan", "logs"}
    for name in subparsers():
        assert name in text


# --------------------------------------------------------------------------------- valores


@pytest.mark.parametrize("script", [ZSH, BASH], ids=["zsh", "bash"])
def test_the_scan_profiles_are_offered(script: Path) -> None:
    text = script.read_text(encoding="utf-8")

    for profile in choices_of("scan", "--profile"):
        assert profile in text, f"falta el perfil {profile} en {script.name}"


@pytest.mark.parametrize("script", [ZSH, BASH], ids=["zsh", "bash"])
def test_the_output_formats_are_offered(script: Path) -> None:
    text = script.read_text(encoding="utf-8")

    for output_format in choices_of("logs", "--format"):
        assert output_format in text, f"falta el formato {output_format} en {script.name}"


@pytest.mark.parametrize("script", [ZSH, BASH], ids=["zsh", "bash"])
def test_the_priority_names_are_offered(script: Path) -> None:
    """Los nombres deben salir del modelo, no de una lista escrita aparte."""
    from suize.models.log_entry import PRIORITY_NAMES

    text = script.read_text(encoding="utf-8")

    for name in PRIORITY_NAMES.values():
        assert name in text, f"falta la prioridad {name} en {script.name}"


@pytest.mark.parametrize("script", [ZSH, BASH], ids=["zsh", "bash"])
def test_the_time_presets_are_offered(script: Path) -> None:
    """Los presets del completado deben existir de verdad en la configuración."""
    from suize.config.settings import load_settings

    text = script.read_text(encoding="utf-8")
    keys = [preset.key for preset in load_settings().time_presets if preset.key != "custom"]

    for key in keys:
        assert key in text, f"falta el preset {key} en {script.name}"


@pytest.mark.parametrize("script", [ZSH, BASH], ids=["zsh", "bash"])
def test_the_units_come_from_systemctl(script: Path) -> None:
    """El valor del completado está en ofrecer las unidades reales del equipo."""
    assert "systemctl list-units" in script.read_text(encoding="utf-8")
