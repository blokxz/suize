"""Tests de coherencia del versionado.

El número de versión vive en ``src/suize/__init__.py`` y se repite en el
CHANGELOG. Estos tests evitan que se separen: publicar una versión cuyo
changelog dice otra cosa es un error silencioso y difícil de detectar después.
"""

import re
from pathlib import Path

from suize import __version__

#: Raíz del repositorio (tests/unit/ -> tests/ -> raíz).
ROOT = Path(__file__).resolve().parents[2]
CHANGELOG = ROOT / "CHANGELOG.md"

#: Encabezado de versión: "## [0.2.0] - 2026-09-12".
VERSION_HEADING_RE = re.compile(
    r"^## \[(?P<version>\d+\.\d+\.\d+)\] - (?P<date>\d{4}-\d{2}-\d{2})$"
)

#: Versionado semántico, sin prerreleases (el proyecto no los usa por ahora).
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


def released_versions() -> list[str]:
    """Versiones publicadas, en el orden en que aparecen en el CHANGELOG."""
    return [
        match.group("version")
        for line in CHANGELOG.read_text(encoding="utf-8").splitlines()
        if (match := VERSION_HEADING_RE.match(line))
    ]


def test_the_version_follows_semver() -> None:
    assert SEMVER_RE.match(__version__)


def test_the_code_version_is_the_latest_in_the_changelog() -> None:
    """Si fallas aquí, o falta la entrada del changelog o falta subir la versión."""
    versions = released_versions()

    assert versions, "el CHANGELOG no tiene ninguna versión publicada"
    assert versions[0] == __version__


def test_versions_are_listed_from_newest_to_oldest() -> None:
    versions = released_versions()
    as_numbers = [tuple(int(part) for part in version.split(".")) for version in versions]

    assert as_numbers == sorted(as_numbers, reverse=True)


def test_there_are_no_duplicate_versions() -> None:
    versions = released_versions()

    assert len(versions) == len(set(versions))


def test_the_changelog_has_a_section_for_unreleased_changes() -> None:
    """Donde se anotan los cambios según se hacen, antes de publicarlos."""
    assert "## [Sin publicar]" in CHANGELOG.read_text(encoding="utf-8")


def test_the_changelog_only_uses_known_section_names() -> None:
    """Las secciones deben salir del vocabulario de Keep a Changelog, no inventarse."""
    used = set(re.findall(r"^### (.+)$", CHANGELOG.read_text(encoding="utf-8"), re.M))
    known = {"Añadido", "Cambiado", "Obsoleto", "Eliminado", "Corregido", "Seguridad"}

    assert used <= known, f"secciones desconocidas: {used - known}"
