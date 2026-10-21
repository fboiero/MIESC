"""Guards against documentation drift (Product Excellence Plan, B.7).

Three doc sweeps on 2026-10-20 fixed version strings, the README MCP tool list,
stale module paths and dead relative links. These tests make each of those a
CI failure instead of a periodic cleanup.
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

import miesc

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
INSTALL_EN = ROOT / "docs" / "INSTALLATION.md"
INSTALL_ES = ROOT / "docs" / "INSTALLATION_ES.md"
REPRODUCE = ROOT / "REPRODUCE.md"
CITATION = ROOT / "CITATION.cff"
MCP_SERVER = ROOT / "miesc" / "mcp_server.py"

USER_FACING_DOCS = [
    README,
    REPRODUCE,
    INSTALL_EN,
    INSTALL_ES,
    ROOT / "docs" / "index.md",
    ROOT / "docs" / "index_es.md",
    ROOT / "docs" / "roadmap" / "PRODUCT_EXCELLENCE_PLAN_2026-10.md",
]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# MCP tool list
# ---------------------------------------------------------------------------


def _server_tools() -> set[str]:
    src = _read(MCP_SERVER)
    return set(re.findall(r"@mcp\.tool\(\)\s*(?:async\s+)?def\s+([a-z_][a-z0-9_]*)", src))


def test_readme_mcp_tool_list_matches_server():
    match = re.search(r"\*\*Available MCP tools \((\d+)\):\*\*([^\n]+)", _read(README))
    assert match, "README must keep the '**Available MCP tools (N):**' line"
    advertised = set(re.findall(r"`(miesc_[a-z0-9_]+)`", match.group(2)))
    actual = _server_tools()
    assert actual, "no @mcp.tool() definitions found in miesc/mcp_server.py"
    assert advertised == actual, (
        f"README lists {sorted(advertised - actual)} that the server lacks; "
        f"server exposes {sorted(actual - advertised)} that README omits"
    )
    assert int(match.group(1)) == len(actual)


# ---------------------------------------------------------------------------
# Version strings
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "pattern"),
    [
        (INSTALL_EN, r"^# MIESC (\d+\.\d+\.\d+) - Complete Installation Guide"),
        (INSTALL_EN, r"^MIESC v(\d+\.\d+\.\d+) - Installation Verification"),
        (INSTALL_EN, r"^\*\*Version\*\*: (\d+\.\d+\.\d+) \|"),
        (INSTALL_ES, r"^# MIESC (\d+\.\d+\.\d+) - Guía de Instalación Completa"),
        (INSTALL_ES, r"^MIESC v(\d+\.\d+\.\d+) - Installation Verification"),
        (INSTALL_ES, r"^\*\*Versión\*\*: (\d+\.\d+\.\d+) \|"),
        (CITATION, r"^version: (\d+\.\d+\.\d+)$"),
    ],
    ids=lambda v: v.name if isinstance(v, Path) else v[:28],
)
def test_doc_version_strings_match_package(path: Path, pattern: str):
    match = re.search(pattern, _read(path), re.M)
    assert match, f"{path.relative_to(ROOT)}: pattern not found: {pattern}"
    assert (
        match.group(1) == miesc.__version__
    ), f"{path.relative_to(ROOT)} says {match.group(1)}, package is {miesc.__version__}"


def test_readme_release_line_matches_package():
    text = _read(README)
    match = re.search(r"latest published PyPI / GHCR release is \*\*(\d+\.\d+\.\d+)\*\*", text)
    assert match, "README must state the latest published release"
    assert match.group(1) == miesc.__version__


# ---------------------------------------------------------------------------
# Quoted `python -m <module>` commands must import
# ---------------------------------------------------------------------------

_SKIP_MODULES = {"venv", "pip", "pytest", "build", "twine", "mypy", "ruff", "black"}


def _quoted_modules() -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    for doc in USER_FACING_DOCS:
        for mod in re.findall(
            r"python3?(?:\.\d+)? -m ([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)", _read(doc)
        ):
            if mod.split(".")[0] not in _SKIP_MODULES:
                found.add((doc.name, mod))
    return found


@pytest.mark.parametrize(("doc", "module"), sorted(_quoted_modules()), ids=lambda v: v)
def test_quoted_python_modules_exist(doc: str, module: str):
    assert (
        importlib.util.find_spec(module) is not None
    ), f"{doc} tells the reader to run `python -m {module}`, which does not exist"


# ---------------------------------------------------------------------------
# Relative Markdown links must resolve
# ---------------------------------------------------------------------------

_LINK = re.compile(r"\]\((?!https?://|mailto:|#)([^)\s]+?)(?:#[^)]*)?\)")


def _relative_links() -> list[tuple[str, str]]:
    links: list[tuple[str, str]] = []
    for doc in USER_FACING_DOCS:
        for target in _LINK.findall(_read(doc)):
            links.append((str(doc.relative_to(ROOT)), target))
    return sorted(set(links))


@pytest.mark.parametrize(("doc", "target"), _relative_links(), ids=lambda v: v)
def test_relative_links_resolve(doc: str, target: str):
    resolved = (ROOT / doc).parent / target
    assert resolved.exists(), f"{doc} links to {target}, which does not exist"
