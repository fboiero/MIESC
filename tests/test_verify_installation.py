"""scripts/verify_installation.py must check exactly the core dependencies.

Regression for the Django false alarm: the script failed a minimal
`pip install miesc` on packages that only come with extras.
"""

from __future__ import annotations

import importlib.util
import re
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def verify_module():
    spec = importlib.util.spec_from_file_location(
        "verify_installation", ROOT / "scripts" / "verify_installation.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _pip_names(requirements: list[str]) -> set[str]:
    return {re.split(r"[<>=!~\[; ]", req, maxsplit=1)[0].lower() for req in requirements}


def test_core_packages_match_pyproject_dependencies(verify_module):
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    core = _pip_names(project["dependencies"])
    checked = {pip_name.lower() for _, pip_name in verify_module.CORE_PACKAGES}
    assert checked == core, f"script checks {checked}, pyproject core is {core}"


def test_extras_are_not_core(verify_module):
    core = {pip_name.lower() for _, pip_name in verify_module.CORE_PACKAGES}
    for pip_name in ("django", "djangorestframework", "weasyprint", "scikit-learn", "mcp"):
        assert pip_name not in core
    optional = {pip_name.lower() for _, pip_name, _ in verify_module.OPTIONAL_PACKAGES}
    assert {"scikit-learn", "weasyprint", "mcp", "django"} <= optional


def test_optional_entries_name_their_extra(verify_module):
    for _, _, extra in verify_module.OPTIONAL_PACKAGES:
        assert extra.startswith("miesc["), extra
