"""
Tests for the Python version guard (P1-4).

MIESC targets Python >= 3.12. When the `miesc` console script is installed for
an older interpreter, importing the package fails with a cryptic error far from
the cause (a runtime `TypeError` on `X | None` under 3.9, or a dependency
`ModuleNotFoundError` under 3.11). The guard at the top of ``miesc/__init__``
pre-empts all of those with one clear, actionable message.
"""

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from miesc import _MIN_PYTHON, _python_version_error

_REPO_ROOT = Path(__file__).resolve().parent.parent


class TestPythonVersionErrorPolicy:
    """The pure policy function."""

    def test_supported_current_interpreter_returns_none(self):
        # The test suite itself runs on a supported interpreter.
        assert _python_version_error(tuple(sys.version_info[:3])) is None

    @pytest.mark.parametrize("version", [(3, 12, 0), (3, 13, 2), (3, 14, 1), (4, 0, 0)])
    def test_supported_versions_return_none(self, version):
        assert _python_version_error(version_info=version, executable="/x/python") is None

    @pytest.mark.parametrize(
        "version", [(3, 9, 18), (3, 10, 14), (3, 11, 10), (3, 8, 0), (2, 7, 18)]
    )
    def test_unsupported_versions_return_message(self, version):
        msg = _python_version_error(version_info=version, executable="/opt/py/bin/python")
        assert msg is not None
        # Message is actionable: states the requirement, the detected version,
        # the interpreter path, and how to fix it.
        assert "3.12" in msg
        assert ".".join(str(p) for p in version[:3]) in msg
        assert "/opt/py/bin/python" in msg
        assert "python3 -m miesc" in msg

    def test_boundary_is_inclusive_of_minimum(self):
        assert _python_version_error(version_info=_MIN_PYTHON, executable="/x") is None
        below = (_MIN_PYTHON[0], _MIN_PYTHON[1] - 1)
        assert _python_version_error(version_info=below, executable="/x") is not None


def _find_old_python():
    """Return the path to an installed interpreter older than 3.12, or None."""
    for name in ("python3.11", "python3.10", "python3.9", "python3.8"):
        found = shutil.which(name)
        if found:
            return found
    return None


class TestGuardRaisesUnderOldInterpreter:
    """End-to-end: a real unsupported interpreter must hit the guard on import."""

    # Force this checkout to the front of sys.path inside the child: an editable
    # install's `.pth` for another checkout can otherwise shadow PYTHONPATH and
    # import a different `miesc` (seen locally under the system interpreter).
    _IMPORT_SNIPPET = f"import sys; sys.path.insert(0, {str(_REPO_ROOT)!r}); import miesc"

    def test_import_under_old_python_raises_clear_error(self):
        old_python = _find_old_python()
        if old_python is None:
            pytest.skip("no Python < 3.12 interpreter available on this host")

        proc = subprocess.run(
            [old_python, "-c", self._IMPORT_SNIPPET],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert proc.returncode != 0
        assert "MIESC requires Python >= 3.12" in proc.stderr
        # It must fail at the guard, not at some later dependency/syntax error.
        assert "RuntimeError" in proc.stderr

    def test_current_supported_interpreter_imports_cleanly(self):
        proc = subprocess.run(
            [sys.executable, "-c", self._IMPORT_SNIPPET + "; print(miesc.__version__)"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert proc.returncode == 0, proc.stderr
