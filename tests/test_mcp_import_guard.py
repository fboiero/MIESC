"""The MCP server must say *why* it cannot start: SDK missing vs. SDK 2.x.

Run in subprocesses so the stubbed `mcp` package never leaks into the test
session (tests/test_mcp_server.py installs its own fake at import time).
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

PROBE = textwrap.dedent("""
    import importlib, sys
    sys.path.insert(0, {root!r})
    {prelude}
    mod = importlib.import_module("miesc.mcp_server")
    print("FASTMCP", mod.FastMCP is not None)
    print("ERROR", mod._MCP_IMPORT_ERROR)
    """)


def _run(prelude: str, pythonpath: str = "") -> str:
    env = {"PYTHONPATH": pythonpath, "PATH": "/usr/bin:/bin"}
    proc = subprocess.run(
        [sys.executable, "-c", PROBE.format(root=str(ROOT), prelude=prelude)],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def test_sdk_missing_is_reported_as_not_installed():
    out = _run("sys.modules['mcp'] = None  # make `import mcp` fail")
    assert "FASTMCP False" in out
    assert "not installed" in out
    assert "miesc[mcp]" in out


def test_sdk_2x_is_reported_as_incompatible(tmp_path):
    # A stub of the 2.x layout: `mcp.server.fastmcp` exists but has no FastMCP.
    pkg = tmp_path / "mcp"
    (pkg / "server").mkdir(parents=True)
    (pkg / "__init__.py").write_text("__version__ = '2.3.0'\n")
    (pkg / "server" / "__init__.py").write_text("")
    (pkg / "server" / "fastmcp.py").write_text("# FastMCP was renamed to MCPServer in 2.x\n")

    out = _run("", pythonpath=str(tmp_path))
    assert "FASTMCP False" in out
    assert "incompatible MCP SDK" in out
    assert "mcp[cli]>=1.2.0,<2" in out
