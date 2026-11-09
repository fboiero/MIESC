"""Behavioural coverage for ``miesc.cli.commands.tools`` (the ``tools list`` / ``tools info`` CLI).

Exercises the Rich and plain-text rendering branches and the error paths through Click's
``CliRunner``; the non-Rich branches are reached by flipping the module's ``RICH_AVAILABLE`` flag,
and the metadata-failure path by making an adapter's ``get_metadata`` raise.
"""

from __future__ import annotations

import importlib

from click.testing import CliRunner

from miesc.cli.commands.tools import tools

# The package re-exports the ``tools`` Click group, which shadows the submodule attribute on the
# package, so reach the real module object (with its ``RICH_AVAILABLE`` / ``AdapterLoader`` globals)
# through importlib rather than attribute access.
tools_mod = importlib.import_module("miesc.cli.commands.tools")


def test_tools_list_rich_renders_every_layer():
    res = CliRunner().invoke(tools, ["list"])
    assert res.exit_code == 0
    # Layer 1's tools are named in the rendered tables.
    assert "slither" in res.output and "aderyn" in res.output


def test_tools_list_single_layer_filter():
    res = CliRunner().invoke(tools, ["list", "--layer", "1"])
    assert res.exit_code == 0
    assert "slither" in res.output


def test_tools_list_plain_text_branch(monkeypatch):
    # No Rich -> the plain `=== Layer N ===` / `[OK|MISSING] tool` path (lines 77-84).
    monkeypatch.setattr(tools_mod, "RICH_AVAILABLE", False)
    res = CliRunner().invoke(tools, ["list", "--layer", "1"])
    assert res.exit_code == 0
    assert "=== Layer 1:" in res.output
    assert "slither" in res.output
    assert "[OK]" in res.output or "[MISSING]" in res.output


def test_tools_list_available_only_plain(monkeypatch):
    monkeypatch.setattr(tools_mod, "RICH_AVAILABLE", False)
    res = CliRunner().invoke(tools, ["list", "--available-only"])
    assert res.exit_code == 0  # tools not installed in the test env are filtered out cleanly


def test_tools_info_unknown_tool_reports_and_lists(monkeypatch):
    res = CliRunner().invoke(tools, ["info", "does-not-exist"])
    assert res.exit_code == 0
    assert "No adapter found" in res.output
    assert "slither" in res.output  # the available-tools hint lists real adapters


def test_tools_info_plain_text_branch(monkeypatch):
    monkeypatch.setattr(tools_mod, "RICH_AVAILABLE", False)
    res = CliRunner().invoke(tools, ["info", "slither"])
    assert res.exit_code == 0
    assert "=== slither ===" in res.output
    assert "Version:" in res.output and "Installation:" in res.output


def test_tools_info_handles_metadata_failure(monkeypatch):
    class _Boom:
        def get_metadata(self):
            raise RuntimeError("metadata exploded")

        def is_available(self):
            return False

    monkeypatch.setattr(tools_mod.AdapterLoader, "get_adapter", staticmethod(lambda _t: _Boom()))
    res = CliRunner().invoke(tools, ["info", "slither"])
    assert res.exit_code == 0
    assert "Could not get info" in res.output
