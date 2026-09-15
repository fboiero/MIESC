"""MEJORAS2.md #3: run_layer must bound how long it waits on a tool, even one
that ignores the `timeout` it was given (root cause: not every adapter
propagates `timeout` down to its subprocess/network call)."""

from __future__ import annotations

import time

from miesc.cli import utils as cli_utils


def _fake_run_tool(stuck_tools, sleep_for=30):
    def run_tool(tool, contract, timeout=0, **kwargs):
        if tool in stuck_tools:
            time.sleep(sleep_for)
            return {"tool": tool, "status": "success", "findings": []}
        return {
            "tool": tool,
            "contract": contract,
            "status": "success",
            "findings": [],
            "execution_time": 0.01,
            "timestamp": "now",
        }

    return run_tool


def test_run_layer_bounds_stuck_adapter_among_several(monkeypatch):
    monkeypatch.setitem(
        cli_utils.LAYERS,
        9999,
        {"name": "test", "description": "test", "tools": ["stuck_tool", "fast_tool"]},
    )
    monkeypatch.setattr(cli_utils, "run_tool", _fake_run_tool({"stuck_tool"}))
    monkeypatch.setattr(cli_utils, "get_max_workers", lambda default=4: 4)

    start = time.monotonic()
    results = cli_utils.run_layer(9999, "Contract.sol", timeout=1)
    elapsed = time.monotonic() - start

    by_tool = {r["tool"]: r for r in results}
    assert elapsed < 1 + cli_utils._LAYER_TIMEOUT_SAFETY_MARGIN + 3
    assert by_tool["stuck_tool"]["status"] == "timeout"
    assert by_tool["fast_tool"]["status"] == "success"


def test_run_layer_bounds_stuck_adapter_alone(monkeypatch):
    """Single-tool layers used to skip the thread pool entirely (the old
    serial fast path) and had no safety net at all."""
    monkeypatch.setitem(
        cli_utils.LAYERS,
        9998,
        {"name": "test", "description": "test", "tools": ["stuck_tool"]},
    )
    monkeypatch.setattr(cli_utils, "run_tool", _fake_run_tool({"stuck_tool"}))
    monkeypatch.setattr(cli_utils, "get_max_workers", lambda default=4: 4)

    start = time.monotonic()
    results = cli_utils.run_layer(9998, "Contract.sol", timeout=1)
    elapsed = time.monotonic() - start

    assert elapsed < 1 + cli_utils._LAYER_TIMEOUT_SAFETY_MARGIN + 3
    assert results[0]["status"] == "timeout"
