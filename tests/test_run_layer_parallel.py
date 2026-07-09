"""Tests for bounded parallel layer execution."""

import time


def test_run_layer_parallel_preserves_order(monkeypatch):
    from miesc.cli import utils

    monkeypatch.setitem(
        utils.LAYERS,
        99,
        {"name": "test", "tools": ["slow_a", "slow_b", "slow_c"]},
    )
    monkeypatch.setattr(utils, "get_max_workers", lambda default=4: 3)
    monkeypatch.setattr(utils, "info", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(utils, "success", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(utils, "warning", lambda *_args, **_kwargs: None)

    def fake_run_tool(tool, contract, timeout):
        time.sleep(0.1)
        return {
            "tool": tool,
            "contract": contract,
            "status": "success",
            "findings": [],
            "execution_time": 0.1,
        }

    monkeypatch.setattr(utils, "run_tool", fake_run_tool)

    start = time.monotonic()
    results = utils.run_layer(99, "C.sol", timeout=10)
    elapsed = time.monotonic() - start

    assert [result["tool"] for result in results] == ["slow_a", "slow_b", "slow_c"]
    assert elapsed < 0.25


def test_run_layer_can_be_forced_to_serial(monkeypatch):
    from miesc.cli import utils

    calls = []
    monkeypatch.setitem(utils.LAYERS, 98, {"name": "test", "tools": ["a", "b"]})
    monkeypatch.setattr(utils, "get_max_workers", lambda default=4: 1)
    monkeypatch.setattr(utils, "info", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(utils, "success", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(utils, "warning", lambda *_args, **_kwargs: None)

    def fake_run_tool(tool, contract, timeout):
        calls.append(tool)
        return {
            "tool": tool,
            "contract": contract,
            "status": "success",
            "findings": [],
            "execution_time": 0.0,
        }

    monkeypatch.setattr(utils, "run_tool", fake_run_tool)

    results = utils.run_layer(98, "C.sol", timeout=10)

    assert calls == ["a", "b"]
    assert [result["tool"] for result in results] == ["a", "b"]
