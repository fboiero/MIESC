"""Aderyn 0.1.x panics (exit 101) on legacy Solidity it cannot model.

Regression for the SmartBugs-curated re-run (2026-10-20): 36 of 143 contracts
made aderyn abort on ``throw``. The adapter must report a skip with a reason,
not an error, so the layer summary explains the missing result.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace
from unittest.mock import patch

from miesc.adapters.aderyn_adapter import (
    AderynAdapter,
    ToolStatus,
    _is_unsupported_source_panic,
)

PANIC = (
    "thread 'main' panicked at aderyn_driver-0.1.9/src/process_auto.rs:165:73:\n"
    'called `Result::unwrap()` on an `Err` value: Error("unknown variant `Throw`, '
    'expected one of `Block`, `Break`")'
)


def test_panic_detection_rules():
    assert _is_unsupported_source_panic(101, PANIC)
    assert _is_unsupported_source_panic(101, "")  # panic text lost, bare 101
    assert not _is_unsupported_source_panic(1, PANIC)
    assert not _is_unsupported_source_panic(101, "error: could not find solc")


def test_analyze_reports_skip_on_panic(tmp_path, caplog):
    contract = tmp_path / "legacy.sol"
    contract.write_text("pragma solidity ^0.4.19;\ncontract L { function f() { throw; } }\n")
    fake = SimpleNamespace(returncode=101, stdout="", stderr=PANIC)

    with patch.object(AderynAdapter, "is_available", return_value=ToolStatus.AVAILABLE):
        with patch("miesc.adapters.aderyn_adapter.subprocess.run", return_value=fake):
            with caplog.at_level(logging.WARNING, logger="miesc.adapters.aderyn_adapter"):
                result = AderynAdapter().analyze(str(contract), verbose=False)

    assert result["status"] == "skipped"
    assert result["findings"] == []
    assert result["metadata"]["reason"] == "unsupported_source"
    assert result["metadata"]["exit_code"] == 101
    assert "unsupported Solidity dialect" in result["error"]
    assert not any(r.levelno >= logging.ERROR for r in caplog.records)


def test_analyze_still_errors_on_other_failures(tmp_path):
    contract = tmp_path / "c.sol"
    contract.write_text("pragma solidity ^0.8.0;\ncontract C {}\n")
    fake = SimpleNamespace(returncode=1, stdout="", stderr="error: solc not found")

    with patch.object(AderynAdapter, "is_available", return_value=ToolStatus.AVAILABLE):
        with patch("miesc.adapters.aderyn_adapter.subprocess.run", return_value=fake):
            result = AderynAdapter().analyze(str(contract), verbose=False)

    assert result["status"] == "error"
    assert "exit code 1" in result["error"]
