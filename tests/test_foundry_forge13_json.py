"""FoundryAdapter must parse forge >=1.x test JSON and keep the test-results stream.

Regression for two compounding bugs that made `miesc audit single foundry` report
``tests_run=0`` on forge 1.3.5:

1. forge >=1.x nests ``test_results`` under each suite id and reports pass/fail as a
   ``status`` string ("Success"/"Failure"); the parser expected a top-level
   ``test_results`` map with a boolean ``success``.
2. the adapter combined ``--gas-report`` with ``--json``; in forge >=1.x that emits
   only the gas-report JSON and SUPPRESSES the test-results JSON the adapter parses.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from miesc.adapters.foundry_adapter import FoundryAdapter
from miesc.core.tool_protocol import ToolStatus

# A faithful slice of real `forge test --json` output (forge 1.3.5-stable).
FORGE_13_JSON = {
    "test/Counter.t.sol:CounterTest": {
        "duration": "2ms",
        "test_results": {
            "testFuzz_NeverLarge(uint256)": {
                "status": "Failure",
                "reason": "number too large",
                "counterexample": {"Single": {}},
                "decoded_logs": [],
                "kind": {"Fuzz": {}},
            },
            "testFuzz_SetNumber(uint256)": {
                "status": "Success",
                "reason": None,
                "counterexample": None,
                "decoded_logs": [],
                "kind": {"Fuzz": {}},
            },
        },
        "warnings": [],
    }
}

# The older top-level shape, boolean success.
FORGE_LEGACY_JSON = {
    "test_results": {
        "CounterTest": {
            "test_a": {"success": True},
            "test_b": {"success": False, "reason": "boom"},
        }
    }
}


def test_parses_forge_1x_nested_status_shape():
    findings, stats = FoundryAdapter()._parse_json_results(FORGE_13_JSON)
    assert stats == {"total": 2, "passed": 1, "failed": 1}
    assert len(findings) == 1
    assert findings[0]["test"] == "testFuzz_NeverLarge(uint256)"
    assert "number too large" in findings[0]["description"]


def test_parses_legacy_flat_success_shape():
    _, stats = FoundryAdapter()._parse_json_results(FORGE_LEGACY_JSON)
    assert stats == {"total": 2, "passed": 1, "failed": 1}


def test_is_forge_test_results_detector():
    a = FoundryAdapter()
    assert a._is_forge_test_results(FORGE_13_JSON) is True
    assert a._is_forge_test_results(FORGE_LEGACY_JSON) is True
    # A non-results JSON line forge also prints (e.g. a gas report) is rejected.
    assert a._is_forge_test_results([{"contract": "C", "functions": {}}]) is False
    assert a._is_forge_test_results({"warnings": []}) is False


def test_analyze_command_does_not_combine_gas_report_with_json():
    """`--gas-report` must not ride along with `--json`: it suppresses test JSON."""
    adapter = FoundryAdapter()
    adapter.gas_report = True  # even when configured on

    captured = {}

    def fake_run(cmd, *args, **kwargs):
        captured["cmd"] = cmd
        res = MagicMock()
        res.returncode = 0
        res.stdout = ""
        res.stderr = ""
        return res

    with patch.object(FoundryAdapter, "is_available", return_value=ToolStatus.AVAILABLE):
        with patch("miesc.adapters.foundry_adapter.subprocess.run", side_effect=fake_run):
            adapter.analyze("examples/contracts/fuzzing/src/Counter.sol")

    assert "--json" in captured["cmd"]
    assert "--gas-report" not in captured["cmd"]
