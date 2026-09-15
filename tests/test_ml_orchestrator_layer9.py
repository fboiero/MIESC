"""
Layer 9 second-opinion orchestration (MEJORAS.md item #30a).

Before this, `audit_consensus`/`exploit_synthesizer`/`vuln_verifier` ran in the
same parallel batch as every other tool and always got called with no
findings_map/findings — so they always returned `findings: []` regardless of
how vulnerable the contract was. `MLOrchestrator.analyze()` now runs them in a
second pass, after layers 1-8's findings exist, and passes each of them what
its `analyze()` signature actually expects.

Mocks `discovery.load_adapter` (the tool-loading boundary) so this doesn't
depend on real Slither/Ollama being installed — same pattern as
tests/test_core.py's `_run_tool` tests.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

from miesc.core.ml_orchestrator import MLOrchestrator


class _FakeAdapter:
    def __init__(self, handler):
        self._handler = handler

    def analyze(self, contract_path: str, **kwargs: Any) -> dict:
        return self._handler(contract_path, **kwargs)


def _detector_result(tool: str, finding_id: str) -> dict:
    return {
        "tool": tool,
        "status": "success",
        "findings": [
            {
                "id": finding_id,
                "type": "reentrancy",
                "severity": "High",
                "location": {"file": "Vault.sol", "line": 10},
            }
        ],
    }


def _make_orchestrator(tmp_path: Path, calls: dict) -> MLOrchestrator:
    orchestrator = MLOrchestrator(cache_enabled=False, ml_enabled=False)

    def load_adapter(tool_name: str):
        if tool_name == "slither":
            return _FakeAdapter(lambda cp, **kw: _detector_result("slither", "slither-1"))
        if tool_name == "aderyn":
            return _FakeAdapter(lambda cp, **kw: _detector_result("aderyn", "aderyn-1"))
        if tool_name == "audit_consensus":

            def handler(cp, **kw):
                calls["audit_consensus"] = kw
                return {
                    "tool": "audit_consensus",
                    "status": "success",
                    "findings": (
                        [{"id": "consensus-1", "type": "reentrancy", "severity": "High"}]
                        if kw.get("findings_map")
                        else []
                    ),
                }

            return _FakeAdapter(handler)
        if tool_name == "exploit_synthesizer":

            def handler(cp, **kw):
                calls["exploit_synthesizer"] = kw
                return {
                    "tool": "exploit_synthesizer",
                    "status": "success",
                    "findings": (
                        [{"id": "exploit-1", "type": "exploit_chain", "severity": "Critical"}]
                        if kw.get("findings")
                        else []
                    ),
                }

            return _FakeAdapter(handler)
        if tool_name == "vuln_verifier":

            def handler(cp, **kw):
                calls["vuln_verifier"] = kw
                return {
                    "tool": "vuln_verifier",
                    "status": "success",
                    "findings": (
                        [{"id": "verified-1", "type": "verification", "severity": "Info"}]
                        if kw.get("findings")
                        else []
                    ),
                }

            return _FakeAdapter(handler)
        raise AssertionError(f"unexpected tool: {tool_name}")

    orchestrator.discovery = MagicMock()
    orchestrator.discovery.get_available_tools.return_value = [
        MagicMock(name=n)
        for n in ("slither", "aderyn", "audit_consensus", "exploit_synthesizer", "vuln_verifier")
    ]
    for i, n in enumerate(
        ("slither", "aderyn", "audit_consensus", "exploit_synthesizer", "vuln_verifier")
    ):
        orchestrator.discovery.get_available_tools.return_value[i].name = n
    orchestrator.discovery.load_adapter.side_effect = load_adapter

    return orchestrator


class TestLayer9SecondPass:
    def test_second_opinion_tools_receive_pass1_findings(self, tmp_path):
        contract = tmp_path / "Vault.sol"
        contract.write_text("contract Vault {}")
        calls: dict = {}
        orchestrator = _make_orchestrator(tmp_path, calls)

        result = orchestrator.analyze(
            contract_path=str(contract),
            tools=["slither", "aderyn", "audit_consensus", "exploit_synthesizer", "vuln_verifier"],
            timeout=30,
        )

        # The core regression: findings_map/findings are no longer empty.
        assert calls["audit_consensus"]["findings_map"]
        assert "slither" in calls["audit_consensus"]["findings_map"]
        assert "aderyn" in calls["audit_consensus"]["findings_map"]
        assert calls["exploit_synthesizer"]["findings"]
        assert calls["vuln_verifier"]["findings"]

        result_ids = {f["id"] for f in result.ml_filtered_findings}
        assert {"consensus-1", "exploit-1", "verified-1"} <= result_ids
        assert set(result.tools_success) == {
            "slither",
            "aderyn",
            "audit_consensus",
            "exploit_synthesizer",
            "vuln_verifier",
        }

    def test_second_opinion_tools_alone_get_empty_input_gracefully(self, tmp_path):
        """If no pass1 detector tools are requested, pass2 tools still run (on an
        empty findings_map/findings) instead of being silently skipped — they
        degrade to their own documented "no input" response, not a crash."""
        contract = tmp_path / "Vault.sol"
        contract.write_text("contract Vault {}")
        calls: dict = {}
        orchestrator = _make_orchestrator(tmp_path, calls)

        result = orchestrator.analyze(
            contract_path=str(contract),
            tools=["audit_consensus"],
            timeout=30,
        )

        assert calls["audit_consensus"]["findings_map"] == {}
        assert result.ml_filtered_findings == []
        assert "audit_consensus" in result.tools_success


class TestConfirmExploitsFlag:
    """MEJORAS3.md item 3: run_poc off by default (real forge latency), opt-in
    via analyze(confirm_exploits=True) - threaded through to exploit_synthesizer
    as its run_poc kwarg. audit_consensus/vuln_verifier are unaffected (they
    don't take a run_poc argument)."""

    def test_confirm_exploits_false_by_default(self, tmp_path):
        contract = tmp_path / "Vault.sol"
        contract.write_text("contract Vault {}")
        calls: dict = {}
        orchestrator = _make_orchestrator(tmp_path, calls)

        orchestrator.analyze(
            contract_path=str(contract),
            tools=["exploit_synthesizer"],
            timeout=30,
        )

        assert calls["exploit_synthesizer"]["run_poc"] is False

    def test_confirm_exploits_true_threads_through(self, tmp_path):
        contract = tmp_path / "Vault.sol"
        contract.write_text("contract Vault {}")
        calls: dict = {}
        orchestrator = _make_orchestrator(tmp_path, calls)

        orchestrator.analyze(
            contract_path=str(contract),
            tools=["exploit_synthesizer"],
            timeout=30,
            confirm_exploits=True,
        )

        assert calls["exploit_synthesizer"]["run_poc"] is True
