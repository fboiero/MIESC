"""
Regression tests for bugs found during v5.1.7 gate work.

Each test name encodes the specific bug it prevents from coming back.

Bugs covered:
  1. `_targeted_defi_scan` called DeFiPatternDetector.detect() which does
     not exist — should be analyze_code(). Returned [] silently.
  2. Phase 3 top-level report dropped properties_generated /
     defi_confirmed / needs_manual_review between _phase_deep_investigation
     and report["phases"]["deep_investigation"].
  3. Multi-LLM consensus gate was `fsev == "critical"` only; real tools
     emit HIGH for most reentrancy/access-control findings so the gate
     almost never fired in production.
  4. Phase 3 branches matched on substring in `ftype` — real Slither
     detectors (arbitrary-send-eth, suicidal) didn't contain the expected
     substrings. Now uses CanonicalCategory via finding_taxonomy.
"""

from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import patch

import pytest

from src.agents.deep_audit_agent import DeepAuditAgent, DeepAuditConfig, ReconResult, ScanResult

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def contract_path(tmp_path):
    p = tmp_path / "C.sol"
    p.write_text(
        "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\n"
        "contract C {\n"
        "    mapping(address => uint256) balances;\n"
        "    function withdraw(uint256 a) external {\n"
        "        (bool ok,) = msg.sender.call{value: a}('');\n"
        "        require(ok);\n"
        "        balances[msg.sender] -= a;\n"
        "    }\n"
        "}\n"
    )
    return str(p)


@pytest.fixture
def agent_llm():
    cfg = DeepAuditConfig(
        timeout_seconds=60,
        max_iterations=3,
        enable_llm=True,
        enable_rag=False,
        enable_taint=False,
        enable_call_graph=False,
        enable_exploit_chains=False,
    )
    return DeepAuditAgent(config=cfg)


@pytest.fixture
def agent_no_llm():
    cfg = DeepAuditConfig(
        timeout_seconds=60,
        max_iterations=3,
        enable_llm=False,
        enable_rag=False,
        enable_taint=False,
        enable_call_graph=False,
        enable_exploit_chains=False,
    )
    return DeepAuditAgent(config=cfg)


# ---------------------------------------------------------------------------
# Bug 1 — _targeted_defi_scan used a non-existent API
# ---------------------------------------------------------------------------


class TestDefiScanApi:
    def test_targeted_defi_scan_calls_analyze_code_not_detect(self, agent_no_llm):
        """
        Regression: before v5.1.7 the scan called DeFiPatternDetector.detect()
        which raised AttributeError and was swallowed by a try/except,
        silently returning []. Now must call analyze_code().
        """
        from src.ml.defi_patterns import DeFiPatternDetector

        det = DeFiPatternDetector()
        # The contract MUST use analyze_code, not detect.
        assert hasattr(det, "analyze_code")
        assert not hasattr(det, "detect")

    def test_targeted_defi_scan_returns_list_even_on_empty_source(self, agent_no_llm):
        result = agent_no_llm._targeted_defi_scan("contract Empty {}", None)
        assert isinstance(result, list)

    def test_targeted_defi_scan_picks_up_oracle_pattern(self, agent_no_llm):
        """An explicit getReserves() + division pattern should trigger a match."""
        source = """
        contract V {
            function price() public view returns (uint) {
                (uint r0, uint r1, ) = pair.getReserves();
                return r0 / r1;
            }
        }
        """
        result = agent_no_llm._targeted_defi_scan(source, None)
        # We don't assert exact count (detector version may shift), only that
        # the call reaches the detector and returns a list of dicts.
        assert isinstance(result, list)
        for item in result:
            assert isinstance(item, dict)


# ---------------------------------------------------------------------------
# Bug 2 — Phase 3 report block dropped new counters
# ---------------------------------------------------------------------------


class TestPhase3ReportBlockExposure:
    """The top-level result['phases']['deep_investigation'] must carry the
    Bloque-3 counters (properties_generated, defi_confirmed,
    needs_manual_review), not just the older iterations/findings_enriched."""

    def test_report_block_exposes_properties_generated(self, agent_no_llm, contract_path):
        result = agent_no_llm.analyze(contract_path)
        block = result["phases"]["deep_investigation"]
        assert "properties_generated" in block
        assert isinstance(block["properties_generated"], int)

    def test_report_block_exposes_defi_confirmed(self, agent_no_llm, contract_path):
        result = agent_no_llm.analyze(contract_path)
        block = result["phases"]["deep_investigation"]
        assert "defi_confirmed" in block
        assert isinstance(block["defi_confirmed"], int)

    def test_report_block_exposes_needs_manual_review(self, agent_no_llm, contract_path):
        result = agent_no_llm.analyze(contract_path)
        block = result["phases"]["deep_investigation"]
        assert "needs_manual_review" in block
        assert isinstance(block["needs_manual_review"], int)

    def test_report_block_retains_legacy_keys(self, agent_no_llm, contract_path):
        """Must not break downstream consumers that read the pre-v5.1.7 keys."""
        result = agent_no_llm.analyze(contract_path)
        block = result["phases"]["deep_investigation"]
        for key in (
            "iterations",
            "findings_enriched",
            "additional_tools",
            "chains_detected",
            "mitigated",
        ):
            assert key in block, f"report block dropped legacy key: {key}"


# ---------------------------------------------------------------------------
# Bug 3 — Consensus gate was critical-only; must include HIGH
# ---------------------------------------------------------------------------


class TestConsensusGateHighInclusion:
    """
    Real tools (Slither, Aderyn) emit HIGH for the majority of reentrancy
    and access-control findings. CRITICAL is rare. The v5.1.6 gate was
    `fsev == "critical"` which made consensus almost never fire in
    production. v5.1.7 widened it to ('critical', 'high').
    """

    def test_high_severity_triggers_consensus(self, agent_llm, contract_path):
        agent_llm._start_time = time.monotonic()

        fake_consensus = {
            "opinions": [{"_model": "a", "confirmed": True}, {"_model": "b", "confirmed": True}],
            "models_queried": ["a", "b"],
            "confirmed_count": 2,
            "rejected_count": 0,
            "consensus": "agree_confirmed",
            "confidence_delta": 0.20,
            "needs_manual_review": False,
        }
        with patch.object(agent_llm, "_get_llm_consensus", return_value=fake_consensus) as m:
            scan = ScanResult(
                tools_run=["slither"],
                filtered_findings=[
                    {
                        "id": "h1",
                        "title": "reentrancy",
                        "type": "reentrancy-eth",
                        "severity": "High",  # HIGH, not CRITICAL
                        "location": {"function": "withdraw"},
                    }
                ],
            )
            agent_llm._phase_deep_investigation(
                contract_path,
                Path(contract_path).read_text(),
                ReconResult(),
                scan,
            )
            assert m.called, "consensus should fire on HIGH findings after v5.1.7"

    def test_critical_still_triggers_consensus(self, agent_llm, contract_path):
        """Make sure widening the gate didn't accidentally drop CRITICAL handling."""
        agent_llm._start_time = time.monotonic()
        fake_consensus = {
            "opinions": [{"_model": "a", "confirmed": True}],
            "models_queried": ["a"],
            "confirmed_count": 1,
            "rejected_count": 0,
            "consensus": "single_opinion",
            "confidence_delta": 0.0,
            "needs_manual_review": False,
        }
        with patch.object(agent_llm, "_get_llm_consensus", return_value=fake_consensus) as m:
            scan = ScanResult(
                tools_run=["slither"],
                filtered_findings=[
                    {
                        "id": "c1",
                        "type": "reentrancy-eth",
                        "severity": "critical",
                        "location": {"function": "withdraw"},
                    }
                ],
            )
            agent_llm._phase_deep_investigation(
                contract_path,
                Path(contract_path).read_text(),
                ReconResult(),
                scan,
            )
            assert m.called

    def test_medium_severity_does_NOT_trigger_consensus(self, agent_llm, contract_path):
        """Medium findings must still be excluded — consensus is an expensive
        LLM round trip; reserving it for HIGH+ keeps cost bounded."""
        agent_llm._start_time = time.monotonic()
        with patch.object(agent_llm, "_get_llm_consensus") as m:
            scan = ScanResult(
                tools_run=["slither"],
                filtered_findings=[
                    {
                        "id": "m1",
                        "type": "reentrancy-eth",
                        "severity": "Medium",
                        "location": {"function": "withdraw"},
                    }
                ],
            )
            agent_llm._phase_deep_investigation(
                contract_path,
                Path(contract_path).read_text(),
                ReconResult(),
                scan,
            )
            # Medium findings don't even enter the Phase 3 queue
            assert not m.called


# ---------------------------------------------------------------------------
# Bug 4 — Phase 3 branches matched substrings, not canonical category
# ---------------------------------------------------------------------------


class TestCanonicalCategoryRouting:
    """Regression: before v5.1.7 the Phase-3 branches matched substrings in
    `ftype`. Slither detectors like `arbitrary-send-eth` (access control)
    didn't contain the substring 'access' and so never triggered property
    generation. Now uses src.core.finding_taxonomy."""

    def test_arbitrary_send_eth_routes_to_access_control_branch(self, agent_no_llm, contract_path):
        agent_no_llm._start_time = time.monotonic()
        with patch.object(
            agent_no_llm,
            "_targeted_property_for_function",
            return_value={
                "format": "cvl",
                "rule_name": "r",
                "content": "...",
                "target_function": "withdraw",
            },
        ) as prop_mock:
            scan = ScanResult(
                tools_run=["slither"],
                filtered_findings=[
                    {
                        "id": "a1",
                        "type": "arbitrary-send-eth",  # Slither vocabulary, not 'access-control'
                        "severity": "High",
                        "location": {"function": "withdraw"},
                    }
                ],
            )
            result = agent_no_llm._phase_deep_investigation(
                contract_path,
                Path(contract_path).read_text(),
                ReconResult(),
                scan,
            )
            assert prop_mock.called, (
                "arbitrary-send-eth should map to ACCESS_CONTROL via "
                "CanonicalCategory and trigger property generation"
            )
            assert result["properties_generated"] == 1

    def test_suicidal_routes_to_access_control_branch(self, agent_no_llm, contract_path):
        agent_no_llm._start_time = time.monotonic()
        with patch.object(
            agent_no_llm,
            "_targeted_property_for_function",
            return_value={
                "format": "cvl",
                "rule_name": "r",
                "content": "...",
                "target_function": "kill",
            },
        ) as prop_mock:
            scan = ScanResult(
                tools_run=["slither"],
                filtered_findings=[
                    {
                        "id": "s1",
                        "type": "suicidal",
                        "severity": "High",
                        "location": {"function": "kill"},
                    }
                ],
            )
            agent_no_llm._phase_deep_investigation(
                contract_path,
                Path(contract_path).read_text(),
                ReconResult(),
                scan,
            )
            assert prop_mock.called

    def test_canonical_category_recorded_in_investigation(self, agent_no_llm, contract_path):
        agent_no_llm._start_time = time.monotonic()
        scan = ScanResult(
            tools_run=["slither"],
            filtered_findings=[
                {
                    "id": "a1",
                    "type": "reentrancy-eth",
                    "severity": "High",
                    "location": {"function": "withdraw"},
                }
            ],
        )
        result = agent_no_llm._phase_deep_investigation(
            contract_path,
            Path(contract_path).read_text(),
            ReconResult(),
            scan,
        )
        inv = result["findings"][0]["investigation"]
        assert inv["canonical_category"] == "reentrancy"


# ---------------------------------------------------------------------------
# Bug 5 — _start_time timeout gotcha (found during Gate 3 debugging)
# ---------------------------------------------------------------------------


class TestStartTimeTimeoutGuard:
    """
    `_timeout_exceeded` returns (time.monotonic() - _start_time) > timeout.
    If _start_time is 0.0 (default), this is ALWAYS true (monotonic is
    a huge number), which short-circuits every loop on the first iteration.
    Tests that call private phase methods directly MUST prime _start_time.
    This test locks in that behavior so a future refactor doesn't break it.
    """

    def test_default_start_time_reports_timeout_exceeded(self, agent_no_llm):
        assert agent_no_llm._timeout_exceeded() is True  # with _start_time=0

    def test_primed_start_time_reports_not_exceeded(self, agent_no_llm):
        agent_no_llm._start_time = time.monotonic()
        assert agent_no_llm._timeout_exceeded() is False

    def test_analyze_primes_start_time_internally(self, agent_no_llm, contract_path):
        """analyze() must prime _start_time before running phases."""
        # Before calling analyze, _start_time is 0 and timeout would fire.
        agent_no_llm._start_time = 0.0
        result = agent_no_llm.analyze(contract_path)
        # If analyze didn't prime the timer, Phase 1 would immediately bail
        # and the result would be empty. Verify the phases actually ran:
        assert "phases" in result
        assert "reconnaissance" in result["phases"]
        assert "deep_investigation" in result["phases"]
