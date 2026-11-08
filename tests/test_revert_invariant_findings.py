"""Tests for promoting access-control counterexamples into findings."""

from __future__ import annotations

import shutil

import pytest

from miesc.llm.revert_invariant_findings import counterexample_findings

_SRC = """pragma solidity ^0.8.20;
contract Vault {
  address owner; address treasury; uint256 fee;
  constructor() { owner = msg.sender; }
  modifier onlyOwner() { require(msg.sender == owner, "no"); _; }
  function setFee(uint256 x) external onlyOwner { fee = x; }
  function setTreasury(address a) external { treasury = a; }
}
"""


class TestEmissionGating:
    def test_counterexample_becomes_one_finding(self):
        executions = [
            {
                "id": "p-access_control",
                "category": "access_control",
                "promotion_state": "counterexample",
                "counterexamples": ["setTreasury"],
                "evidence": ["an unauthorized caller successfully called `setTreasury`"],
            }
        ]
        out = counterexample_findings(executions, _SRC, contract_path="Vault.sol")
        assert len(out) == 1
        f = out[0]
        assert f["type"] == "access_control"
        assert f["severity"] == "High"
        assert f["confidence"] == 0.85
        assert f["source"] == "revert_invariant_executor"
        assert f["location"]["file"] == "Vault.sol"
        # line points at the real `function setTreasury(` declaration, not a line:1 placeholder.
        assert f["location"]["line"] == 7
        assert "setTreasury" in f["title"]
        assert f["evidence"]

    def test_hypothesis_state_emits_nothing(self):
        executions = [
            {
                "category": "access_control",
                "promotion_state": "hypothesis",
                "reason": "every unauthorized probe reverted",
            }
        ]
        assert counterexample_findings(executions, _SRC) == []

    def test_empty_executions(self):
        assert counterexample_findings([], _SRC) == []

    def test_missing_line_degrades_to_zero_not_crash(self):
        executions = [
            {
                "promotion_state": "counterexample",
                "category": "access_control",
                "counterexamples": ["notInSource"],
                "evidence": [],
            }
        ]
        out = counterexample_findings(executions, _SRC)
        assert out[0]["location"]["line"] == 0


# End-to-end through the agent's synthesis phase: needs forge.
_HAS_FORGE = shutil.which("forge") is not None


@pytest.mark.skipif(not _HAS_FORGE, reason="forge not installed")
class TestSynthesisEmission:
    def test_counterexample_reaches_report_findings_when_enabled(self):
        from miesc.agents.deep_audit_agent import DeepAuditAgent, DeepAuditConfig

        agent = DeepAuditAgent(DeepAuditConfig(enable_gap_execution=True, enable_llm=False))
        emitted = agent._counterexample_findings(_SRC, "Vault.sol")
        assert any(f["type"] == "access_control" and "setTreasury" in f["title"] for f in emitted)

    def test_disabled_by_default_emits_nothing_via_flag(self):
        from miesc.agents.deep_audit_agent import DeepAuditConfig

        assert DeepAuditConfig().enable_gap_execution is False


_TB_SRC = """pragma solidity ^0.8.20;
contract Bridge {
  IAdapter adapter;
  function sendMsg(bytes memory _message, address _token) external {
    Params memory params = _decode(_message);
    require(params.inputAsset == _token, "mismatch");
    adapter.newIntent(params.receiver, params.inputAsset, params.amount);
  }
}
"""


class TestTrustBoundaryFindings:
    @staticmethod
    def _plans(src: str):
        from miesc.llm.revert_invariant_mining import mine_revert_invariants

        return mine_revert_invariants(src, None)

    def test_hypothesis_becomes_one_medium_advisory_finding(self):
        from miesc.llm.revert_invariant_findings import trust_boundary_findings

        out = trust_boundary_findings(self._plans(_TB_SRC), _TB_SRC, "Bridge.sol")
        assert len(out) == 1
        f = out[0]
        assert f["severity"] == "Medium"
        assert f["type"] == "access_control"
        assert f["confidence"] < 0.85  # below the verified-counterexample confidence
        assert "sendMsg" in f["title"]
        assert "NOT reproduced" in f["description"]  # marked inferred, not execution-verified
        assert f["evidence"]

    def test_all_validated_emits_nothing(self):
        from miesc.llm.revert_invariant_findings import trust_boundary_findings

        src = _TB_SRC.replace(
            'require(params.inputAsset == _token, "mismatch");',
            "require(params.inputAsset == _token);" " require(params.receiver == _token);",
        )
        assert trust_boundary_findings(self._plans(src), src, "x") == []


class TestTrustBoundarySynthesis:
    def test_flag_off_by_default(self):
        from miesc.agents.deep_audit_agent import DeepAuditConfig

        assert DeepAuditConfig().enable_trust_boundary_findings is False

    def test_agent_emits_medium_finding_when_enabled(self):
        from miesc.agents.deep_audit_agent import DeepAuditAgent, DeepAuditConfig

        agent = DeepAuditAgent(
            DeepAuditConfig(enable_trust_boundary_findings=True, enable_llm=False)
        )
        emitted = agent._trust_boundary_findings(_TB_SRC, "Bridge.sol")
        assert any(f["severity"] == "Medium" and "sendMsg" in f["title"] for f in emitted)
