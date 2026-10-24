"""Tests for the opt-in deterministic advisory-plan phase in DeepAuditAgent.

The phase runs the LLM-free plan miners (revert-invariant, privileged-governance,
resource/liveness-griefing, lending-solvency) and surfaces their plans as report
metadata. It is advisory: plans are dicts, never Findings, so it adds no precision risk.
"""

from miesc.agents.deep_audit_agent import DeepAuditAgent, DeepAuditConfig, ReconResult, ScanResult

BANK = """
pragma solidity ^0.8.20;
contract Bank {
    address public owner;
    mapping(address => uint256) public balances;
    address[] public depositors;
    function deposit() external payable {
        require(msg.value > 0, "zero");
        if (balances[msg.sender] == 0) { depositors.push(msg.sender); }
        balances[msg.sender] += msg.value;
    }
    function payoutAll() external {
        require(msg.sender == owner, "not owner");
        for (uint256 i = 0; i < depositors.length; i++) {
            payable(depositors[i]).transfer(balances[depositors[i]]);
        }
    }
}
"""

_CAPABILITIES = {
    "revert_invariants",
    "privileged_governance",
    "resource_liveness_griefing",
    "lending_solvency_liquidation",
}


def test_advisory_plans_off_by_default():
    assert DeepAuditConfig().enable_advisory_plans is False


def test_extract_advisory_plans_runs_every_miner_locally():
    agent = DeepAuditAgent(DeepAuditConfig(enable_advisory_plans=True, enable_llm=False))
    phase = agent._extract_advisory_plans(BANK, "Bank.sol")

    assert phase["enabled"] is True
    assert set(phase["capabilities"]) == _CAPABILITIES
    # the BANK fixture has guards (require) and a growable+traversed array
    assert phase["capabilities"]["revert_invariants"]["count"] >= 1
    assert phase["capabilities"]["resource_liveness_griefing"]["count"] >= 1
    assert phase["count"] == sum(c["count"] for c in phase["capabilities"].values())
    assert all("error" not in c for c in phase["capabilities"].values())


def test_advisory_plans_are_plans_never_findings():
    agent = DeepAuditAgent(DeepAuditConfig(enable_advisory_plans=True, enable_llm=False))
    phase = agent._extract_advisory_plans(BANK, "Bank.sol")

    plan = phase["capabilities"]["revert_invariants"]["plans"][0]
    assert isinstance(plan, dict)
    assert "severity" not in plan  # a plan is advisory, not a Finding
    assert plan["promotion"]["state"] == "hypothesis"
    assert plan["metadata"]["capability"] == "revert_invariant_mining"


def test_extract_advisory_plans_never_raises_on_empty_or_garbage():
    agent = DeepAuditAgent(DeepAuditConfig(enable_advisory_plans=True, enable_llm=False))
    for src in ("", "   ", "not solidity at all {{{"):
        phase = agent._extract_advisory_plans(src, "x.sol")
        assert phase["enabled"] is True
        assert phase["count"] == 0
        assert set(phase["capabilities"]) == _CAPABILITIES


def test_advisory_miner_failure_is_isolated(monkeypatch):
    agent = DeepAuditAgent(DeepAuditConfig(enable_advisory_plans=True, enable_llm=False))

    def boom(*_args, **_kwargs):
        raise RuntimeError("miner blew up")

    monkeypatch.setattr("miesc.llm.mine_revert_invariants", boom)
    phase = agent._extract_advisory_plans(BANK, "Bank.sol")

    assert phase["capabilities"]["revert_invariants"]["error"] == "miner blew up"
    assert phase["capabilities"]["revert_invariants"]["count"] == 0
    # the other miners still run
    assert phase["capabilities"]["resource_liveness_griefing"]["count"] >= 1


def test_advisory_plans_phase_is_metadata_only(tmp_path, monkeypatch):
    contract = tmp_path / "Bank.sol"
    contract.write_text(BANK)
    finding = {"id": "static-1", "severity": "HIGH", "type": "reentrancy"}
    agent = DeepAuditAgent(
        DeepAuditConfig(
            enable_advisory_plans=True,
            enable_llm=False,
            enable_rag=False,
            enable_taint=False,
            enable_call_graph=False,
            enable_exploit_chains=False,
        )
    )

    monkeypatch.setattr(
        agent,
        "_phase_reconnaissance",
        lambda *_a, **_k: ReconResult(risk_profile={"primary": "general"}),
    )
    monkeypatch.setattr(
        agent,
        "_phase_targeted_scan",
        lambda *_a, **_k: ScanResult(
            tools_run=["slither"], raw_findings=[finding], filtered_findings=[finding]
        ),
    )
    monkeypatch.setattr(
        agent,
        "_phase_deep_investigation",
        lambda *_a, **_k: {
            "findings": [finding],
            "exploit_chains": [],
            "iterations": 0,
            "enriched_count": 0,
            "additional_tools": [],
            "mitigated_count": 0,
        },
    )
    monkeypatch.setattr(
        agent,
        "_phase_synthesis",
        lambda *_a, **_k: {
            "findings": [finding],
            "exploit_chains": [],
            "summary": {"HIGH": 1, "total": 1},
            "narrative": "",
            "has_llm_narrative": False,
        },
    )

    report = agent.analyze(str(contract))

    # the phase ran and is surfaced, but it did not touch the finding set
    assert report["findings"] == [finding]
    assert set(report["phases"]["advisory_plans"]["capabilities"]) == _CAPABILITIES
    assert report["metadata"]["advisory_plan_count"] == report["phases"]["advisory_plans"]["count"]


# A contract with an inconsistent pause gate: `deposit` is pause-gated, `withdraw` is not.
PAUSE_GAP = """
pragma solidity ^0.8.20;
contract Vault {
    bool public paused;
    uint256 bal;
    modifier whenNotPaused() { require(!paused, "paused"); _; }
    function deposit() external whenNotPaused { bal += 1; }
    function withdraw() external { bal -= 1; }
}
"""


def test_advisory_phase_surfaces_bridged_oracle_plans():
    from miesc.llm.agentic_contracts import parse_sequence_oracle_plans

    agent = DeepAuditAgent(DeepAuditConfig(enable_advisory_plans=True, enable_llm=False))
    phase = agent._extract_advisory_plans(PAUSE_GAP, "Vault.sol")

    ri = phase["capabilities"]["revert_invariants"]
    # the bridge adds an advisory oracle-plan surface alongside the raw inventory
    assert "oracle_plans" in ri
    assert len(ri["oracle_plans"]) >= 1
    # the bridged plans are valid sequence-oracle plans (they round-trip through the parser)
    reparsed = parse_sequence_oracle_plans({"plans": ri["oracle_plans"]})
    assert len(reparsed) == len(ri["oracle_plans"])
    # still advisory: dicts, low confidence, never Findings
    op = ri["oracle_plans"][0]
    assert op["confidence"] == 0.2
    assert op["metadata"]["advisory"] == "true"


def test_advisory_phase_surfaces_test_generated_harnesses():
    agent = DeepAuditAgent(DeepAuditConfig(enable_advisory_plans=True, enable_llm=False))
    phase = agent._extract_advisory_plans(PAUSE_GAP, "Vault.sol")

    ri = phase["capabilities"]["revert_invariants"]
    assert "harnesses" in ri
    assert len(ri["harnesses"]) >= 1
    art = ri["harnesses"][0]
    # test_generated rung: a harness exists, with recorded blockers, never auto-executed.
    assert art["promotion_state"] == "test_generated"
    assert art["blockers"]
    assert "vm.expectRevert()" in art["foundry_harness"]
    # pause harness must not fabricate a pauser call.
    assert "pause()" not in art["foundry_harness"]
