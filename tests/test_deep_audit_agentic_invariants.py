"""Tests for opt-in agentic invariant metadata in DeepAuditAgent."""

from miesc.agents.deep_audit_agent import DeepAuditAgent, DeepAuditConfig, ReconResult, ScanResult


def test_deep_audit_extracts_agentic_invariant_metadata_locally():
    agent = DeepAuditAgent(
        DeepAuditConfig(
            enable_agentic_invariants=True,
            agentic_invariants_allow_remote=False,
            enable_llm=False,
        )
    )

    phase = agent._extract_agentic_invariants(
        """
        contract Vault {
            uint256 public totalSupply;
            uint256 public totalAssets;
            function deposit(uint256 amount) external {}
            function withdraw(uint256 shares) external {}
        }
        """,
        "Vault.sol",
        findings=[],
    )

    assert phase["enabled"] is True
    assert phase["policy"]["local_first"] is True
    assert phase["policy"]["allow_remote"] is False
    assert phase["count"] >= 1
    assert phase["candidates"][0]["category"] == "accounting"


def test_deep_audit_agentic_invariants_are_metadata_only(monkeypatch, tmp_path):
    contract = tmp_path / "Vault.sol"
    contract.write_text("""
        pragma solidity ^0.8.20;
        contract Vault {
            uint256 public totalSupply;
            uint256 public totalAssets;
            function deposit(uint256 amount) external {}
        }
        """)
    finding = {"id": "static-1", "severity": "HIGH", "type": "reentrancy"}
    agent = DeepAuditAgent(
        DeepAuditConfig(
            enable_agentic_invariants=True,
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
        lambda *_args, **_kwargs: ReconResult(risk_profile={"primary": "general"}),
    )
    monkeypatch.setattr(
        agent,
        "_phase_targeted_scan",
        lambda *_args, **_kwargs: ScanResult(
            tools_run=["slither"],
            raw_findings=[finding],
            filtered_findings=[finding],
        ),
    )
    monkeypatch.setattr(
        agent,
        "_phase_deep_investigation",
        lambda *_args, **_kwargs: {
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
        lambda *_args, **_kwargs: {
            "findings": [finding],
            "exploit_chains": [],
            "summary": {"HIGH": 1, "total": 1},
            "narrative": "",
            "has_llm_narrative": False,
        },
    )

    report = agent.analyze(str(contract))

    assert report["findings"] == [finding]
    assert report["phases"]["agentic_invariants"]["count"] >= 1
    assert report["metadata"]["agentic_invariants_count"] >= 1
