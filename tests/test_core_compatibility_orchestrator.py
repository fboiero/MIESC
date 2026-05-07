from pathlib import Path
from unittest.mock import Mock

from miesc.core.orchestrator import MIESCOrchestrator


def test_compatibility_orchestrator_reports_supported_and_skipped_tools(
    monkeypatch, tmp_path: Path
):
    contract = tmp_path / "Contract.sol"
    contract.write_text("pragma solidity ^0.8.20; contract Contract {}", encoding="utf-8")

    def fake_run(cmd, **kwargs):
        if cmd[:2] == ["slither", "--version"]:
            return Mock(returncode=0, stdout="", stderr="")
        if cmd[:2] == ["myth", "version"]:
            return Mock(returncode=1, stdout="", stderr="")
        if cmd[0] == "slither":
            return Mock(returncode=0, stdout='{"results":{"detectors":[]}}', stderr="")
        raise AssertionError(f"unexpected command: {cmd}")

    monkeypatch.setattr("miesc.core.orchestrator.subprocess.run", fake_run)

    orchestrator = MIESCOrchestrator()
    result = orchestrator.audit(str(contract), layers=[1], tools=["slither", "aderyn"])

    assert result["orchestrator_mode"] == "compatibility"
    assert result["supported_tools"] == ["mythril", "slither"]
    assert result["layers_run"][0]["tools_run"] == ["slither"]
    assert result["layers_run"][0]["tools_skipped"] == [
        {
            "tool": "aderyn",
            "reason": "not_implemented_in_compatibility_orchestrator",
        }
    ]
