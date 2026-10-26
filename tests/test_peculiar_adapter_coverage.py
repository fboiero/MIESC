"""Coverage for the Peculiar (code-property-graph) adapter.

No GNN model is present in the test env, so analyze() exercises the real
pattern-analysis fallback end to end (graph build -> pattern analysis ->
findings) with no network or model files.
"""

import json

import pytest

from miesc.adapters.peculiar_adapter import PeculiarAdapter
from miesc.core.tool_protocol import ToolStatus

VULNERABLE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Bank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] -= amount;
    }
}
"""

BENIGN = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract C { uint256 public x; function setX(uint256 v) external { x = v; } }
"""


@pytest.fixture
def adapter():
    # Low threshold so pattern findings are not filtered out.
    return PeculiarAdapter(config={"confidence_threshold": 0.1})


def _write(tmp_path, body, name="C.sol"):
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return str(p)


class TestMetadataAndConfig:
    def test_is_available_always(self, adapter):
        assert adapter.is_available() == ToolStatus.AVAILABLE

    def test_metadata(self, adapter):
        md = adapter.get_metadata()
        assert md.name == "peculiar"

    def test_default_config(self, adapter):
        cfg = adapter.get_default_config()
        assert "confidence_threshold" in cfg
        assert cfg["enable_taint_analysis"] is True

    def test_can_analyze(self, adapter):
        assert adapter.can_analyze("C.sol") is True
        assert adapter.can_analyze("C.txt") is False


class TestAnalyze:
    def test_analyze_vulnerable_pattern_fallback(self, adapter, tmp_path):
        result = adapter.analyze(_write(tmp_path, VULNERABLE))
        assert result["status"] == "success"
        assert result["metadata"]["analysis_mode"] == "pattern_fallback"
        assert "graph_stats" in result["metadata"]
        assert isinstance(result["findings"], list)
        assert result["metadata"]["num_findings"] == len(result["findings"])

    def test_analyze_benign_runs_clean(self, adapter, tmp_path):
        result = adapter.analyze(_write(tmp_path, BENIGN))
        assert result["status"] == "success"
        assert isinstance(result["findings"], list)

    def test_analyze_missing_file_is_error(self, adapter, tmp_path):
        result = adapter.analyze(str(tmp_path / "nope.sol"))
        assert result["status"] == "error"
        assert result["findings"] == []

    def test_analyze_exports_graph(self, adapter, tmp_path):
        out = tmp_path / "graph.json"
        adapter.analyze(_write(tmp_path, VULNERABLE), output_graph=str(out))
        assert out.exists()
        # Exported graph is valid JSON.
        json.loads(out.read_text(encoding="utf-8"))


class TestNormalizeFindings:
    def test_passthrough_result_dict(self, adapter):
        out = adapter.normalize_findings({"findings": [{"type": "reentrancy"}]})
        assert out == [{"type": "reentrancy"}]

    def test_raw_predictions_filtered_by_confidence(self, adapter):
        raw = [
            {"type": "reentrancy", "confidence": 0.9, "location": {"line": 5}},
            {"type": "reentrancy", "confidence": 0.05},  # below the adapter threshold
        ]
        out = adapter.normalize_findings(raw)
        assert len(out) == 1
        assert out[0]["type"] == "reentrancy"
        assert out[0]["confidence"] == 0.9
        assert out[0]["id"].startswith("PECULIAR-")

    def test_unknown_input(self, adapter):
        assert adapter.normalize_findings(42) == []
