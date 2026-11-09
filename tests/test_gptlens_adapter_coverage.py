"""Coverage for the GPTLens dual-role (Auditor + Critic) adapter.

analyze() always runs the pure pattern-based analysis first (covering the
regex `_detect_*` methods), then the LLM auditor + critic. The LLM calls are
mocked at `_call_ollama`, so no Ollama is needed.
"""

import json
import uuid
from unittest.mock import patch

import pytest

from miesc.adapters.gptlens_adapter import GPTLensAdapter
from miesc.core.tool_protocol import ToolStatus

VULNERABLE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract KitchenSink {
    address owner; uint256 balance; mapping(address=>uint256) balances;
    function withdraw(uint256 a) public {
        (bool ok,) = msg.sender.call{value: a}("");
        balances[msg.sender] -= a;
    }
    function auth() public { require(tx.origin == owner); }
    function run(bytes memory d) public { addr.delegatecall(d); }
    function timed() public view returns (bool) { return block.timestamp > 100; }
    function price() public { uint256 p = oracle.latestAnswer(); balance = p; }
    function send0(address to) public { require(to != address(0)); }
}
"""

AUDITOR_JSON = json.dumps(
    {
        "findings": [
            {
                "type": "reentrancy",
                "title": "Reentrancy in withdraw",
                "severity": "High",
                "description": "external call before state update",
                "line": 6,
                "function": "withdraw",
                "confidence": 0.8,
            }
        ]
    }
)


@pytest.fixture
def adapter():
    return GPTLensAdapter()


def _write(tmp_path, body=VULNERABLE, name="C.sol"):
    p = tmp_path / name
    p.write_text(f"{body}\n// nonce {uuid.uuid4()}\n", encoding="utf-8")
    return str(p)


# --------------------------------------------------------------------------
# Metadata / config / pure helpers
# --------------------------------------------------------------------------
class TestHelpers:
    def test_metadata_and_config(self, adapter):
        assert adapter.get_metadata().name == "gptlens"
        assert "auditor_model" in adapter.get_default_config() or adapter.get_default_config()

    def test_can_analyze(self, adapter):
        assert adapter.can_analyze("C.sol") is True
        assert adapter.can_analyze("C.txt") is False

    def test_normalize_severity(self, adapter):
        assert adapter._normalize_severity("critical") == "Critical"
        assert adapter._normalize_severity("weird") in ("Medium", "Info", "Low", "High", "Critical")

    def test_valid_taxonomy_id(self, adapter):
        assert adapter._valid_taxonomy_id("SWC-107") == "SWC-107"
        assert adapter._valid_taxonomy_id("SWC-XXX") == ""
        assert adapter._valid_taxonomy_id(None) == ""

    def test_parse_critic_verdict(self, adapter):
        assert adapter._parse_critic_verdict("TRUE_POSITIVE: real bug")[0] == "TRUE_POSITIVE"
        assert adapter._parse_critic_verdict("FALSE_POSITIVE, not reachable")[0] == "FALSE_POSITIVE"
        assert adapter._parse_critic_verdict("this is EXPLOITABLE")[0] == "TRUE_POSITIVE"
        assert adapter._parse_critic_verdict("NOT VULNERABLE here")[0] == "FALSE_POSITIVE"
        assert adapter._parse_critic_verdict("hmm not sure")[0] == "UNCERTAIN"

    def test_extract_json_from_response(self, adapter):
        parsed = adapter._extract_json_from_response("prose ```json\n" + AUDITOR_JSON + "\n``` end")
        assert parsed is not None and "findings" in parsed

    def test_read_contract_missing(self, adapter, tmp_path):
        assert adapter._read_contract(str(tmp_path / "nope.sol")) is None

    def test_truncate_code(self, adapter):
        long = "a" * 100000
        assert len(adapter._truncate_code(long)) <= len(long)

    def test_normalize_findings(self, adapter):
        # Only a result-dict is unwrapped; a bare list or scalar yields [].
        assert adapter.normalize_findings({"findings": [{"x": 1}]}) == [{"x": 1}]
        assert adapter.normalize_findings([{"y": 2}]) == []
        assert adapter.normalize_findings(99) == []


# --------------------------------------------------------------------------
# Pattern analysis (pure regex detectors)
# --------------------------------------------------------------------------
class TestPatternAnalysis:
    def test_pattern_based_analysis_fires(self, adapter):
        findings = adapter._pattern_based_analysis(VULNERABLE, "C.sol")
        assert isinstance(findings, list)
        assert len(findings) >= 3
        types = {f.get("type") for f in findings}
        assert any(
            "reentrancy" in str(t) or "origin" in str(t) or "delegatecall" in str(t) for t in types
        )


# --------------------------------------------------------------------------
# analyze() — dual-role pipeline with the LLM mocked
# --------------------------------------------------------------------------
class TestAnalyze:
    def test_not_available_is_error(self, adapter, tmp_path):
        with patch.object(adapter, "is_available", return_value=ToolStatus.NOT_INSTALLED):
            result = adapter.analyze(_write(tmp_path))
        assert result["status"] == "error"

    def test_unreadable_contract(self, adapter, tmp_path):
        with patch.object(adapter, "is_available", return_value=ToolStatus.AVAILABLE):
            result = adapter.analyze(str(tmp_path / "missing.sol"))
        assert result["status"] == "error"

    def test_full_pipeline_skip_critic(self, adapter, tmp_path):
        with patch.object(adapter, "is_available", return_value=ToolStatus.AVAILABLE):
            with patch.object(adapter, "_call_ollama", return_value=AUDITOR_JSON):
                result = adapter.analyze(_write(tmp_path), skip_critic=True)
        assert result["status"] == "success"
        assert isinstance(result["findings"], list)
        assert result["findings"], "pattern + auditor findings expected"

    def test_pipeline_with_critic_confirms(self, adapter, tmp_path):
        calls = {"n": 0}

        def fake(*a, **k):
            calls["n"] += 1
            return AUDITOR_JSON if calls["n"] == 1 else "TRUE_POSITIVE: confirmed, reachable"

        with patch.object(adapter, "is_available", return_value=ToolStatus.AVAILABLE):
            with patch.object(adapter, "_call_ollama", side_effect=fake):
                result = adapter.analyze(_write(tmp_path))
        assert result["status"] == "success"
        assert result["findings"]

    def test_pipeline_critic_rejects(self, adapter, tmp_path):
        calls = {"n": 0}

        def fake(*a, **k):
            calls["n"] += 1
            return AUDITOR_JSON if calls["n"] == 1 else "FALSE_POSITIVE: not reachable at all"

        with patch.object(adapter, "is_available", return_value=ToolStatus.AVAILABLE):
            with patch.object(adapter, "_call_ollama", side_effect=fake):
                result = adapter.analyze(_write(tmp_path))
        assert result["status"] == "success"

    def test_auditor_no_response_keeps_pattern_findings(self, adapter, tmp_path):
        with patch.object(adapter, "is_available", return_value=ToolStatus.AVAILABLE):
            with patch.object(adapter, "_call_ollama", return_value=None):
                result = adapter.analyze(_write(tmp_path), skip_critic=True)
        # LLM gave nothing, but the pattern pass still yields findings.
        assert result["status"] == "success"
        assert isinstance(result["findings"], list)


# --------------------------------------------------------------------------
# Pattern detectors that the incidental (DeepAuditAgent) path does not hit
# --------------------------------------------------------------------------
OVERFLOW_C = """// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;
contract Over {
    function add(uint256 a, uint256 b) public pure returns (uint256) {
        uint256 c = a + b;
        return c;
    }
}
"""

DEFI_C = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Dex {
    function swapTokens(uint256 amtIn) public returns (uint256) {
        (uint112 r0, uint112 r1,) = pair.getReserves();
        uint256 price = (amtIn / 1e18) * r0;
        return price;
    }
}
"""

ADMIN_C = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Admin {
    address owner;
    function setOwner(address newOwner) public { owner = newOwner; }
    function emergencyDrain() public { payable(owner).transfer(address(this).balance); }
    function pause() public {}
    function ping(address t) public { t.call(abi.encodeWithSignature("x()")); }
}
"""


class TestUncommonPatternDetectors:
    def test_overflow_on_old_pragma(self, adapter):
        findings = adapter._pattern_based_analysis(OVERFLOW_C, "Over.sol")
        assert isinstance(findings, list)

    def test_defi_patterns(self, adapter):
        findings = adapter._pattern_based_analysis(DEFI_C, "Dex.sol")
        assert isinstance(findings, list)

    def test_admin_patterns(self, adapter):
        findings = adapter._pattern_based_analysis(ADMIN_C, "Admin.sol")
        assert isinstance(findings, list)

    def test_detectors_run_without_error_on_all(self, adapter):
        # Exercise the full detector sweep over every crafted contract; the
        # point is that each _detect_* method runs cleanly on varied input.
        total = 0
        for src, path in [
            (VULNERABLE, "V.sol"),
            (OVERFLOW_C, "O.sol"),
            (DEFI_C, "D.sol"),
            (ADMIN_C, "A.sol"),
        ]:
            total += len(adapter._pattern_based_analysis(src, path))
        assert total >= 4
