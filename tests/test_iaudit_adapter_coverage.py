"""Coverage for the iAudit multi-agent adapter.

Exercises the offline surface that needs no live Ollama: the pattern-based
fallback (the bulk of the module), finding normalization, availability
probing (urllib mocked), metadata/config, and the error/cache paths.
"""

import json
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from miesc.adapters.iaudit_adapter import IAuditAdapter
from miesc.core.tool_protocol import ToolStatus

VULNERABLE_SOL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vulnerable {
    mapping(address => uint256) public balances;
    address public owner;
    address public lib;

    function withdraw(uint256 amount) public {
        // external call BEFORE state update -> reentrancy
        (bool ok, ) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
    }

    function setOwner() public {
        // tx.origin authorization -> access control
        require(tx.origin == owner);
        owner = msg.sender;
    }

    function run(bytes memory data) public {
        // delegatecall to untrusted callee
        lib.delegatecall(data);
    }

    function boom() public {
        // unprotected selfdestruct
        selfdestruct(payable(msg.sender));
    }

    function timed() public view returns (bool) {
        // timestamp dependence
        return block.timestamp % 2 == 0;
    }

    function pay(address to) public {
        // unchecked low-level call
        to.call{value: 1 ether}("");
    }
}
"""

MITIGATED_SOL = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract Mitigated is ReentrancyGuard {
    mapping(address => uint256) public balances;
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function withdraw(uint256 amount) public nonReentrant {
        balances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }
}
"""


@pytest.fixture
def adapter():
    return IAuditAdapter()


def _write(tmp_path: Path, name: str, body: str) -> str:
    # A unique marker makes each written contract's content distinct so the
    # content-keyed LLM cache never collides across tests (one test's cached
    # result must not short-circuit another's analyze()).
    p = tmp_path / name
    p.write_text(f"{body}\n// nonce: {uuid.uuid4()}\n", encoding="utf-8")
    return str(p)


# --------------------------------------------------------------------------
# Metadata / config / can_analyze
# --------------------------------------------------------------------------
class TestMetadata:
    def test_metadata_shape(self, adapter):
        md = adapter.get_metadata()
        assert md.name == "iaudit"
        assert md.requires_api_key is False
        assert md.is_optional is True
        assert any(c.name == "multi_agent_audit" for c in md.capabilities)

    def test_default_config(self, adapter):
        cfg = adapter.get_default_config()
        assert cfg["model"] == "qwen2.5-coder:7b"
        assert cfg["fallback_only"] is False
        assert cfg["planner_timeout"] == adapter.DEFAULT_PLANNER_TIMEOUT

    def test_can_analyze(self, adapter, tmp_path):
        assert adapter.can_analyze(str(tmp_path / "C.sol")) is True
        assert adapter.can_analyze(str(tmp_path / "notes.txt")) is False


# --------------------------------------------------------------------------
# Pattern-based fallback (the offline bulk of the module)
# --------------------------------------------------------------------------
class TestPatternFallback:
    def test_fallback_finds_vulnerabilities(self, adapter, tmp_path):
        path = _write(tmp_path, "Vulnerable.sol", VULNERABLE_SOL)
        result = adapter.analyze(path, fallback_only=True)

        assert result["status"] == "success"
        assert result["metadata"]["backend"] == "pattern-fallback"
        assert result["metadata"]["sovereign"] is True
        assert result["from_cache"] is False
        findings = result["findings"]
        assert findings, "vulnerable contract should produce pattern findings"
        types = {f["type"] for f in findings}
        # Several distinct categories should fire on this contract.
        assert len(types) >= 3
        # Reentrancy requires the positional call-before-state check to pass.
        assert "reentrancy" in types
        # Findings are sorted by severity (Critical first).
        severities = [f["severity"] for f in findings]
        assert severities[0] in ("Critical", "High")
        # Each finding carries a source tag and a location.
        for f in findings:
            assert f["source"] == "iaudit-pattern-fallback"
            assert f["location"]["file"] == path
            assert f["location"]["line"] >= 1

    def test_fallback_mitigation_downgrades_confidence(self, adapter, tmp_path):
        path = _write(tmp_path, "Mitigated.sol", MITIGATED_SOL)
        result = adapter.analyze(path, fallback_only=True)
        assert result["status"] == "success"
        # A contract with nonReentrant + require mitigations exercises the
        # has_mitigation branch; any finding kept there carries the lowered
        # confidence (0.45) rather than the un-mitigated 0.75.
        mitigated = [f for f in result["findings"] if f.get("has_mitigation")]
        for f in mitigated:
            assert f["confidence"] == pytest.approx(0.45)

    def test_enclosing_function_resolved(self, adapter, tmp_path):
        path = _write(tmp_path, "Vulnerable.sol", VULNERABLE_SOL)
        result = adapter.analyze(path, fallback_only=True)
        funcs = {f["location"]["function"] for f in result["findings"]}
        # At least one finding should be attributed to a named function.
        assert funcs & {"withdraw", "setOwner", "run", "boom", "timed", "pay"}


# --------------------------------------------------------------------------
# analyze() control paths
# --------------------------------------------------------------------------
class TestAnalyzeControlPaths:
    def test_unreadable_contract_is_error(self, adapter, tmp_path):
        result = adapter.analyze(str(tmp_path / "missing.sol"))
        assert result["status"] == "error"
        assert "Could not read" in result["error"]
        assert result["findings"] == []

    def test_second_call_hits_cache(self, adapter, tmp_path):
        path = _write(tmp_path, "Vulnerable.sol", VULNERABLE_SOL)
        first = adapter.analyze(path, fallback_only=True)
        assert first["from_cache"] is False
        second = adapter.analyze(path, fallback_only=True)
        assert second["from_cache"] is True
        assert second["findings"] == first["findings"]

    def test_ollama_available_runs_pipeline(self, adapter, tmp_path):
        path = _write(tmp_path, "Vulnerable.sol", VULNERABLE_SOL)
        fake = {
            "tool": "iaudit",
            "status": "success",
            "findings": [{"type": "reentrancy", "severity": "High"}],
            "metadata": {"backend": "multi-agent"},
        }
        with patch.object(adapter, "is_available", return_value=ToolStatus.AVAILABLE):
            with patch.object(adapter, "_run_multi_agent_pipeline", return_value=fake) as pipe:
                result = adapter.analyze(path)
        pipe.assert_called_once()
        assert result["metadata"]["backend"] == "multi-agent"


# --------------------------------------------------------------------------
# is_available (urllib mocked)
# --------------------------------------------------------------------------
class TestIsAvailable:
    def _resp(self, payload):
        resp = MagicMock()
        resp.read.return_value = json.dumps(payload).encode("utf-8")
        resp.__enter__.return_value = resp
        resp.__exit__.return_value = False
        return resp

    def test_suitable_model_available(self, adapter):
        payload = {"models": [{"name": "qwen2.5-coder:7b"}]}
        with patch("urllib.request.urlopen", return_value=self._resp(payload)):
            assert adapter.is_available() == ToolStatus.AVAILABLE

    def test_no_suitable_model_is_config_error(self, adapter):
        payload = {"models": [{"name": "some-random-model:1b"}]}
        with patch("urllib.request.urlopen", return_value=self._resp(payload)):
            assert adapter.is_available() == ToolStatus.CONFIGURATION_ERROR

    def test_urlerror_falls_back_to_cli(self, adapter):
        import urllib.error

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("down")):
            with patch.object(
                adapter, "_check_ollama_cli", return_value=ToolStatus.NOT_INSTALLED
            ) as cli:
                assert adapter.is_available() == ToolStatus.NOT_INSTALLED
                cli.assert_called_once()


# --------------------------------------------------------------------------
# normalize_findings + taxonomy / severity helpers
# --------------------------------------------------------------------------
class TestNormalizeFindings:
    def test_from_result_dict(self, adapter):
        raw = {
            "findings": [
                {
                    "id": "x1",
                    "type": "reentrancy",
                    "severity": "critical",
                    "confidence": 0.9,
                    "location": {"file": "C.sol", "line": 10, "function": "withdraw"},
                    "title": "Reentrancy",
                    "swc_id": "SWC-107",
                    "cwe_id": "CWE-841",
                }
            ]
        }
        out = adapter.normalize_findings(raw)
        assert len(out) == 1
        f = out[0]
        assert f["severity"] == "Critical"
        assert f["message"] == "Reentrancy"
        assert f["location"]["line"] == 10
        assert f["swc_id"] == "SWC-107"

    def test_placeholder_taxonomy_dropped(self, adapter):
        out = adapter.normalize_findings(
            [{"severity": "High", "swc_id": "SWC-XXX", "cwe_id": "N/A"}]
        )
        assert out[0]["swc_id"] is None
        assert out[0]["cwe_id"] is None

    def test_location_as_string_and_defaults(self, adapter):
        out = adapter.normalize_findings([{"location": "line 42 of foo()"}])
        assert out[0]["id"] == "iaudit-1"
        assert out[0]["type"] == "ai_detected"
        assert out[0]["severity"] == "Medium"
        assert out[0]["confidence"] == pytest.approx(0.7)
        assert out[0]["location"]["function"] == "line 42 of foo()"

    def test_non_dict_items_skipped(self, adapter):
        out = adapter.normalize_findings(["nope", 5, {"severity": "Low"}])
        assert len(out) == 1
        assert out[0]["severity"] == "Low"

    def test_unknown_input_returns_empty(self, adapter):
        assert adapter.normalize_findings(42) == []

    def test_severity_normalization_table(self, adapter):
        assert adapter._normalize_severity("informational") == "Info"
        assert adapter._normalize_severity("warning") == "Medium"
        assert adapter._normalize_severity("error") == "High"
        assert adapter._normalize_severity("weird") == "Medium"


# --------------------------------------------------------------------------
# Multi-agent pipeline (Ollama touch-point mocked at _call_ollama_api)
# --------------------------------------------------------------------------
PLANNER_OK = '{"scope": "audit plan", "entry_points": ["withdraw"], "attack_surface": "funds"}'


def _detector(findings):
    return json.dumps({"findings": findings})


def _reviewer(items):
    return json.dumps({"reviewed_findings": items})


class TestMultiAgentPipeline:
    def _run(self, adapter, tmp_path, responses, **kwargs):
        path = _write(tmp_path, "C.sol", VULNERABLE_SOL)
        with patch.object(adapter, "is_available", return_value=ToolStatus.AVAILABLE):
            with patch.object(adapter, "_call_ollama_api", side_effect=responses):
                return adapter.analyze(path, model="codellama:7b", **kwargs)

    def test_full_pipeline_confirmed_and_fp(self, adapter, tmp_path):
        det = _detector(
            [
                {
                    "id": "d1",
                    "type": "reentrancy",
                    "severity": "Critical",
                    "title": "Reentrancy in withdraw",
                    "confidence": 0.8,
                },
                {
                    "id": "d2",
                    "type": "timestamp_dependence",
                    "severity": "Low",
                    "title": "Timestamp use",
                    "confidence": 0.6,
                },
            ]
        )
        rev = _reviewer(
            [
                {"original_id": "d1", "verdict": "confirmed", "adjusted_confidence": 0.9},
                {"original_id": "d2", "verdict": "false_positive"},
            ]
        )
        result = self._run(adapter, tmp_path, [PLANNER_OK, det, rev])
        assert result["status"] == "success"
        assert result["metadata"]["backend"] == "ollama"
        assert result["metadata"]["reviewer_applied"] is True
        assert result["metadata"]["false_positives_removed"] == 1
        ids = {f["id"] for f in result["findings"]}
        assert ids == {"d1"}  # non-critical FP dropped
        assert result["findings"][0]["confidence"] == pytest.approx(0.9)
        assert result["findings"][0]["reviewed"] is True

    def test_downgraded_needs_context_and_unreviewed(self, adapter, tmp_path):
        det = _detector(
            [
                {
                    "id": "d1",
                    "type": "access_control",
                    "severity": "High",
                    "title": "AC",
                    "confidence": 0.8,
                },
                {
                    "id": "d2",
                    "type": "other",
                    "severity": "Medium",
                    "title": "Ctx",
                    "confidence": 0.7,
                },
                {
                    "id": "d3",
                    "type": "other",
                    "severity": "Low",
                    "title": "Orphan",
                    "confidence": 0.7,
                },
            ]
        )
        rev = _reviewer(
            [
                {
                    "original_id": "d1",
                    "verdict": "downgraded",
                    "adjusted_severity": "low",
                    "adjusted_confidence": 0.5,
                },
                {"original_id": "d2", "verdict": "needs_context"},
            ]
        )
        result = self._run(adapter, tmp_path, [PLANNER_OK, det, rev])
        by_id = {f["id"]: f for f in result["findings"]}
        assert by_id["d1"]["severity"] == "Low"
        assert by_id["d1"]["confidence"] == pytest.approx(0.5)
        assert by_id["d2"]["needs_context"] is True
        # d3 had no verdict -> kept, flagged unreviewed with lowered confidence.
        assert by_id["d3"]["reviewed"] is False
        assert by_id["d3"]["confidence"] == pytest.approx(0.6)

    def test_critical_fp_is_overridden_not_dropped(self, adapter, tmp_path):
        det = _detector(
            [
                {
                    "id": "d1",
                    "type": "reentrancy",
                    "severity": "Critical",
                    "title": "Crit",
                    "confidence": 0.8,
                }
            ]
        )
        rev = _reviewer([{"original_id": "d1", "verdict": "false_positive"}])
        result = self._run(adapter, tmp_path, [PLANNER_OK, det, rev])
        # Critical finding is kept despite the FP verdict, with reduced confidence.
        assert [f["id"] for f in result["findings"]] == ["d1"]
        assert result["findings"][0]["review_verdict"] == "false_positive_overridden"

    def test_skip_reviewer(self, adapter, tmp_path):
        det = _detector(
            [
                {
                    "id": "d1",
                    "type": "reentrancy",
                    "severity": "High",
                    "title": "R",
                    "confidence": 0.8,
                }
            ]
        )
        # Only planner + detector are consumed when the reviewer is skipped.
        result = self._run(adapter, tmp_path, [PLANNER_OK, det], skip_reviewer=True)
        assert result["metadata"]["reviewer_applied"] is False
        assert [f["id"] for f in result["findings"]] == ["d1"]

    def test_planner_failure_falls_back_to_pattern(self, adapter, tmp_path):
        # Empty planner response -> pipeline degrades to pattern analysis.
        result = self._run(adapter, tmp_path, ["", "unused"])
        assert result["metadata"]["backend"] == "pattern-fallback"

    def test_detector_empty_findings_is_clean_success(self, adapter, tmp_path):
        result = self._run(adapter, tmp_path, [PLANNER_OK, _detector([])])
        assert result["status"] == "success"
        assert result["findings"] == []
        assert result["metadata"]["detector_findings_count"] == 0

    def test_reviewer_failure_keeps_detector_findings(self, adapter, tmp_path):
        det = _detector(
            [
                {
                    "id": "d1",
                    "type": "reentrancy",
                    "severity": "High",
                    "title": "R",
                    "confidence": 0.8,
                }
            ]
        )
        # Empty reviewer response -> raw detector findings kept, reviewer not applied.
        result = self._run(adapter, tmp_path, [PLANNER_OK, det, ""])
        assert result["metadata"]["reviewer_applied"] is False
        assert [f["id"] for f in result["findings"]] == ["d1"]

    def test_reviewer_text_fallback_marks_fp(self, adapter, tmp_path):
        det = _detector(
            [
                {
                    "id": "d1",
                    "type": "reentrancy",
                    "severity": "Medium",
                    "title": "ReentrancyBug",
                    "confidence": 0.8,
                }
            ]
        )
        # Non-JSON reviewer output triggers the keyword text fallback; the
        # finding title appears near "false positive" -> dropped (non-critical).
        rev_text = "The finding reentrancybug is a false positive, not exploitable."
        result = self._run(adapter, tmp_path, [PLANNER_OK, det, rev_text])
        assert result["findings"] == []


# --------------------------------------------------------------------------
# CLI availability + model detection (subprocess / urllib mocked)
# --------------------------------------------------------------------------
class TestCliAndModelDetection:
    def _completed(self, returncode, stdout=""):
        cp = MagicMock()
        cp.returncode = returncode
        cp.stdout = stdout
        return cp

    def test_cli_finds_model(self, adapter):
        with patch("subprocess.run", return_value=self._completed(0, "qwen2.5-coder:7b  4GB")):
            assert adapter._check_ollama_cli() == ToolStatus.AVAILABLE

    def test_cli_no_suitable_model(self, adapter):
        with patch("subprocess.run", return_value=self._completed(0, "random-model:1b")):
            assert adapter._check_ollama_cli() == ToolStatus.CONFIGURATION_ERROR

    def test_cli_nonzero_returncode(self, adapter):
        with patch("subprocess.run", return_value=self._completed(1, "")):
            assert adapter._check_ollama_cli() == ToolStatus.CONFIGURATION_ERROR

    def test_cli_not_installed(self, adapter):
        with patch("subprocess.run", side_effect=FileNotFoundError()):
            assert adapter._check_ollama_cli() == ToolStatus.NOT_INSTALLED

    def test_cli_timeout(self, adapter):
        import subprocess

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("ollama", 10)):
            assert adapter._check_ollama_cli() == ToolStatus.CONFIGURATION_ERROR

    def test_detect_model_env_override(self, adapter):
        with patch.dict("os.environ", {"MIESC_LLM_MODEL": "codellama:13b"}, clear=False):
            assert adapter._detect_best_model() == "codellama:13b"

    def test_detect_model_via_api(self, adapter):
        payload = {"models": [{"name": "qwen2.5-coder:14b"}, {"name": "codellama:7b"}]}
        resp = MagicMock()
        resp.read.return_value = json.dumps(payload).encode("utf-8")
        resp.__enter__.return_value = resp
        resp.__exit__.return_value = False
        with patch.dict("os.environ", {}, clear=True):
            with patch("urllib.request.urlopen", return_value=resp):
                # Highest-priority *installed* exact match wins; 7b is not
                # present, so 14b (next in MODEL_PRIORITY) is selected.
                assert adapter._detect_best_model() == "qwen2.5-coder:14b"

    def test_detect_model_final_fallback(self, adapter):
        import urllib.error

        with patch.dict("os.environ", {}, clear=True):
            with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("x")):
                with patch("subprocess.run", side_effect=FileNotFoundError()):
                    assert adapter._detect_best_model() == "qwen2.5-coder:14b"
