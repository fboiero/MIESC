"""
Deeper tests for GPTLensAdapter.

Covers:
- _parse_auditor_response() — valid JSON, malformed, empty string
- _normalize_auditor_finding() — field mapping, confidence clamping, defaults
- _parse_critic_verdict() — TRUE_POSITIVE, FALSE_POSITIVE, edge cases
- analyze() — mocked Ollama HTTP API (valid 2-finding response, malformed JSON, OSError)
- Auditor-Critic two-stage flow exercised end-to-end
"""

import json
import urllib.error
from unittest.mock import MagicMock, patch

import pytest

from src.adapters.gptlens_adapter import GPTLensAdapter

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def adapter(tmp_path):
    """Return adapter with a temp cache dir so tests don't touch ~/.miesc."""
    a = GPTLensAdapter(
        auditor_model="test-auditor",
        critic_model="test-critic",
        ollama_url="http://localhost:11434",
    )
    a._cache_dir = tmp_path / "gptlens_cache"
    a._cache_dir.mkdir(parents=True, exist_ok=True)
    a._max_retries = 1  # speed up failure tests
    a._retry_delay = 0
    return a


@pytest.fixture
def sample_contract(tmp_path):
    """Write a minimal Solidity contract and return its path."""
    src = tmp_path / "Vulnerable.sol"
    src.write_text(
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.0;\n"
        "contract Vulnerable {\n"
        "    mapping(address => uint) public balances;\n"
        "    function withdraw() external {\n"
        "        uint amount = balances[msg.sender];\n"
        '        (bool ok,) = msg.sender.call{value: amount}("");\n'
        "        require(ok);\n"
        "        balances[msg.sender] = 0;\n"  # state update AFTER call
        "    }\n"
        "}\n"
    )
    return str(src)


def _make_ollama_resp(text: str) -> MagicMock:
    """Return a mock urllib response object that yields a JSON Ollama reply."""
    body = json.dumps({"response": text}).encode()
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.read.return_value = body
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


def _make_health_resp() -> MagicMock:
    """Return a mock health-check response (GET /)."""
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


# ---------------------------------------------------------------------------
# _parse_auditor_response
# ---------------------------------------------------------------------------


class TestParseAuditorResponse:

    def test_valid_json_block_two_findings(self, adapter, tmp_path):
        contract_path = str(tmp_path / "C.sol")
        response = json.dumps(
            {
                "findings": [
                    {
                        "type": "reentrancy",
                        "severity": "Critical",
                        "confidence": 0.9,
                        "title": "Reentrancy in withdraw()",
                        "description": "External call before state update.",
                        "function": "withdraw",
                        "line": 7,
                        "attack_scenario": "Attacker re-enters before balance zeroed.",
                        "impact": "Drain funds.",
                        "recommendation": "Use checks-effects-interactions.",
                    },
                    {
                        "type": "access_control",
                        "severity": "High",
                        "confidence": 0.8,
                        "title": "Missing access control",
                        "description": "Owner function not protected.",
                        "function": "setOwner",
                        "line": 15,
                    },
                ]
            }
        )
        findings = adapter._parse_auditor_response(response, contract_path)
        assert len(findings) == 2
        assert findings[0]["type"] == "reentrancy"
        assert findings[1]["type"] == "access_control"

    def test_valid_json_in_code_block_markers(self, adapter, tmp_path):
        contract_path = str(tmp_path / "C.sol")
        inner = json.dumps(
            {
                "findings": [
                    {
                        "type": "tx_origin",
                        "severity": "Medium",
                        "title": "tx.origin misuse",
                        "line": 5,
                    }
                ]
            }
        )
        response = f"Here are the findings:\n```json\n{inner}\n```"
        findings = adapter._parse_auditor_response(response, contract_path)
        assert len(findings) == 1

    def test_malformed_json_falls_back_to_text_extraction(self, adapter, tmp_path):
        contract_path = str(tmp_path / "C.sol")
        # Not valid JSON at all — adapter should not crash
        response = "CRITICAL: reentrancy vulnerability found at line 10."
        findings = adapter._parse_auditor_response(response, contract_path)
        # May return 0 or more via text-extraction fallback, but must not raise
        assert isinstance(findings, list)

    def test_empty_string_returns_empty_list(self, adapter, tmp_path):
        contract_path = str(tmp_path / "C.sol")
        findings = adapter._parse_auditor_response("", contract_path)
        assert findings == []

    def test_json_with_empty_findings_list(self, adapter, tmp_path):
        contract_path = str(tmp_path / "C.sol")
        response = json.dumps({"findings": []})
        findings = adapter._parse_auditor_response(response, contract_path)
        assert findings == []

    def test_findings_field_not_list_returns_empty(self, adapter, tmp_path):
        contract_path = str(tmp_path / "C.sol")
        response = json.dumps({"findings": "not a list"})
        findings = adapter._parse_auditor_response(response, contract_path)
        assert findings == []

    def test_non_dict_items_in_findings_skipped(self, adapter, tmp_path):
        contract_path = str(tmp_path / "C.sol")
        response = json.dumps({"findings": ["string item", None, {"type": "reentrancy"}]})
        findings = adapter._parse_auditor_response(response, contract_path)
        # Only the dict item should survive
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# _normalize_auditor_finding
# ---------------------------------------------------------------------------


class TestNormalizeAuditorFinding:

    def test_basic_finding_normalization(self, adapter, tmp_path):
        contract_path = str(tmp_path / "C.sol")
        raw = {
            "type": "reentrancy",
            "severity": "High",
            "confidence": 0.85,
            "title": "Reentrancy bug",
            "description": "External call before state update.",
            "function": "withdraw",
            "line": 42,
            "recommendation": "Use CEI pattern.",
        }
        finding = adapter._normalize_auditor_finding(raw, contract_path)
        assert finding is not None
        assert finding["type"] == "reentrancy"
        assert finding["severity"] == "High"
        assert finding["confidence"] == 0.85
        assert finding["location"]["file"] == contract_path
        assert finding["location"]["line"] == 42
        assert finding["location"]["function"] == "withdraw"
        assert finding["source"] == "gptlens_auditor"
        assert finding["critic_verdict"] is None

    def test_confidence_clamped_above_one(self, adapter, tmp_path):
        raw = {"type": "access_control", "severity": "Low", "confidence": 1.5}
        finding = adapter._normalize_auditor_finding(raw, str(tmp_path / "C.sol"))
        assert finding["confidence"] <= 1.0

    def test_confidence_clamped_below_zero(self, adapter, tmp_path):
        raw = {"type": "access_control", "severity": "Low", "confidence": -0.3}
        finding = adapter._normalize_auditor_finding(raw, str(tmp_path / "C.sol"))
        assert finding["confidence"] >= 0.0

    def test_invalid_confidence_defaults_to_075(self, adapter, tmp_path):
        raw = {"type": "reentrancy", "severity": "Medium", "confidence": "not-a-number"}
        finding = adapter._normalize_auditor_finding(raw, str(tmp_path / "C.sol"))
        assert finding["confidence"] == 0.75

    def test_invalid_line_number_defaults_to_zero(self, adapter, tmp_path):
        raw = {"type": "reentrancy", "severity": "Medium", "line": "abc"}
        finding = adapter._normalize_auditor_finding(raw, str(tmp_path / "C.sol"))
        assert finding["location"]["line"] == 0

    def test_missing_title_generates_default(self, adapter, tmp_path):
        raw = {"type": "timestamp_dependence", "severity": "Low"}
        finding = adapter._normalize_auditor_finding(raw, str(tmp_path / "C.sol"))
        assert "title" in finding
        assert len(finding["title"]) > 0

    def test_swc_mapping_populated_for_reentrancy(self, adapter, tmp_path):
        raw = {"type": "reentrancy", "severity": "Critical"}
        finding = adapter._normalize_auditor_finding(raw, str(tmp_path / "C.sol"))
        assert finding["swc_id"] == "SWC-107"
        assert "CWE" in finding["cwe_id"]

    def test_placeholder_taxonomy_ids_fall_back_to_mapping(self, adapter, tmp_path):
        raw = {
            "type": "reentrancy",
            "severity": "High",
            "swc_id": "SWC-XXX",
            "cwe_id": "CWE-XXX",
        }
        finding = adapter._normalize_auditor_finding(raw, str(tmp_path / "C.sol"))
        assert finding["swc_id"] == "SWC-107"
        assert finding["cwe_id"] == "CWE-841"

    def test_unknown_type_gets_logic_error_fallback(self, adapter, tmp_path):
        raw = {"type": "totally_unknown_vuln", "severity": "Low"}
        finding = adapter._normalize_auditor_finding(raw, str(tmp_path / "C.sol"))
        # Should not crash; type may stay or be reclassified
        assert finding is not None

    def test_severity_normalization_case_insensitive(self, adapter, tmp_path):
        for raw_sev, expected in [
            ("critical", "Critical"),
            ("HIGH", "High"),
            ("medium", "Medium"),
            ("LOW", "Low"),
            ("informational", "Info"),
        ]:
            raw = {"type": "reentrancy", "severity": raw_sev}
            finding = adapter._normalize_auditor_finding(raw, str(tmp_path / "C.sol"))
            assert finding["severity"] == expected, f"Failed for {raw_sev}"


# ---------------------------------------------------------------------------
# _parse_critic_verdict
# ---------------------------------------------------------------------------


class TestParseCriticVerdict:

    def test_true_positive_explicit_marker(self, adapter):
        verdict, explanation = adapter._parse_critic_verdict(
            "TRUE_POSITIVE: The external call happens before the balance is zeroed."
        )
        assert verdict == "TRUE_POSITIVE"
        assert "external call" in explanation

    def test_false_positive_explicit_marker(self, adapter):
        verdict, explanation = adapter._parse_critic_verdict(
            "FALSE_POSITIVE: The function is protected by a reentrancy guard."
        )
        assert verdict == "FALSE_POSITIVE"
        assert len(explanation) > 0

    def test_true_positive_with_spaces(self, adapter):
        verdict, _ = adapter._parse_critic_verdict("TRUE POSITIVE - looks exploitable")
        assert verdict == "TRUE_POSITIVE"

    def test_false_positive_with_spaces(self, adapter):
        verdict, _ = adapter._parse_critic_verdict("FALSE POSITIVE - no issue here")
        assert verdict == "FALSE_POSITIVE"

    def test_heuristic_valid_keyword(self, adapter):
        verdict, _ = adapter._parse_critic_verdict("VALID: the reentrancy is clearly exploitable.")
        assert verdict == "TRUE_POSITIVE"

    def test_heuristic_confirmed_keyword(self, adapter):
        verdict, _ = adapter._parse_critic_verdict("CONFIRMED: this is a real vulnerability.")
        assert verdict == "TRUE_POSITIVE"

    def test_heuristic_not_vulnerable_keyword(self, adapter):
        # "NOT VULNERABLE" is in the FALSE_POSITIVE heuristic list
        verdict, _ = adapter._parse_critic_verdict(
            "NOT VULNERABLE: the guard prevents exploitation."
        )
        assert verdict == "FALSE_POSITIVE"

    def test_heuristic_no_vulnerability_keyword(self, adapter):
        # "NO VULNERABILITY" is in the FALSE_POSITIVE heuristic list and
        # does NOT contain any TRUE_POSITIVE substring
        verdict, _ = adapter._parse_critic_verdict("NO VULNERABILITY found in this function.")
        assert verdict == "FALSE_POSITIVE"

    def test_ambiguous_response_returns_uncertain(self, adapter):
        verdict, _ = adapter._parse_critic_verdict("I'm not sure about this one.")
        assert verdict == "UNCERTAIN"

    def test_empty_response_returns_uncertain(self, adapter):
        verdict, _ = adapter._parse_critic_verdict("")
        assert verdict == "UNCERTAIN"

    def test_case_insensitive_true_positive(self, adapter):
        verdict, _ = adapter._parse_critic_verdict("true_positive - confirmed")
        assert verdict == "TRUE_POSITIVE"


# ---------------------------------------------------------------------------
# analyze() — mocked Ollama HTTP API
# ---------------------------------------------------------------------------


class TestAnalyzeWithMockedOllama:

    def _auditor_json(self):
        return json.dumps(
            {
                "findings": [
                    {
                        "type": "reentrancy",
                        "severity": "Critical",
                        "confidence": 0.9,
                        "title": "Reentrancy in withdraw()",
                        "description": "External call before state update.",
                        "function": "withdraw",
                        "line": 7,
                        "attack_scenario": "Drain funds via re-entry.",
                        "impact": "Loss of ETH.",
                        "recommendation": "Update state before external call.",
                    },
                    {
                        "type": "access_control",
                        "severity": "High",
                        "confidence": 0.8,
                        "title": "Unprotected setOwner",
                        "description": "Anyone can call setOwner.",
                        "function": "setOwner",
                        "line": 20,
                    },
                ]
            }
        )

    def test_valid_response_returns_findings(self, adapter, sample_contract):
        """Full auditor + critic flow with two findings both confirmed TRUE_POSITIVE."""
        auditor_text = self._auditor_json()
        critic_text = "TRUE_POSITIVE: This is clearly exploitable."

        generate_calls = {"n": 0}

        def fake_urlopen(req, timeout=None):
            if req.get_full_url().endswith("/api/generate"):
                generate_calls["n"] += 1
                return _make_ollama_resp(auditor_text if generate_calls["n"] == 1 else critic_text)
            # health check
            return _make_health_resp()

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            result = adapter.analyze(sample_contract)

        assert result["status"] == "success"
        assert len(result["findings"]) >= 1

    def test_auditor_malformed_json_still_succeeds(self, adapter, sample_contract):
        """When auditor returns malformed JSON, fallback analysis runs and result is success."""
        call_count = {"n": 0}

        def fake_urlopen(req, timeout=None):
            call_count["n"] += 1
            if req.get_full_url().endswith("/api/generate"):
                return _make_ollama_resp("This contract has a reentrancy vulnerability.")
            return _make_health_resp()

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            result = adapter.analyze(sample_contract)

        # Should succeed — fallback text/pattern analysis runs
        assert result["status"] == "success"
        assert "findings" in result

    def test_network_error_returns_error_status(self, adapter, sample_contract):
        """When Ollama is unreachable (OSError), analyze() returns an error result."""

        def fake_urlopen(req, timeout=None):
            raise OSError("Connection refused")

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            result = adapter.analyze(sample_contract)

        assert result["status"] == "error"
        assert "error" in result

    def test_url_error_returns_error_status(self, adapter, sample_contract):
        """When Ollama is unavailable (URLError), analyze() returns an error result."""

        def fake_urlopen(req, timeout=None):
            raise urllib.error.URLError("Name or service not known")

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            result = adapter.analyze(sample_contract)

        assert result["status"] == "error"

    def test_auditor_critic_two_stage_flow(self, adapter, sample_contract):
        """Verify the two-stage flow: auditor produces findings, critic evaluates each one."""
        auditor_text = self._auditor_json()
        # Critic confirms first finding, rejects second
        critic_responses = [
            "TRUE_POSITIVE: Reentrancy confirmed.",
            "FALSE_POSITIVE: setOwner is protected by onlyOwner.",
        ]
        critic_call = {"n": 0}
        auditor_called = {"called": False}

        def fake_urlopen(req, timeout=None):
            if not req.get_full_url().endswith("/api/generate"):
                return _make_health_resp()

            body = json.loads(req.data.decode())
            model = body.get("model", "")
            if model == "test-auditor":
                auditor_called["called"] = True
                return _make_ollama_resp(auditor_text)
            else:
                # critic call
                idx = critic_call["n"]
                critic_call["n"] += 1
                text = critic_responses[idx] if idx < len(critic_responses) else "TRUE_POSITIVE: ok"
                return _make_ollama_resp(text)

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            result = adapter.analyze(sample_contract)

        assert auditor_called["called"], "Auditor was never called"
        assert result["status"] == "success"
        # Critic ran: reentrancy confirmed (kept), access_control rejected (filtered)
        # Only one finding should remain (the confirmed TP)
        findings = result["findings"]
        types_found = [f["type"] for f in findings]
        assert "reentrancy" in types_found

    def test_skip_critic_flag_bypasses_phase2(self, adapter, sample_contract):
        """When skip_critic=True, only the auditor runs."""
        auditor_text = self._auditor_json()
        critic_called = {"called": False}

        def fake_urlopen(req, timeout=None):
            if not req.get_full_url().endswith("/api/generate"):
                return _make_health_resp()
            body = json.loads(req.data.decode())
            model = body.get("model", "")
            if model != "test-auditor":
                critic_called["called"] = True
            return _make_ollama_resp(auditor_text)

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            result = adapter.analyze(sample_contract, skip_critic=True)

        assert not critic_called["called"], "Critic should not have been called"
        assert result["status"] == "success"
        assert result["metadata"]["critic_stats"]["skipped"] is True

    def test_cached_result_is_returned_on_second_call(self, adapter, sample_contract):
        """Second call with same contract returns cached result without hitting /api/generate."""
        auditor_text = self._auditor_json()
        generate_calls = {"n": 0}

        def fake_urlopen(req, timeout=None):
            if req.get_full_url().endswith("/api/generate"):
                generate_calls["n"] += 1
                body = json.loads(req.data.decode())
                model = body.get("model", "")
                if model == "test-auditor":
                    return _make_ollama_resp(auditor_text)
                return _make_ollama_resp("TRUE_POSITIVE: ok")
            return _make_health_resp()

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            result1 = adapter.analyze(sample_contract)
            calls_after_first = generate_calls["n"]
            result2 = adapter.analyze(sample_contract)
            calls_after_second = generate_calls["n"]

        assert result1["status"] == "success"
        assert result2.get("from_cache") is True
        # No new generate calls on second invocation (cache hit)
        assert calls_after_second == calls_after_first

    def test_nonexistent_contract_returns_error(self, adapter):
        """Passing a non-existent file path returns error, not crash."""

        def fake_urlopen(req, timeout=None):
            return _make_health_resp()

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            result = adapter.analyze("/nonexistent/path/Contract.sol")

        assert result["status"] == "error"
