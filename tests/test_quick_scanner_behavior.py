"""Behavioral tests for ``miesc.core.quick_scanner.QuickScanner``.

The QuickScanner shells out to Slither/Aderyn/Solhint. These tests mock
``subprocess.run`` so no real tool is invoked, and assert the parsing,
severity-normalisation and summary logic on real, representative tool JSON.

Author: Fernando Boiero
License: AGPL-3.0
"""

from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from miesc.core.quick_scanner import QuickScanner


def _proc(stdout: str = "", returncode: int = 0):
    return SimpleNamespace(stdout=stdout, stderr="", returncode=returncode)


@pytest.fixture
def scanner_all_available():
    """A QuickScanner whose tools all report available (probe mocked)."""
    with patch("subprocess.run", return_value=_proc(returncode=0)):
        return QuickScanner()


class TestToolProbe:
    def test_available_tools_when_probe_succeeds(self):
        with patch("subprocess.run", return_value=_proc(returncode=0)):
            scanner = QuickScanner()
        assert scanner.available_tools == {"slither": True, "aderyn": True, "solhint": True}

    def test_unavailable_when_probe_raises(self):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            scanner = QuickScanner()
        assert scanner.available_tools == {"slither": False, "aderyn": False, "solhint": False}


class TestSeverityNormalization:
    def test_known_mappings(self, scanner_all_available):
        s = scanner_all_available
        assert s._normalize_severity("High") == "high"
        assert s._normalize_severity("informational") == "info"
        assert s._normalize_severity("warning") == "medium"
        assert s._normalize_severity("error") == "high"
        assert s._normalize_severity("optimization") == "info"

    def test_empty_and_unknown_default_to_info(self, scanner_all_available):
        assert scanner_all_available._normalize_severity("") == "info"
        assert scanner_all_available._normalize_severity("wat") == "info"


class TestSummary:
    def test_summary_counts_by_severity_and_types(self, scanner_all_available):
        findings = [
            {"tool": "slither", "type": "reentrancy-eth", "severity": "high"},
            {"tool": "slither", "type": "reentrancy-eth", "severity": "high"},
            {"tool": "aderyn", "type": "unused-var", "severity": "low"},
            {"tool": "solhint", "type": None, "severity": "info"},
        ]
        summary = scanner_all_available._calculate_summary(findings)
        assert summary["total_findings"] == 4
        assert summary["by_severity"]["high"] == 2
        assert summary["by_severity"]["low"] == 1
        assert set(summary["tools_used"]) == {"slither", "aderyn", "solhint"}
        # Distinct non-empty types: reentrancy-eth, unused-var
        assert summary["issue_types"] == 2


class TestRunSlither:
    def test_parses_detectors(self, scanner_all_available):
        payload = {
            "results": {
                "detectors": [
                    {
                        "check": "reentrancy-eth",
                        "impact": "High",
                        "confidence": "Medium",
                        "description": "Reentrancy in withdraw()",
                        "first_markdown_element": "A.sol#L10",
                    }
                ]
            }
        }
        with patch("subprocess.run", return_value=_proc(json.dumps(payload))):
            findings = scanner_all_available._run_slither("A.sol")
        assert len(findings) == 1
        f = findings[0]
        assert f["tool"] == "slither"
        assert f["type"] == "reentrancy-eth"
        assert f["severity"] == "high"
        assert f["confidence"] == "medium"

    def test_invalid_json_yields_no_findings(self, scanner_all_available):
        with patch("subprocess.run", return_value=_proc("not-json")):
            assert scanner_all_available._run_slither("A.sol") == []

    def test_timeout_is_handled(self, scanner_all_available):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("slither", 60)):
            assert scanner_all_available._run_slither("A.sol") == []


class TestRunAderyn:
    def test_parses_issues(self, scanner_all_available):
        payload = {"issues": [{"title": "Centralization", "severity": "medium", "description": "x"}]}
        with patch("subprocess.run", return_value=_proc(json.dumps(payload))):
            findings = scanner_all_available._run_aderyn("A.sol")
        assert findings[0]["tool"] == "aderyn"
        assert findings[0]["type"] == "Centralization"
        assert findings[0]["severity"] == "medium"

    def test_not_installed_handled(self, scanner_all_available):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            assert scanner_all_available._run_aderyn("A.sol") == []


class TestRunSolhint:
    def test_parses_messages_with_severity_mapping(self, scanner_all_available):
        payload = [
            {
                "messages": [
                    {"ruleId": "no-unused-vars", "severity": 2, "message": "unused", "line": 3,
                     "column": 5},
                    {"ruleId": "quotes", "severity": 1, "message": "use double", "line": 4,
                     "column": 1},
                ]
            }
        ]
        with patch("subprocess.run", return_value=_proc(json.dumps(payload))):
            findings = scanner_all_available._run_solhint("A.sol")
        assert len(findings) == 2
        # severity 2 -> "error" -> normalized "high"; severity 1 -> "warning" -> "medium"
        assert findings[0]["severity"] == "high"
        assert findings[1]["severity"] == "medium"
        assert findings[0]["line"] == 3


class TestScan:
    def test_missing_contract_raises(self, scanner_all_available, tmp_path):
        with pytest.raises(FileNotFoundError):
            scanner_all_available.scan(str(tmp_path / "does_not_exist.sol"))

    def test_scan_aggregates_available_tool_findings(self, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text("pragma solidity ^0.8.0;\ncontract C {}\n", encoding="utf-8")

        # Build a scanner with only slither available.
        with patch("subprocess.run", return_value=_proc(returncode=0)):
            scanner = QuickScanner()
        scanner.available_tools = {"slither": True, "aderyn": False, "solhint": False}

        slither_payload = {
            "results": {"detectors": [{"check": "reentrancy-eth", "impact": "High"}]}
        }
        with patch("subprocess.run", return_value=_proc(json.dumps(slither_payload))):
            result = scanner.scan(str(contract), verbose=True)

        assert result["scan_type"] == "quick"
        assert result["tools_run"] == ["slither"]
        assert result["summary"]["total_findings"] == 1
        assert result["summary"]["by_severity"]["high"] == 1
        assert "execution_time" in result

    def test_scan_skips_unavailable_tools(self, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text("contract C {}", encoding="utf-8")
        with patch("subprocess.run", return_value=_proc(returncode=0)):
            scanner = QuickScanner()
        scanner.available_tools = {"slither": False, "aderyn": False, "solhint": False}
        # No subprocess.run should matter — nothing runs; still a well-formed result.
        result = scanner.scan(str(contract))
        assert result["tools_run"] == []
        assert result["summary"]["total_findings"] == 0

    def test_scan_survives_tool_exception(self, tmp_path):
        contract = tmp_path / "C.sol"
        contract.write_text("contract C {}", encoding="utf-8")
        with patch("subprocess.run", return_value=_proc(returncode=0)):
            scanner = QuickScanner()
        scanner.available_tools = {"slither": True, "aderyn": False, "solhint": False}
        with patch.object(scanner, "_run_slither", side_effect=RuntimeError("boom")):
            result = scanner.scan(str(contract))
        # Tool crashed -> no findings recorded, but scan still completes.
        assert result["summary"]["total_findings"] == 0
        assert "slither" not in result["tools_run"]
