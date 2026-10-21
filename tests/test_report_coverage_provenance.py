"""The professional report shows coverage gaps, provenance and per-finding corroboration."""

from __future__ import annotations

import json

from click.testing import CliRunner

from miesc.cli.commands.report import _coverage_and_provenance_variables, report


def _audit_json():
    return {
        "contract_path": "Vault.sol",
        "timestamp": "2026-10-21T10:00:00",
        "tools_run": ["slither", "aderyn", "wake", "dagnn", "mythril"],
        "tools_success": ["slither", "aderyn", "dagnn"],
        "tools_skipped": ["wake"],
        "tools_fallback": ["dagnn"],
        "tools_failed": ["mythril"],
        "tool_status": {
            "slither": "success",
            "aderyn": "success",
            "wake": "skipped",
            "dagnn": "success (fallback)",
            "mythril": "timeout",
        },
        "raw_findings": [
            {
                "title": "Reentrancy in withdraw",
                "severity": "high",
                "description": "External call before state update.",
                "tool": "slither",
                "confidence": 0.82,
                "confirming_tools": ["slither", "aderyn"],
                "tool_count": 2,
                "location": {"file": "Vault.sol", "line": 42},
            }
        ],
        "findings": [
            {
                "title": "Reentrancy in withdraw",
                "severity": "high",
                "description": "External call before state update.",
                "tool": "slither",
                "confidence": 0.82,
                "confirming_tools": ["slither", "aderyn"],
                "tool_count": 2,
                "location": {"file": "Vault.sol", "line": 42},
            }
        ],
        "provenance": {
            "timestamp": "2026-10-21T10:00:00",
            "miesc": {"version": "6.3.0", "git_sha": "abcdef1234567890", "git_dirty": False},
            "python": {"version": "3.12.6", "implementation": "CPython"},
            "platform": {"system": "Darwin", "release": "25.4.0", "machine": "arm64"},
            "solc": {"per_contract": {"Vault.sol": "0.8.28"}},
            "config": {"path": "/x/miesc.yaml", "sha256": "deadbeefcafebabe0123"},
            "llm_free": True,
            "command_line": "miesc audit full Vault.sol --no-llm",
            "tools": {"slither": "0.11.6", "aderyn": "aderyn 0.1.9", "fouranalyzer": "unknown"},
        },
    }


def test_variables_from_audit_json():
    v = _coverage_and_provenance_variables(_audit_json())
    assert v["coverage_tools_skipped"] == ["wake"]
    assert v["coverage_tools_fallback"] == ["dagnn"]
    assert v["coverage_tools_failed"] == ["mythril"]
    assert v["coverage_tools_clean"] == ["slither", "aderyn"]
    assert v["coverage_llm_free"] is True
    labels = dict(v["provenance_rows"])
    assert labels["MIESC"].startswith("6.3.0 (abcdef123456")
    assert "Vault.sol → 0.8.28" in labels["solc per contract"]
    assert ("slither", "0.11.6") in v["provenance_tool_versions"]
    assert ("fouranalyzer", "unknown") not in v["provenance_tool_versions"]


def test_variables_degrade_without_provenance():
    v = _coverage_and_provenance_variables({"tools": ["slither"], "tools_failed": []})
    assert v["has_provenance"] is False
    assert v["coverage_tools_run"] == ["slither"]
    assert v["provenance_rows"] == []
    assert v["coverage_llm_free"] is None


def test_professional_report_renders_sections(tmp_path):
    src = tmp_path / "audit.json"
    src.write_text(json.dumps(_audit_json()))
    out = tmp_path / "report.md"
    result = CliRunner().invoke(
        report, [str(src), "-t", "professional", "-f", "markdown", "-o", str(out)]
    )
    assert result.exit_code == 0, result.output
    text = out.read_text()
    assert "## Coverage and Limitations" in text
    assert "wake" in text and "dagnn" in text and "mythril" in text
    assert "## Appendix B: Provenance" in text
    assert "6.3.0 (abcdef123456" in text
    assert "Vault.sol → 0.8.28" in text
    assert "Detected by | slither, aderyn (2 tools agree)" in text
    assert "Confidence | 82%" in text
