from unittest.mock import patch

from miesc.adapters.deep_reasoning_adapter import (
    _extract_json_array,
    _format_existing_findings,
    run_deep_reasoning,
)


def test_extract_json_array_handles_fenced_and_noisy_text():
    assert _extract_json_array('```json\n[{"a": 1}]\n```') == [{"a": 1}]
    assert _extract_json_array("here you go: [1, 2] thanks") == [1, 2]
    assert _extract_json_array("no array here") == []
    assert _extract_json_array("") == []


def test_format_existing_findings_empty():
    assert _format_existing_findings([]) == "(none reported)"


def test_format_existing_findings_renders_location():
    findings = [
        {
            "severity": "High",
            "type": "access_control",
            "location": {"function": "withdraw"},
            "title": "missing check",
        }
    ]
    rendered = _format_existing_findings(findings)
    assert "High" in rendered and "withdraw" in rendered and "missing check" in rendered


def test_run_deep_reasoning_skips_when_cli_unavailable():
    with patch("miesc.adapters.deep_reasoning_adapter.check_claude_cli", return_value=False):
        result = run_deep_reasoning("/some/dir", [])
    assert result["enabled"] is True
    assert result["findings"] == []
    assert "not found" in result["error"]


def test_run_deep_reasoning_normalizes_findings():
    raw_json = (
        '[{"title": "Share inflation", "severity": "high", "type": "Business Logic", '
        '"contract": "Vault.sol", "function": "deposit", "description": "first depositor"}]'
    )
    with (
        patch("miesc.adapters.deep_reasoning_adapter.check_claude_cli", return_value=True),
        patch(
            "miesc.adapters.deep_reasoning_adapter.call_claude_cli_agentic",
            return_value=raw_json,
        ),
    ):
        result = run_deep_reasoning("/some/dir", [])

    assert result["count"] == 1
    finding = result["findings"][0]
    assert finding["tool"] == "deep-reasoning-claude-code"
    assert finding["severity"] == "High"
    assert finding["type"] == "business_logic"
    assert finding["location"]["file"] == "Vault.sol"
    assert finding["location"]["function"] == "deposit"


def test_run_deep_reasoning_never_raises_on_cli_failure():
    with (
        patch("miesc.adapters.deep_reasoning_adapter.check_claude_cli", return_value=True),
        patch(
            "miesc.adapters.deep_reasoning_adapter.call_claude_cli_agentic",
            side_effect=RuntimeError("Claude Code subscription usage limit reached."),
        ),
    ):
        result = run_deep_reasoning("/some/dir", [])
    assert result["findings"] == []
    assert "usage limit" in result["error"]
