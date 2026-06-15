"""Regression tests for SmartGuard CoT JSON parsing robustness.

SmartGuard previously used a naive first-`{`..last-`}` grab + strict json.loads,
which broke on real LLM output (code fences, trailing commas, trailing prose) —
producing "JSON parse error in CoT response" and silently losing findings. The
parser now uses balanced-brace extraction + common-error repair.
"""

from __future__ import annotations

from src.adapters.smartguard_adapter import SmartGuardAdapter


def _adapter():
    return SmartGuardAdapter()


def test_parses_malformed_json_with_fence_trailing_comma_and_prose():
    """The exact shape that broke the old parser must now yield a finding."""
    response = (
        "Sure, here is my analysis:\n"
        "```json\n"
        "{\n"
        '  "analysis": {\n'
        '    "chain_of_thought": "withdraw sends ETH before updating balance.",\n'
        '    "vulnerabilities": [\n'
        '      {"type": "reentrancy", "severity": "high", "description": "state '
        'update after call", "location": "withdraw", "fix": "CEI",},\n'
        "    ]\n"
        "  }\n"
        "}\n"
        "```\n"
        "Hope this helps!"
    )
    findings = _adapter()._parse_cot_response(response, "withdraw", "C.sol")
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert "reentrancy" in findings[0]["title"].lower()


def test_parses_clean_json():
    response = (
        '{"analysis": {"chain_of_thought": "ok", "vulnerabilities": '
        '[{"type": "access_control", "severity": "medium", "description": "d", '
        '"location": "f", "fix": "x"}]}}'
    )
    findings = _adapter()._parse_cot_response(response, "f", "C.sol")
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"


def test_unparseable_returns_empty_without_crashing():
    findings = _adapter()._parse_cot_response("no json here at all", "f", "C.sol")
    assert findings == []


def test_no_vulnerabilities_returns_empty():
    response = '{"analysis": {"chain_of_thought": "looks safe", "vulnerabilities": []}}'
    findings = _adapter()._parse_cot_response(response, "f", "C.sol")
    assert findings == []


# ---------------------------------------------------------------------------
# Same robust-parsing fix applied to GPTScan and LLMSmartAudit
# ---------------------------------------------------------------------------


def test_gptscan_parses_malformed_json():
    from src.adapters.gptscan_adapter import GPTScanAdapter

    resp = (
        '```json\n{"vulnerabilities":[{"title":"Reentrancy","severity":"high",'
        '"type":"reentrancy",},]}\n```\nDone.'
    )
    findings = GPTScanAdapter()._parse_gptscan_output(resp, "C.sol")
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"


def test_llmsmartaudit_parses_malformed_json():
    from src.adapters.llmsmartaudit_adapter import LLMSmartAuditAdapter

    resp = (
        'Here:\n```json\n{"issues":[{"title":"Overflow","severity":"medium",'
        '"category":"arithmetic",},]}\n```'
    )
    findings = LLMSmartAuditAdapter()._parse_llmsmartaudit_output(resp, "C.sol")
    assert len(findings) == 1
    assert findings[0]["severity"] == "MEDIUM"


def test_parses_invalid_backslash_escape():
    """Invalid \\escape (e.g. \\( or regex \\d in a fix string) must not lose
    the finding — repair_common_json_errors now escapes stray backslashes."""
    response = (
        '{"analysis": {"chain_of_thought": "uses \\( and \\d", '
        '"vulnerabilities": [{"type": "regex_dos", "severity": "low", '
        '"description": "pattern \\d+ unbounded", "location": "f", '
        '"fix": "anchor the \\( group"}]}}'
    )
    findings = _adapter()._parse_cot_response(response, "f", "C.sol")
    assert len(findings) == 1
    assert findings[0]["severity"] == "LOW"


def test_llmbugscanner_parses_malformed_json():
    from src.adapters.llmbugscanner_adapter import LLMBugScannerAdapter

    resp = (
        '```json\n{"findings":[{"title":"Reentrancy","severity":"high",'
        '"description":"x",}]}\n```\nDone.'
    )
    findings = LLMBugScannerAdapter()._parse_llm_response(resp, "C.sol", "m")
    assert len(findings) == 1
    assert findings[0]["title"] == "Reentrancy"
