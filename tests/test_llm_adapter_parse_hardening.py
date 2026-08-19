"""Regression tests: LLM adapters must not crash (or silently fail clean) on
hostile/malformed model output.

LLM responses are untrusted — a malicious contract can influence them via prompt
injection, and local/quantized models emit off-spec shapes. Normalization must
tolerate non-string field values and non-dict/list containers rather than raising
(which aborts the scan) or crashing into a broad ``except`` that masks the parse
failure as a clean, zero-finding result.
"""

from unittest.mock import patch

from miesc.adapters.frontier_llm_adapter import FrontierLLMAdapter
from miesc.adapters.gptscan_adapter import GPTScanAdapter
from miesc.core.tool_protocol import ToolStatus

# --------------------------------------------------------------------------- #
# FrontierLLM: normalization loop in analyze()
# --------------------------------------------------------------------------- #


def test_frontier_analyze_survives_hostile_finding_shapes(tmp_path):
    """A non-string ``type`` or a non-dict finding must not crash analyze()."""
    contract = tmp_path / "c.sol"
    contract.write_text("contract C {}")

    hostile = [
        {"type": 123, "title": "numeric type"},  # int type -> old .lower() crash
        "i am not a dict object",  # non-dict finding -> old .get() crash
        {"type": ["reentrancy"], "severity": 5},  # list type + non-string severity
    ]

    with (
        patch.object(FrontierLLMAdapter, "is_available", return_value=ToolStatus.AVAILABLE),
        patch.object(FrontierLLMAdapter, "_get_provider", return_value="openai"),
        patch.object(FrontierLLMAdapter, "_analyze_openai", return_value=hostile),
    ):
        result = FrontierLLMAdapter().analyze(str(contract))

    # Contract: returns a dict, does not raise, and did not error out.
    assert isinstance(result, dict)
    assert result.get("status") != "error"
    # The two dict findings normalize; the non-dict entry is skipped.
    assert isinstance(result.get("findings"), list)


# --------------------------------------------------------------------------- #
# GPTScan: _parse_gptscan_output
# --------------------------------------------------------------------------- #


def test_gptscan_parse_string_vulnerabilities_is_not_a_crash():
    """``vulnerabilities`` as a string must yield [] (not iterate chars & crash)."""
    adapter = GPTScanAdapter()
    out = adapter._parse_gptscan_output('{"vulnerabilities": "none found"}', "c.sol")
    assert out == []


def test_gptscan_parse_non_dict_json_is_not_a_crash():
    """Top-level JSON that is not an object must yield [] (no .get on a list)."""
    adapter = GPTScanAdapter()
    out = adapter._parse_gptscan_output("[1, 2, 3]", "c.sol")
    assert out == []


def test_gptscan_parse_skips_non_dict_entries_keeps_real():
    """A non-dict entry in the list is skipped; a valid dict is still parsed."""
    adapter = GPTScanAdapter()
    payload = '{"vulnerabilities": ["not a dict", {"title": "Real", "severity": "high"}]}'
    out = adapter._parse_gptscan_output(payload, "c.sol")
    assert len(out) == 1
    assert out[0]["title"] == "Real"
    assert out[0]["severity"] == "HIGH"


def test_gptscan_parse_non_string_severity_does_not_crash():
    """A non-string severity must be coerced, not crash .upper()."""
    adapter = GPTScanAdapter()
    payload = '{"vulnerabilities": [{"title": "X", "severity": 5}]}'
    out = adapter._parse_gptscan_output(payload, "c.sol")
    assert len(out) == 1
    assert out[0]["severity"] == "5"
