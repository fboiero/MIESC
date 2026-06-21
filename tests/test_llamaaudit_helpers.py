"""Tests for LlamaAuditAdapter pure helpers (parsing, normalization, dedup).

These need no Ollama/network — they exercise the JSON-extraction, regex fallback,
severity normalization, truncation, dedup, and caching logic.
"""

from __future__ import annotations

from src.adapters.llamaaudit_adapter import LlamaAuditAdapter


def _adapter():
    return LlamaAuditAdapter()


class TestJsonExtraction:
    def test_json_block_valid(self):
        a = _adapter()
        text = 'prefix ```json\n{"findings": [1]}\n``` suffix'
        assert a._extract_json_block(text) == {"findings": [1]}

    def test_json_block_invalid_returns_none(self):
        a = _adapter()
        assert a._extract_json_block("```json\n{bad}\n```") is None

    def test_json_block_absent_returns_none(self):
        a = _adapter()
        assert a._extract_json_block("no block here") is None

    def test_json_object_findings_first(self):
        a = _adapter()
        text = 'noise {"findings": [{"type": "x"}]} trailing'
        assert a._extract_json_object(text) == {"findings": [{"type": "x"}]}

    def test_json_object_trailing_comma_recovered(self):
        a = _adapter()
        text = '{"a": 1, "b": [2,],}'
        assert a._extract_json_object(text) == {"a": 1, "b": [2]}

    def test_json_object_none(self):
        a = _adapter()
        assert a._extract_json_object("no json at all") is None


class TestRegexFallback:
    def test_extracts_keyword_finding(self):
        a = _adapter()
        out = a._extract_findings_regex("The contract has a reentrancy bug", "C.sol")
        assert len(out) == 1
        assert out[0]["type"] == "reentrancy"

    def test_dedupes_same_type(self):
        a = _adapter()
        # "reentrancy" and "re-entrancy" both map to reentrancy -> one finding
        out = a._extract_findings_regex("reentrancy and re-entrancy", "C.sol")
        assert sum(1 for f in out if f["type"] == "reentrancy") == 1


class TestNormalizationAndUtils:
    def test_normalize_severity_known(self):
        a = _adapter()
        assert a._normalize_severity("CRITICAL") == "Critical"
        assert a._normalize_severity("warning") == "Medium"
        assert a._normalize_severity("error") == "High"

    def test_normalize_severity_unknown_defaults_medium(self):
        a = _adapter()
        assert a._normalize_severity("bogus") == "Medium"

    def test_truncate_short_unchanged(self):
        a = _adapter()
        code = "contract C {}"
        assert a._truncate_code(code) == code

    def test_truncate_long_marks(self):
        a = _adapter()
        code = "x" * (a._max_contract_chars + 100)
        out = a._truncate_code(code)
        assert len(out) < len(code)
        assert "truncated" in out

    def test_find_enclosing_function(self):
        a = _adapter()
        lines = ["contract C {", "function withdraw() public {", "  bad();", "}"]
        assert a._find_enclosing_function(lines, 2) == "withdraw"

    def test_find_enclosing_function_none(self):
        a = _adapter()
        assert a._find_enclosing_function(["uint x;"], 0) == ""

    def test_deduplicate_keeps_higher_confidence(self):
        a = _adapter()
        findings = [
            {"type": "reentrancy", "location": {"function": "f"}, "confidence": 0.5},
            {"type": "reentrancy", "location": {"function": "f"}, "confidence": 0.9},
        ]
        out = a._deduplicate_findings(findings)
        assert len(out) == 1
        assert out[0]["confidence"] == 0.9

    def test_error_result_shape(self):
        a = _adapter()
        res = a._error_result(0.0, "boom")
        assert res["status"] == "error"
        assert res["error"] == "boom"
        assert res["findings"] == []

    def test_cache_key_deterministic(self):
        a = _adapter()
        assert a._get_cache_key("code") == a._get_cache_key("code")
        assert a._get_cache_key("code") != a._get_cache_key("other")

    def test_read_contract_missing_returns_none(self):
        a = _adapter()
        assert a._read_contract("/no/such/file_xyz.sol") is None

    def test_read_contract_reads(self, tmp_path):
        a = _adapter()
        f = tmp_path / "C.sol"
        f.write_text("contract C {}", encoding="utf-8")
        assert a._read_contract(str(f)) == "contract C {}"
