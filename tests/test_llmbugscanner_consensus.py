"""Tests for LLMBugScannerAdapter consensus/aggregation helpers (no network)."""

from __future__ import annotations

from src.adapters.llmbugscanner_adapter import LLMBugScannerAdapter, ModelConfig


def _adapter():
    return LLMBugScannerAdapter()


def _model(name, weight=0.5):
    return ModelConfig(name=name, weight=weight, timeout=10, specialization="general")


class TestCategorization:
    def test_known_category(self):
        a = _adapter()
        assert a._categorize_finding({"type": "reentrancy"}) != "other"

    def test_unknown_is_other(self):
        a = _adapter()
        assert a._categorize_finding({"type": "zzz", "title": "", "description": ""}) == "other"

    def test_finding_key_is_category(self):
        a = _adapter()
        f = {"type": "reentrancy"}
        assert a._get_finding_key(f) == a._categorize_finding(f)


class TestMergeAndConsensus:
    def test_merge_findings(self):
        a = _adapter()
        group = [
            ("m1", {"description": "short", "severity": "HIGH"}),
            ("m2", {"description": "a much longer detailed description", "severity": "HIGH"}),
        ]
        merged = a._merge_findings(group, consensus_score=1.0)
        assert merged["agreement_count"] == 2
        assert set(merged["models_agreeing"]) == {"m1", "m2"}
        assert 0.5 < merged["confidence"] <= 0.95

    def test_aggregate_reaches_consensus(self):
        a = _adapter()
        ensemble = [_model("m1"), _model("m2")]
        all_findings = {
            "m1": [{"type": "reentrancy", "severity": "HIGH", "description": "x"}],
            "m2": [{"type": "reentrancy", "severity": "HIGH", "description": "y"}],
        }
        out = a._aggregate_with_consensus(all_findings, ensemble, threshold=0.5)
        assert len(out) == 1
        assert out[0]["agreement_count"] == 2

    def test_aggregate_single_model_high_severity_fallback(self):
        a = _adapter()
        ensemble = [_model("m1"), _model("m2")]
        # Only one model reports -> below threshold, but HIGH severity fallback kicks in
        all_findings = {
            "m1": [{"type": "reentrancy", "severity": "HIGH", "description": "x"}],
            "m2": [],
        }
        out = a._aggregate_with_consensus(all_findings, ensemble, threshold=0.9)
        assert len(out) == 1
        assert out[0].get("single_model") is True


class TestUtilities:
    def test_truncate_short_unchanged(self):
        a = _adapter()
        assert a._truncate_code("contract C {}", max_chars=100) == "contract C {}"

    def test_truncate_long(self):
        a = _adapter()
        out = a._truncate_code("x" * 200, max_chars=50)
        assert len(out) < 200

    def test_error_result(self):
        a = _adapter()
        res = a._error_result(0.0, "boom")
        assert res["status"] == "error"
        assert res["error"] == "boom"

    def test_cache_key_deterministic(self):
        a = _adapter()
        assert a._get_cache_key("c") == a._get_cache_key("c")
        assert a._get_cache_key("c") != a._get_cache_key("d")

    def test_generate_prompt_includes_code(self):
        a = _adapter()
        prompt = a._generate_analysis_prompt("contract C {}", "reentrancy")
        assert "contract C {}" in prompt

    def test_read_contract_missing(self):
        a = _adapter()
        assert a._read_contract("/no/such/file_abc.sol") is None

    def test_read_contract_ok(self, tmp_path):
        a = _adapter()
        f = tmp_path / "C.sol"
        f.write_text("contract C {}", encoding="utf-8")
        assert a._read_contract(str(f)) == "contract C {}"
