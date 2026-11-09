"""
Tests for the LLM-extraction diagnostics sink (P2-7).

An LLM adapter that returns ``0 findings, status: success`` was indistinguishable
from one whose response could not be parsed. `extract_llm_json` now records a
small diagnostic in a thread-local sink, and `run_tool` attaches it to the tool
result as ``metadata.llm_extraction`` — so the three cases (parsed-non-empty,
parsed-empty, parse-failed) are tellable apart, with a raw excerpt on the latter
two.
"""

from unittest.mock import Mock, patch

import pytest

from miesc.cli import utils
from miesc.core.tool_protocol import ToolStatus
from miesc.llm import json_extraction as jx


@pytest.fixture(autouse=True)
def _fresh_sink():
    jx.clear_extraction_records()
    utils.AdapterLoader.reset_availability()
    yield
    jx.clear_extraction_records()
    utils.AdapterLoader.reset_availability()


class TestSinkRecording:
    def test_parse_failure_records_excerpt(self):
        jx.extract_llm_json("not json at all", want="object", log_prefix="GPTScan", warn=False)
        rec = jx.take_extraction_record("gptscan")
        assert rec is not None
        assert rec["parsed"] is False
        assert rec["error"] and "not json at all" in rec["raw_excerpt"]

    def test_parsed_but_empty_records_excerpt(self):
        # THE bug: valid JSON, empty findings -> must be distinguishable from a
        # parse failure AND carry the raw so a human can see what the model said.
        jx.extract_llm_json('{"findings": []}', want="object", log_prefix="GPTScan")
        rec = jx.take_extraction_record("gptscan")
        assert rec["parsed"] is True
        assert rec["empty"] is True
        assert rec["raw_excerpt"] == '{"findings": []}'

    def test_parsed_non_empty_has_no_excerpt(self):
        jx.extract_llm_json('{"findings": [{"title": "x"}]}', want="object", log_prefix="GPTScan")
        rec = jx.take_extraction_record("gptscan")
        assert rec["parsed"] is True
        assert rec["empty"] is False
        assert rec["raw_excerpt"] == ""

    def test_vulnerabilities_key_also_counts_as_findings(self):
        jx.extract_llm_json('{"vulnerabilities": [{"x": 1}]}', want="object", log_prefix="GPTScan")
        rec = jx.take_extraction_record("gptscan")
        assert rec["empty"] is False

    def test_bracketed_prefix_matches_tool_name(self):
        # llmbugscanner logs as "LLMBugScanner[<model>]".
        jx.extract_llm_json('{"findings": []}', want="object", log_prefix="LLMBugScanner[qwen2.5]")
        assert jx.take_extraction_record("llmbugscanner") is not None

    def test_separator_prefix_matches_tool_name(self):
        # llmsmartaudit logs as "LLM-SmartAudit".
        jx.extract_llm_json('{"findings": []}', want="object", log_prefix="LLM-SmartAudit")
        assert jx.take_extraction_record("llmsmartaudit") is not None

    def test_take_clears_the_sink(self):
        jx.extract_llm_json('{"findings": []}', want="object", log_prefix="GPTScan")
        assert jx.take_extraction_record("gptscan") is not None
        assert jx.take_extraction_record("gptscan") is None  # gone after the first take


def _adapter_calling_llm(result, *, prefix="GPTScan", response='{"findings": []}', warn=True):
    """A fake adapter whose analyze() runs the real extractor (populating the
    sink) and then returns ``result``."""
    adapter = Mock()
    adapter.is_available.return_value = ToolStatus.AVAILABLE

    def analyze(contract, **kwargs):
        jx.extract_llm_json(response, want="object", log_prefix=prefix, warn=warn)
        return result

    adapter.analyze.side_effect = analyze
    return adapter


class TestRunToolAttaches:
    def test_zero_findings_carries_extraction_diagnostic(self, tmp_path):
        # The bug report, pinned: 0 findings + success, now distinguishable.
        adapter = _adapter_calling_llm({"status": "success", "findings": [], "metadata": {}})
        with (
            patch.object(utils.AdapterLoader, "get_adapter", return_value=adapter),
            patch("miesc.core.tool_protocol.applies_to", return_value=True),
        ):
            r = utils.run_tool("gptscan", str(tmp_path / "C.sol"), timeout=5)
        diag = r["metadata"]["llm_extraction"]
        assert diag["parsed"] is True and diag["empty"] is True
        assert diag["raw_excerpt"]

    def test_parse_failure_is_visible_in_metadata(self, tmp_path):
        adapter = _adapter_calling_llm(
            {"status": "success", "findings": [], "metadata": {}},
            response="total garbage",
            warn=False,
        )
        with (
            patch.object(utils.AdapterLoader, "get_adapter", return_value=adapter),
            patch("miesc.core.tool_protocol.applies_to", return_value=True),
        ):
            r = utils.run_tool("gptscan", str(tmp_path / "C.sol"), timeout=5)
        assert r["metadata"]["llm_extraction"]["parsed"] is False

    def test_tool_making_no_llm_call_has_no_diagnostic(self, tmp_path):
        # Clear-on-entry: pre-dirty the sink under the SAME key as the tool we
        # then run, so only run_tool's clear (not a key mismatch) can keep
        # llm_extraction out. The tool's analyze makes no LLM call.
        adapter = Mock()
        adapter.is_available.return_value = ToolStatus.AVAILABLE
        adapter.analyze.return_value = {"status": "success", "findings": [], "metadata": {}}
        jx.extract_llm_json('{"findings": []}', want="object", log_prefix="Slither")
        with (
            patch.object(utils.AdapterLoader, "get_adapter", return_value=adapter),
            patch("miesc.core.tool_protocol.applies_to", return_value=True),
        ):
            r = utils.run_tool("slither", str(tmp_path / "C.sol"), timeout=5)
        assert "llm_extraction" not in r.get("metadata", {})
