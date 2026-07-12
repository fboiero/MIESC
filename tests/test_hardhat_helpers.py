"""Tests for HardhatAdapter pure helpers (compilation parsing, config) — no npx."""

from __future__ import annotations

from miesc.adapters.hardhat_adapter import HardhatAdapter


def _adapter():
    return HardhatAdapter()


class TestParseCompilationOutput:
    def test_parses_warning_and_error(self):
        out = (
            "Token.sol:10:5: Warning: Unused local variable.\n"
            "Token.sol:20:1: Error: Expected ';' but got '}'.\n"
        )
        findings = _adapter()._parse_compilation_output(out)
        assert len(findings) >= 2
        sevs = {f["severity"] for f in findings}
        assert "medium" in sevs  # warning
        assert "high" in sevs    # error
        assert all(f["file"] == "Token.sol" for f in findings)

    def test_no_diagnostics(self):
        assert _adapter()._parse_compilation_output("Compiled 3 files successfully") == []


class TestUtilities:
    def test_get_recommendation_returns_text(self):
        rec = _adapter()._get_recommendation("compilation_error")
        assert isinstance(rec, str) and len(rec) > 0

    def test_default_config_shape(self):
        cfg = _adapter().get_default_config()
        assert "timeout" in cfg
        assert "network" in cfg

    def test_normalize_findings_empty(self):
        assert _adapter().normalize_findings(None) == []

    def test_normalize_findings_passthrough_list(self):
        raw = [{"type": "x", "severity": "high"}]
        out = _adapter().normalize_findings(raw)
        assert isinstance(out, list)
