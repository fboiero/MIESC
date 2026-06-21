"""Tests for ZKCircuitAdapter pure helpers (framework detection, severity map,
circomspect text parsing, circom pattern analysis) — no external binaries."""

from __future__ import annotations

from pathlib import Path

from src.adapters.zk_circuit_adapter import ZKCircuitAdapter, ZKFramework


def _adapter():
    return ZKCircuitAdapter()


class TestFrameworkDetection:
    def test_circom(self):
        assert _adapter()._detect_framework(Path("a.circom")) == ZKFramework.CIRCOM

    def test_noir(self):
        assert _adapter()._detect_framework(Path("a.nr")) == ZKFramework.NOIR

    def test_gnark(self):
        assert _adapter()._detect_framework(Path("my_gnark.go")) == ZKFramework.GNARK

    def test_halo2(self):
        assert _adapter()._detect_framework(Path("my_halo2.rs")) == ZKFramework.HALO2

    def test_unknown(self):
        assert _adapter()._detect_framework(Path("a.txt")) is None


class TestSeverityMap:
    def test_known(self):
        a = _adapter()
        assert a._map_circomspect_severity("error") == "CRITICAL"
        assert a._map_circomspect_severity("warning") == "MEDIUM"
        assert a._map_circomspect_severity("info") == "LOW"
        assert a._map_circomspect_severity("help") == "INFO"

    def test_unknown_defaults_medium(self):
        assert _adapter()._map_circomspect_severity("bogus") == "MEDIUM"


class TestCircomspectTextParse:
    def test_parses_severity_and_code(self):
        a = _adapter()
        txt = "warning[CW001]: signal not constrained\n\nerror[CE002]: missing constraint\n\n"
        out = a._parse_circomspect_text(txt, "c.circom")
        sev_cat = {(f["severity"], f["category"]) for f in out}
        assert ("MEDIUM", "CW001") in sev_cat
        assert ("CRITICAL", "CE002") in sev_cat

    def test_empty_output(self):
        assert _adapter()._parse_circomspect_text("", "c.circom") == []


class TestCircomPatternAnalysis:
    def test_unconstrained_output_detected(self):
        a = _adapter()
        circom = "template T() { signal input a; signal output b; b <-- a * a; }"
        out = a._run_pattern_analysis(circom, "c.circom", ZKFramework.CIRCOM)
        cats = {f.get("category") for f in out}
        assert "unconstrained_output" in cats

    def test_clean_circuit_no_unconstrained(self):
        a = _adapter()
        circom = "template T() { signal input a; signal output b; b <== a; }"
        out = a._run_pattern_analysis(circom, "c.circom", ZKFramework.CIRCOM)
        assert "unconstrained_output" not in {f.get("category") for f in out}
