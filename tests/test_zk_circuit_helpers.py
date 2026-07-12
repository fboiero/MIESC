"""Tests for ZKCircuitAdapter pure helpers (framework detection, severity map,
circomspect text parsing, circom pattern analysis) — no external binaries."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

from miesc.adapters.zk_circuit_adapter import ZKCircuitAdapter, ZKFramework


def _adapter():
    return ZKCircuitAdapter()


class TestRunCircomspect:
    def test_json_issues_parsed(self):
        a = _adapter()
        payload = {"issues": [
            {"message": "unconstrained signal", "severity": "warning", "code": "CW01",
             "span": {"start": {"line": 4}}},
        ]}
        proc = MagicMock(returncode=0, stdout=json.dumps(payload), stderr="")
        with patch("subprocess.run", return_value=proc):
            out = a._run_circomspect("c.circom")
        assert len(out) == 1
        assert out[0]["category"] == "CW01"

    def test_text_fallback_when_not_json(self):
        a = _adapter()
        proc = MagicMock(returncode=0, stdout="warning[CW02]: bad signal\n\n", stderr="")
        with patch("subprocess.run", return_value=proc):
            out = a._run_circomspect("c.circom")
        assert any(f["category"] == "CW02" for f in out)

    def test_timeout_returns_empty(self):
        a = _adapter()
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("circomspect", 120)):
            assert a._run_circomspect("c.circom") == []

    def test_generic_error_returns_empty(self):
        a = _adapter()
        with patch("subprocess.run", side_effect=FileNotFoundError("circomspect")):
            assert a._run_circomspect("c.circom") == []


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
