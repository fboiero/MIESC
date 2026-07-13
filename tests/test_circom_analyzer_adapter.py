"""
Tests for CircomAnalyzerAdapter (src/adapters/circom_analyzer_adapter.py).

Hybrid module: a single optional subprocess branch (circomspect CLI) plus pure
regex analysis. The CLI branch is exercised by monkeypatching shutil.which +
subprocess.run; everything else (circom pattern analysis, Solidity-ZK analysis,
both normalizers) is pure and needs no mocking.
"""

import json

import miesc.adapters.circom_analyzer_adapter as mod
from miesc.adapters.circom_analyzer_adapter import CircomAnalyzerAdapter
from miesc.core.tool_protocol import ToolStatus


def _a():
    return CircomAnalyzerAdapter()


# --------------------------------------------------------------------------- #
# metadata / availability / can_analyze
# --------------------------------------------------------------------------- #
def test_metadata_and_availability(monkeypatch):
    a = _a()
    assert a.get_metadata().name == "circom_analyzer"
    # available with circomspect present...
    monkeypatch.setattr(mod.shutil, "which", lambda name: "/usr/bin/circomspect")
    assert a.is_available() == ToolStatus.AVAILABLE
    # ...and via fallback when circomspect is absent
    monkeypatch.setattr(mod.shutil, "which", lambda name: None)
    assert a.is_available() == ToolStatus.AVAILABLE


def test_can_analyze():
    a = _a()
    assert a.can_analyze("x.circom") is True
    assert a.can_analyze("x.sol") is True
    assert a.can_analyze("x.txt") is False


# --------------------------------------------------------------------------- #
# _analyze_circom — CLI branch (circomspect present, subprocess mocked)
# --------------------------------------------------------------------------- #
class _FakeProc:
    def __init__(self, stdout):
        self.stdout = stdout


def test_analyze_circom_cli_branch(monkeypatch, tmp_path):
    a = _a()
    circ = tmp_path / "c.circom"
    circ.write_text("template T() { signal input a; }")

    monkeypatch.setattr(mod.shutil, "which", lambda name: "/usr/bin/circomspect")
    fake_json = json.dumps(
        [
            {
                "type": "under constrained signal",
                "level": "error",
                "line": 1,
                "message": "signal a under-constrained",
                "template": "T",
            }
        ]
    )
    monkeypatch.setattr(mod.subprocess, "run", lambda *a, **k: _FakeProc(fake_json))

    out = a.analyze(str(circ))
    assert out["status"] == "success"
    assert out["metadata"]["mode"] == "circomspect_cli"
    assert out["findings"]
    assert out["findings"][0]["tool"] == "circom_analyzer"


def test_analyze_circom_cli_failure_falls_back_to_patterns(monkeypatch, tmp_path):
    a = _a()
    circ = tmp_path / "c.circom"
    circ.write_text("signal input a;\nsignal input ghost;\nsignal output b;\nb <== a;")

    monkeypatch.setattr(mod.shutil, "which", lambda name: "/usr/bin/circomspect")

    def _boom(*a, **k):
        raise RuntimeError("circomspect crashed")

    monkeypatch.setattr(mod.subprocess, "run", _boom)
    out = a.analyze(str(circ))
    assert out["status"] == "success"
    assert out["metadata"]["mode"] == "pattern_analysis"  # fell back


# --------------------------------------------------------------------------- #
# _analyze_circom_patterns — pure (no circomspect)
# --------------------------------------------------------------------------- #
def test_circom_patterns_detects_unused_signal(monkeypatch, tmp_path):
    a = _a()
    monkeypatch.setattr(mod.shutil, "which", lambda name: None)  # force pattern mode
    circ = tmp_path / "c.circom"
    circ.write_text("signal input a;\nsignal input ghost;\nsignal output b;\nb <== a;")
    out = a.analyze(str(circ))
    types = {f["type"] for f in out["findings"]}
    assert "unused_signal" in types
    assert out["metadata"]["signals_found"] >= 3


def test_circom_patterns_detects_unconstrained_output(monkeypatch, tmp_path):
    a = _a()
    monkeypatch.setattr(mod.shutil, "which", lambda name: None)
    circ = tmp_path / "c.circom"
    circ.write_text("signal output result;\nsignal input a;\na === a;")
    out = a.analyze(str(circ))
    types = {f["type"] for f in out["findings"]}
    assert "unconstrained_output" in types


def test_circom_patterns_file_error(monkeypatch):
    a = _a()
    monkeypatch.setattr(mod.shutil, "which", lambda name: None)
    out = a.analyze("/nonexistent/c.circom")
    assert out["status"] == "error"
    assert out["error"]


# --------------------------------------------------------------------------- #
# _analyze_solidity_zk — pure
# --------------------------------------------------------------------------- #
def test_solidity_zk_non_zk_returns_empty(tmp_path):
    a = _a()
    sol = tmp_path / "plain.sol"
    sol.write_text("contract Token { function transfer() public {} }")
    out = a.analyze(str(sol))
    assert out["status"] == "success"
    assert out["metadata"]["is_zk_contract"] is False


def test_solidity_zk_flags_unverified_proof(tmp_path):
    a = _a()
    sol = tmp_path / "zk.sol"
    sol.write_text(
        "contract Mixer {\n"
        "  function submitProof(bytes calldata proof) external {\n"
        "    process(proof);\n"
        "  }\n"
        "}\n"
    )
    out = a.analyze(str(sol))
    assert out["status"] == "success"
    assert out["metadata"]["is_zk_contract"] is True
    types = {f["type"] for f in out["findings"]}
    assert "unverified_proof" in types


def test_solidity_zk_clean_when_proof_verified(tmp_path):
    a = _a()
    sol = tmp_path / "zk.sol"
    sol.write_text(
        "contract Mixer {\n"
        "  function submitProof(bytes calldata proof) external {\n"
        "    require(verifyProof(proof), 'bad proof');\n"
        "  }\n"
        "}\n"
    )
    out = a.analyze(str(sol))
    types = {f["type"] for f in out["findings"]}
    assert "unverified_proof" not in types  # guarded -> not flagged


def test_solidity_zk_file_error():
    a = _a()
    out = a.analyze("/nonexistent/zk.sol")
    assert out["status"] == "error"
    assert out["error"]


# --------------------------------------------------------------------------- #
# _normalize_circomspect
# --------------------------------------------------------------------------- #
def test_normalize_circomspect_list_and_dict_forms():
    a = _a()
    # list form, known type
    out1 = a._normalize_circomspect(
        [{"type": "unused signal", "level": "warning", "line": 3, "message": "m"}], "c.circom"
    )
    assert out1[0]["type"] == "unused_signal"
    assert out1[0]["severity"] == "High"  # 'warning' -> High
    # dict-with-issues form, unknown type -> Medium fallback
    out2 = a._normalize_circomspect(
        {"issues": [{"type": "exotic thing", "level": "info", "line": 1, "message": "m"}]},
        "c.circom",
    )
    assert out2[0]["severity"] == "Medium"  # 'info' -> Medium


# --------------------------------------------------------------------------- #
# normalize_findings
# --------------------------------------------------------------------------- #
def test_normalize_findings_config_passthrough_and_fallback_and_skip():
    a = _a()
    raw = [
        {"type": "unused_signal", "line": 2, "file": "c.circom", "code": "x"},  # known key
        {"type": "weird", "line": 4, "file": "c.circom", "code": "y"},  # fallback
        7,  # non-dict skipped
    ]
    out = a.normalize_findings(raw)
    assert len(out) == 2
    assert all(f["tool"] == "circom_analyzer" for f in out)
    assert all(f["id"].startswith("CRC-") for f in out)


def test_normalize_findings_empty():
    assert _a().normalize_findings([]) == []
    assert _a().normalize_findings(None) == []
