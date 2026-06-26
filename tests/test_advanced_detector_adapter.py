"""
Tests for AdvancedDetectorAdapter (src/adapters/advanced_detector_adapter.py).

Pure wrapper around the in-tree AdvancedDetectorEngine (regex detection of rug-pull
/ governance / honeypot / centralization patterns). No external deps; we drive it
with a triggering contract and exercise the file/source/exception paths.
"""

import sys

import src.adapters.advanced_detector_adapter as mod
from src.adapters.advanced_detector_adapter import AdvancedDetectorAdapter
from src.core.tool_protocol import ToolStatus

# Triggers the rug-pull detector: withdraw-style function gated by onlyOwner.
RUG = (
    "pragma solidity ^0.8.0;\n"
    "contract Rug {\n"
    "  address owner;\n"
    "  modifier onlyOwner() { require(msg.sender == owner); _; }\n"
    "  function emergencyWithdraw() external onlyOwner {\n"
    "    payable(owner).transfer(address(this).balance);\n"
    "  }\n"
    "}\n"
)


def _a():
    return AdvancedDetectorAdapter()


# --------------------------------------------------------------------------- #
# availability / metadata / static info
# --------------------------------------------------------------------------- #
def test_is_available():
    assert _a().is_available() == ToolStatus.AVAILABLE


def test_is_available_not_installed(monkeypatch):
    monkeypatch.setitem(sys.modules, "detectors.advanced_detectors", None)
    assert _a().is_available() == ToolStatus.NOT_INSTALLED


def test_metadata_and_detector_info():
    a = _a()
    assert a.get_metadata().name == a.name
    info = a.get_detector_info()
    assert info["layer"] == 2
    assert info["detectors"]


# --------------------------------------------------------------------------- #
# analyze (file)
# --------------------------------------------------------------------------- #
def test_analyze_file_not_found():
    out = _a().analyze("/nonexistent/C.sol")
    assert out["success"] is False
    assert "not found" in out["error"]


def test_analyze_triggers_findings(tmp_path):
    a = _a()
    sol = tmp_path / "Rug.sol"
    sol.write_text(RUG)
    out = a.analyze(str(sol))
    assert out["success"] is True
    assert out["tool"] == a.name
    assert out["findings"]  # rug-pull pattern detected
    f = out["findings"][0]
    assert f["id"].startswith("ADV-")
    assert f["swc_id"]
    assert f["location"]["file"] == str(sol)


def test_analyze_handles_engine_exception(tmp_path, monkeypatch):
    a = _a()
    sol = tmp_path / "C.sol"
    sol.write_text("contract C {}")
    monkeypatch.setattr(a.engine, "analyze_file",
                        lambda *args, **k: (_ for _ in ()).throw(RuntimeError("engine boom")))
    out = a.analyze(str(sol))
    assert out["success"] is False
    assert "engine boom" in out["error"]


# --------------------------------------------------------------------------- #
# analyze_source
# --------------------------------------------------------------------------- #
def test_analyze_source_triggers_findings():
    out = _a().analyze_source(RUG)
    assert out["success"] is True
    assert out["findings"]
    assert out["findings"][0]["location"].get("line") is not None


def test_analyze_source_handles_exception(monkeypatch):
    a = _a()
    monkeypatch.setattr(a.engine, "analyze",
                        lambda *args, **k: (_ for _ in ()).throw(ValueError("src boom")))
    out = a.analyze_source("contract C {}")
    assert out["success"] is False
    assert "src boom" in out["error"]


def test_analyze_source_clean_contract():
    out = _a().analyze_source("contract Empty { uint x; }")
    assert out["success"] is True
    assert isinstance(out["findings"], list)
