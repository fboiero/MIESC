"""
Tests for DeFiAdapter (src/adapters/defi_adapter.py).

Pure wrapper around the in-tree DeFiDetectorEngine (regex detection of flash-loan /
oracle-manipulation / MEV patterns). No external deps; driven with a triggering
contract plus the file/source/exception paths.
"""

import sys

from src.adapters.defi_adapter import DeFiAdapter
from src.core.tool_protocol import ToolStatus

# Triggers flash-loan (executeOperation/flashLoan) + oracle (getReserves) detectors.
DEFI = (
    "pragma solidity ^0.8.0;\n"
    "interface IUniswapV2Pair { function getReserves() external view returns (uint112,uint112,uint32); }\n"
    "contract Pool {\n"
    "  address pair;\n"
    "  function executeOperation(address asset, uint256 amount) external returns (bool) {\n"
    "    (uint112 r0, uint112 r1,) = IUniswapV2Pair(pair).getReserves();\n"
    "    return true;\n"
    "  }\n"
    "  function flashLoan(uint256 amt) external {}\n"
    "}\n"
)


def _a():
    return DeFiAdapter()


# --------------------------------------------------------------------------- #
# availability / metadata / layer info
# --------------------------------------------------------------------------- #
def test_is_available():
    assert _a().is_available() == ToolStatus.AVAILABLE


def test_is_available_not_installed(monkeypatch):
    monkeypatch.setitem(sys.modules, "detectors.defi_detectors", None)
    assert _a().is_available() == ToolStatus.NOT_INSTALLED


def test_metadata_and_layer_info():
    a = _a()
    assert a.get_metadata().name == a.name
    info = a.get_layer_info()
    assert isinstance(info, dict)


# --------------------------------------------------------------------------- #
# analyze (file)
# --------------------------------------------------------------------------- #
def test_analyze_file_not_found():
    out = _a().analyze("/nonexistent/C.sol")
    assert out["success"] is False
    assert "not found" in out["error"]


def test_analyze_triggers_findings(tmp_path):
    a = _a()
    sol = tmp_path / "Pool.sol"
    sol.write_text(DEFI)
    out = a.analyze(str(sol))
    assert out["success"] is True
    assert out["tool"] == a.name
    assert out["findings"]
    f = out["findings"][0]
    assert f["id"].startswith("DEFI-")
    assert f["swc_id"]
    assert f["location"]["file"] == str(sol)


def test_analyze_handles_engine_exception(tmp_path, monkeypatch):
    a = _a()
    sol = tmp_path / "C.sol"
    sol.write_text("contract C {}")
    monkeypatch.setattr(a.engine, "analyze_file",
                        lambda *args, **k: (_ for _ in ()).throw(RuntimeError("defi boom")))
    out = a.analyze(str(sol))
    assert out["success"] is False
    assert "defi boom" in out["error"]


# --------------------------------------------------------------------------- #
# analyze_source
# --------------------------------------------------------------------------- #
def test_analyze_source_triggers_findings():
    out = _a().analyze_source(DEFI)
    assert out["success"] is True
    assert out["findings"]


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
