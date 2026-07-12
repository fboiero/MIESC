"""
Tests for SmartBugsDetectorAdapter (src/adapters/smartbugs_detector_adapter.py).

Pure wrapper around the in-tree SmartBugsDetectorEngine (regex detection of the
SmartBugs categories: arithmetic / bad_randomness / DoS / front-running). No
external deps; driven with a triggering contract plus file/source/exception paths.
"""

import sys

from miesc.adapters.smartbugs_detector_adapter import SmartBugsDetectorAdapter
from miesc.core.tool_protocol import ToolStatus

# Triggers bad_randomness: blockhash-based pseudo-randomness.
BAD_RANDOM = (
    "pragma solidity ^0.8.0;\n"
    "contract Lottery {\n"
    "    address[] players;\n"
    "    address winner;\n"
    "    function pickWinner() public {\n"
    "        uint r = uint(blockhash(block.number - 1)) % players.length;\n"
    "        winner = players[r];\n"
    "    }\n"
    "}\n"
)

TRANSIENT_LOW_GAS = """
pragma solidity ^0.8.28;
contract Vault {
    function withdraw(address payable to) external {
        assembly { tstore(0x00, 1) }
        to.transfer(1 ether);
        assembly { tstore(0x00, 0) }
    }
}
"""


def _a():
    return SmartBugsDetectorAdapter()


# --------------------------------------------------------------------------- #
# availability / metadata / static info
# --------------------------------------------------------------------------- #
def test_is_available():
    assert _a().is_available() == ToolStatus.AVAILABLE


def test_is_available_not_installed(monkeypatch):
    monkeypatch.setitem(sys.modules, "detectors.smartbugs_detectors", None)
    assert _a().is_available() == ToolStatus.NOT_INSTALLED


def test_metadata_and_detector_info():
    a = _a()
    assert a.get_metadata().name == a.name
    detection_types = a.get_metadata().capabilities[0].detection_types
    assert "transient_storage_reentrancy" in detection_types
    info = a.get_detector_info()
    assert info["layer"] == 6
    assert "reentrancy" in info["categories"]


# --------------------------------------------------------------------------- #
# analyze (file)
# --------------------------------------------------------------------------- #
def test_analyze_file_not_found():
    out = _a().analyze("/nonexistent/C.sol")
    assert out["success"] is False
    assert "not found" in out["error"]


def test_analyze_triggers_findings(tmp_path):
    a = _a()
    sol = tmp_path / "Lottery.sol"
    sol.write_text(BAD_RANDOM)
    out = a.analyze(str(sol))
    assert out["success"] is True
    assert out["findings"]
    f = out["findings"][0]
    assert f["id"].startswith("SB-")
    assert f["category"] == "bad_randomness"
    assert f["location"]["file"] == str(sol)


def test_analyze_converts_transient_storage_file_finding(tmp_path):
    a = _a()
    sol = tmp_path / "Vault.sol"
    sol.write_text(TRANSIENT_LOW_GAS)

    out = a.analyze(str(sol))

    assert out["success"] is True
    finding = next(f for f in out["findings"] if f["category"] == "reentrancy")
    assert finding["id"].startswith("SB-REENTRANCY-")
    assert finding["severity"] == "High"
    assert finding["location"]["file"] == str(sol)
    assert finding["location"]["line"] == 4
    assert "transfer" in finding["location"]["snippet"]
    assert finding["metadata"]["pattern"] == "transient-low-gas-reentrancy"
    assert finding["references"]
    assert out["summary"]["by_category"]["reentrancy"] == 1
    assert out["summary"]["by_detector"]["transient-storage-detector"] == 1


def test_analyze_handles_engine_exception(tmp_path, monkeypatch):
    a = _a()
    sol = tmp_path / "C.sol"
    sol.write_text("contract C {}")
    monkeypatch.setattr(a.engine, "analyze_file",
                        lambda *args, **k: (_ for _ in ()).throw(RuntimeError("sb boom")))
    out = a.analyze(str(sol))
    assert out["success"] is False
    assert "sb boom" in out["error"]


# --------------------------------------------------------------------------- #
# analyze_source
# --------------------------------------------------------------------------- #
def test_analyze_source_triggers_findings():
    out = _a().analyze_source(BAD_RANDOM)
    assert out["success"] is True
    assert out["findings"]
    assert out["findings"][0]["category"] == "bad_randomness"


def test_analyze_source_converts_transient_storage_finding():
    out = _a().analyze_source(TRANSIENT_LOW_GAS)

    assert out["success"] is True
    finding = next(f for f in out["findings"] if f["category"] == "reentrancy")
    assert finding["severity"] == "High"
    assert finding["location"]["file"] is None
    assert finding["location"]["line"] == 4
    assert finding["metadata"]["function"] == "withdraw"
    assert out["summary"]["by_category"]["reentrancy"] == 1


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
