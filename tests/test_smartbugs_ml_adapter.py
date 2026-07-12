"""
Tests for SmartBugsMLAdapter (src/adapters/smartbugs_ml_adapter.py).

numpy/sklearn are only probed for availability; the actual inference is a
rule-based heuristic over extracted features, so it is fully testable: feature
extraction, the five rule-based "ML" findings, confidence thresholding, the JSON
prediction cache, availability gating and registration.
"""

import sys

from miesc.adapters.smartbugs_ml_adapter import SmartBugsMLAdapter, register_adapter
from src.core.tool_protocol import ToolStatus


def _a(config=None):
    cfg = {"cache_predictions": False}
    if config:
        cfg.update(config)
    return SmartBugsMLAdapter(cfg)


def _features(**over):
    base = {
        "external_calls": 0.0, "state_changes_after_call": 0.0, "has_delegatecall": 0.0,
        "uses_blockhash": 0.0, "uses_timestamp": 0.0, "has_unchecked_math": 0.0,
        "has_selfdestruct": 0.0, "has_access_control": 0.0,
    }
    base.update(over)
    return base


# --------------------------------------------------------------------------- #
# metadata / availability / config / registration
# --------------------------------------------------------------------------- #
def test_metadata_and_availability():
    a = _a()
    assert a.get_metadata().name == "smartbugs_ml"
    assert a.is_available() == ToolStatus.AVAILABLE
    chk = a.check_availability()
    assert chk["available"] is True
    assert "scikit-learn" in chk["ml_library"]


def test_availability_not_installed(monkeypatch):
    monkeypatch.setitem(sys.modules, "numpy", None)  # force ImportError on re-import
    a = _a()
    assert a.is_available() == ToolStatus.NOT_INSTALLED


def test_init_defaults_and_config():
    assert _a().model == "random_forest"
    assert _a().confidence_threshold == 0.7
    custom = _a({"model": "svm", "confidence_threshold": 0.9})
    assert custom.model == "svm"
    assert custom.confidence_threshold == 0.9


def test_register_adapter():
    reg = register_adapter()
    assert reg["adapter_class"] is SmartBugsMLAdapter
    assert reg["metadata"]["name"] == "smartbugs_ml"


# --------------------------------------------------------------------------- #
# _extract_features
# --------------------------------------------------------------------------- #
def test_extract_features():
    a = _a()
    code = (
        "pragma solidity ^0.4.24;\n"
        "contract C {\n"
        "  function f() public { msg.sender.call(''); selfdestruct(owner); }\n"
        "  function g() public { uint x = block.timestamp; }\n"
        "}\n"
    )
    feats = a._extract_features(code)
    assert feats["num_functions"] == 2
    assert feats["has_selfdestruct"] == 1.0
    assert feats["has_call"] == 1.0
    assert feats["uses_timestamp"] == 1.0
    assert feats["has_owner"] == 1.0  # 'owner' appears


def test_count_state_changes_after_calls():
    a = _a()
    code = "x.call('');\nbalances[a] = 0;\ntotal = total - 1;"
    assert a._count_state_changes_after_calls(code) == 2.0
    assert a._count_state_changes_after_calls("uint x = 1;") == 0.0


def test_detect_unchecked_math():
    a = _a()
    assert a._detect_unchecked_math("pragma solidity ^0.8.0; uint c = a + b;") == 0.0
    assert a._detect_unchecked_math("pragma solidity ^0.4.0; uint c = a + b;") == 1.0
    assert a._detect_unchecked_math("pragma solidity ^0.4.0; using SafeMath for uint;") == 0.0


# --------------------------------------------------------------------------- #
# _run_ml_inference — each rule + threshold filter
# --------------------------------------------------------------------------- #
def test_inference_reentrancy():
    a = _a({"confidence_threshold": 0.5})
    out = a._run_ml_inference(_features(external_calls=1.0, state_changes_after_call=1.0), "")
    assert any(f["type"] == "reentrancy" for f in out)


def test_inference_delegatecall_randomness_overflow_selfdestruct():
    a = _a()
    assert any(f["type"] == "delegatecall"
               for f in a._run_ml_inference(_features(has_delegatecall=1.0), ""))
    assert any(f["type"] == "bad_randomness"
               for f in a._run_ml_inference(_features(uses_blockhash=1.0), ""))
    assert any(f["type"] == "integer_overflow"
               for f in a._run_ml_inference(_features(has_unchecked_math=1.0), ""))
    assert any(f["type"] == "unprotected_selfdestruct"
               for f in a._run_ml_inference(
                   _features(has_selfdestruct=1.0, has_access_control=0.0), ""))


def test_inference_threshold_suppresses_low_confidence():
    a = _a({"confidence_threshold": 0.99})  # above every rule's confidence
    out = a._run_ml_inference(_features(has_delegatecall=1.0, uses_blockhash=1.0), "")
    assert out == []


def test_inference_selfdestruct_with_access_control_not_flagged():
    a = _a()
    out = a._run_ml_inference(_features(has_selfdestruct=1.0, has_access_control=1.0), "")
    assert not any(f["type"] == "unprotected_selfdestruct" for f in out)


# --------------------------------------------------------------------------- #
# analyze — end to end
# --------------------------------------------------------------------------- #
def test_analyze_file_not_found():
    out = _a().analyze("/nonexistent/C.sol")
    assert out["success"] is False
    assert "not found" in out["error"]


def test_analyze_detects_vuln(tmp_path):
    a = _a({"confidence_threshold": 0.5})
    sol = tmp_path / "Vuln.sol"
    sol.write_text(
        "pragma solidity ^0.4.24;\n"
        "contract Vuln {\n"
        "  mapping(address=>uint) balances; uint total;\n"
        "  function withdraw() public {\n"
        "    msg.sender.call('');\n"
        "    balances[msg.sender] = 0;\n"
        "    total = total - 1;\n"
        "  }\n"
        "}\n"
    )
    out = a.analyze(str(sol))
    assert out["success"] is True
    assert out["model_used"] == "random_forest"
    assert any(f["type"] == "reentrancy" for f in out["findings"])


def test_analyze_handles_exception(tmp_path, monkeypatch):
    a = _a()
    sol = tmp_path / "C.sol"
    sol.write_text("contract C {}")
    monkeypatch.setattr(a, "_extract_features",
                        lambda *args, **k: (_ for _ in ()).throw(RuntimeError("ml boom")))
    out = a.analyze(str(sol))
    assert out["success"] is False
    assert "ml boom" in out["error"]


# --------------------------------------------------------------------------- #
# cache
# --------------------------------------------------------------------------- #
def test_cache_roundtrip_and_analyze_uses_cache(tmp_path):
    a = SmartBugsMLAdapter({"cache_predictions": True, "confidence_threshold": 0.5})
    # isolate the cache to this test's tmp dir so the cold-cache assertion is
    # deterministic (the default cache_dir is a shared system tempdir).
    a.cache_dir = tmp_path / "cache"
    a.cache_dir.mkdir()
    sol = tmp_path / "C.sol"
    sol.write_text("pragma solidity ^0.4.24;\ncontract C { function f() public {} }")

    key = a._get_cache_key(str(sol))
    assert len(key) == 16
    # fallback key path (unreadable -> hash of the path string)
    assert len(a._get_cache_key("/nonexistent/x.sol")) == 16

    assert a._check_cache(str(sol)) is None  # cold cache
    first = a.analyze(str(sol))
    assert first["success"] is True
    cached = a._check_cache(str(sol))  # now warm
    assert cached is not None
    second = a.analyze(str(sol))  # served from cache
    assert second == first


def test_check_cache_tolerates_corrupt_file(tmp_path):
    a = SmartBugsMLAdapter({"cache_predictions": True})
    a.cache_dir = tmp_path / "cache"
    a.cache_dir.mkdir()
    sol = tmp_path / "C.sol"
    sol.write_text("contract C {}")
    # write a non-JSON file at the expected cache key -> json.load raises -> None
    (a.cache_dir / f"{a._get_cache_key(str(sol))}.json").write_text("{ not valid json")
    assert a._check_cache(str(sol)) is None


def test_cache_result_tolerates_write_failure(tmp_path):
    a = SmartBugsMLAdapter({"cache_predictions": True})
    a.cache_dir = tmp_path / "missing" / "deeper"  # does not exist -> open() raises
    # must not raise; the except logs a warning and returns
    a._cache_result(str(tmp_path / "C.sol"), {"x": 1})
