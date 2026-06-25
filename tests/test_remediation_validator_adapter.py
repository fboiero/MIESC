"""
Tests for RemediationValidatorAdapter (src/adapters/remediation_validator_adapter.py).

Pure-logic module (no subprocess, no network): re-checks whether a patch actually
fixes a reported vulnerability and whether it introduced a regression. Every helper
takes strings/dicts and returns dicts/bools, so these tests need no mocking.
"""

from src.adapters.remediation_validator_adapter import (
    RemediationValidatorAdapter,
)
from src.core.tool_protocol import ToolStatus


def _adapter():
    return RemediationValidatorAdapter()


# --------------------------------------------------------------------------- #
# metadata / availability
# --------------------------------------------------------------------------- #
def test_metadata_and_availability():
    a = _adapter()
    md = a.get_metadata()
    assert md.name == "remediation_validator"
    assert "solidity" in md.capabilities[0].supported_languages
    assert a.is_available() == ToolStatus.AVAILABLE


# --------------------------------------------------------------------------- #
# _classify_vuln — every branch
# --------------------------------------------------------------------------- #
def test_classify_vuln_all_branches():
    a = _adapter()
    assert a._classify_vuln("Reentrancy-eth") == "reentrancy"
    assert a._classify_vuln("missing access control") == "access_control"
    assert a._classify_vuln("owner-control") == "access_control"
    assert a._classify_vuln("integer_overflow") == "integer_overflow"
    assert a._classify_vuln("arithmetic underflow") == "integer_overflow"
    assert a._classify_vuln("unsafe transfer") == "unsafe_transfer"
    assert a._classify_vuln("ERC20 issue") == "unsafe_transfer"
    assert a._classify_vuln("block timestamp dependence") == "timestamp"
    assert a._classify_vuln("delegatecall to untrusted") == "delegatecall"
    assert a._classify_vuln("something exotic") == "unknown"


# --------------------------------------------------------------------------- #
# _check_cei_pattern
# --------------------------------------------------------------------------- #
def test_cei_pattern_effects_before_interaction_is_true():
    a = _adapter()
    # state update BEFORE the external call -> CEI respected
    ctx = "balances[msg.sender] -= amount;\n(bool ok,) = msg.sender.call{value: amount}('');"
    assert a._check_cei_pattern(ctx) is True


def test_cei_pattern_interaction_before_effects_is_false():
    a = _adapter()
    # external call BEFORE the state update -> CEI violated
    ctx = "(bool ok,) = msg.sender.call{value: amount}('');\nbalances[msg.sender] -= amount;"
    assert a._check_cei_pattern(ctx) is False


def test_cei_pattern_no_call_is_false():
    a = _adapter()
    assert a._check_cei_pattern("uint x = 1; balances[a] -= 1;") is False


# --------------------------------------------------------------------------- #
# _get_vuln_patterns
# --------------------------------------------------------------------------- #
def test_get_vuln_patterns_known_and_fallback():
    a = _adapter()
    assert a._get_vuln_patterns({"type": "reentrancy"})  # non-empty list
    assert a._get_vuln_patterns({"type": "timestamp"}) == [r"block\.timestamp"]
    assert a._get_vuln_patterns({"type": "delegatecall"}) == [r"\.delegatecall\s*\("]
    # unknown type -> fallback is the raw (lowercased) type string
    assert a._get_vuln_patterns({"type": "WeirdThing"}) == ["weirdthing"]


# --------------------------------------------------------------------------- #
# _validate_remediation — status decision
# --------------------------------------------------------------------------- #
def _finding(vtype, line=2):
    return {"type": vtype, "location": {"line": line, "function": "w"}}


def test_validate_fix_confirmed_when_guard_present_and_vuln_gone():
    a = _adapter()
    patched = (
        "function withdraw() external nonReentrant {\n"
        "  balances[msg.sender] = 0;\n"
        "  payable(msg.sender).transfer(1);\n"
        "}"
    )
    r = a._validate_remediation(_finding("reentrancy"), patched, "", "C.sol")
    assert r["status"] == "fix_confirmed"
    assert r["vuln_type"] == "reentrancy"
    assert any("nonReentrant" in p for p in r["remediation_patterns_found"])


def test_validate_fix_partial_when_guard_present_but_vuln_pattern_remains():
    a = _adapter()
    # has nonReentrant (remediation) AND a raw low-level call{value:} (vuln still present)
    patched = (
        "function withdraw() external nonReentrant {\n"
        "  (bool ok,) = msg.sender.call{value: amount}('');\n"
        "}"
    )
    r = a._validate_remediation(_finding("reentrancy"), patched, "", "C.sol")
    assert r["status"] == "fix_partial"
    assert r["vuln_still_present"] is True


def test_validate_fix_failed_when_no_remediation_and_vuln_remains():
    a = _adapter()
    patched = (
        "function withdraw() external {\n"
        "  (bool ok,) = msg.sender.call{value: amount}('');\n"
        "}"
    )
    r = a._validate_remediation(_finding("reentrancy"), patched, "", "C.sol")
    assert r["status"] == "fix_failed"


def test_validate_integer_overflow_confirmed_by_pragma_version():
    a = _adapter()
    patched = "pragma solidity ^0.8.19;\ncontract C { uint x; }"
    r = a._validate_remediation(_finding("integer_overflow"), patched, "", "C.sol")
    assert r["status"] == "fix_confirmed"


def test_validate_confirmed_via_cei_without_explicit_guard():
    a = _adapter()
    # No nonReentrant/ReentrancyGuard token (no remediation pattern), but effects come
    # before the interaction (CEI respected) and the raw reentrancy patterns don't match
    # a .send() -> hits the cei_expected & has_cei & not vuln_still_present branch.
    patched = (
        "function withdraw() external {\n"
        "  balances[msg.sender] -= amount;\n"
        "  msg.sender.send(amount);\n"
        "}"
    )
    r = a._validate_remediation(_finding("reentrancy"), patched, "", "C.sol")
    assert r["status"] == "fix_confirmed"
    assert r["remediation_patterns_found"] == []  # confirmed purely via CEI ordering


# --------------------------------------------------------------------------- #
# _check_regressions
# --------------------------------------------------------------------------- #
def test_check_regressions_detects_removed_guard():
    a = _adapter()
    original = (
        "function withdraw() external nonReentrant {\n"
        "  payable(msg.sender).transfer(1);\n"
        "}"
    )
    patched = (
        "function withdraw() external {\n"  # nonReentrant removed
        "  payable(msg.sender).transfer(1);\n"
        "}"
    )
    regs = a._check_regressions(patched, original, "C.sol")
    assert any(r["status"] == "regression_detected" for r in regs)
    assert any("reentrancy guard" in r["reason"] for r in regs)


def test_check_regressions_empty_without_original():
    a = _adapter()
    assert a._check_regressions("anything", "", "C.sol") == []


def test_check_regressions_none_when_guards_intact():
    a = _adapter()
    code = "function f() external onlyOwner { require(x); }"
    assert a._check_regressions(code, code, "C.sol") == []


# --------------------------------------------------------------------------- #
# analyze — end to end (uses real temp files, no mocks)
# --------------------------------------------------------------------------- #
def test_analyze_no_findings_returns_empty_success():
    a = _adapter()
    out = a.analyze("/nonexistent/whatever.sol")
    assert out["status"] == "success"
    assert out["findings"] == []
    assert "no original findings" in out["metadata"]["reason"]


def test_analyze_missing_file_returns_error():
    a = _adapter()
    out = a.analyze("/nonexistent/whatever.sol", findings=[_finding("reentrancy")])
    assert out["status"] == "error"
    assert out["error"]


def test_analyze_full_flow_confirms_fix(tmp_path):
    a = _adapter()
    patched = tmp_path / "patched.sol"
    patched.write_text(
        "pragma solidity ^0.8.0;\n"
        "contract C {\n"
        "  mapping(address=>uint) balances;\n"
        "  function withdraw() external nonReentrant {\n"
        "    balances[msg.sender] = 0;\n"
        "    payable(msg.sender).transfer(1);\n"
        "  }\n"
        "}"
    )
    out = a.analyze(str(patched), findings=[_finding("reentrancy", line=4)])
    assert out["status"] == "success"
    assert out["metadata"]["original_findings"] == 1
    assert out["metadata"]["confirmed_fixes"] >= 1
    assert out["findings"]  # normalized findings produced
    f = out["findings"][0]
    assert f["tool"] == "remediation_validator"
    assert f["id"].startswith("REM-")


def test_analyze_tolerates_unreadable_original_path(tmp_path):
    a = _adapter()
    patched = tmp_path / "patched.sol"
    patched.write_text("function w() external nonReentrant { transfer(1); }")
    # original_path points at a directory -> open() raises, the except/pass swallows it
    # and validation still proceeds against the patched code only.
    out = a.analyze(
        str(patched),
        findings=[_finding("reentrancy", line=1)],
        original_path=str(tmp_path),  # a directory, not a file
    )
    assert out["status"] == "success"
    assert out["metadata"]["original_findings"] == 1


def test_analyze_detects_regression_with_original(tmp_path):
    a = _adapter()
    orig = tmp_path / "orig.sol"
    orig.write_text("function w() external nonReentrant { transfer(1); }")
    patched = tmp_path / "patched.sol"
    patched.write_text("function w() external { transfer(1); }")  # guard removed
    out = a.analyze(
        str(patched), findings=[_finding("reentrancy", line=1)], original_path=str(orig)
    )
    assert out["status"] == "success"
    assert out["metadata"]["regressions"] >= 1


# --------------------------------------------------------------------------- #
# normalize_findings
# --------------------------------------------------------------------------- #
def test_normalize_findings_maps_status_and_skips_non_dict():
    a = _adapter()
    raw = [
        {"status": "fix_confirmed", "file": "C.sol", "line": 3, "original_finding": {}},
        "garbage-not-a-dict",
        {"status": "fix_failed", "file": "C.sol", "line": 9,
         "original_finding": {"type": "reentrancy"}, "reason": "still vulnerable"},
    ]
    out = a.normalize_findings(raw)
    assert len(out) == 2  # the string is skipped
    confirmed = next(f for f in out if f["type"] == "fix_confirmed")
    assert confirmed["severity"] == "Info"
    assert confirmed["recommendation"] == "No action needed"
    failed = next(f for f in out if f["type"] == "fix_failed")
    assert failed["severity"] == "High"
    assert "still vulnerable" in failed["message"]


def test_normalize_findings_empty():
    assert _adapter().normalize_findings([]) == []
    assert _adapter().normalize_findings(None) == []
