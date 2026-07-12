"""
Tests for VulnVerifierAdapter (src/adapters/vuln_verifier_adapter.py).

z3-backed module (z3 is a Python library, present in the env -> NOT an external
CLI tool, so the old 'requires external CLI tools' omit was wrong). Verifies
reported findings with Z3 (arithmetic overflow / access control / reentrancy) and
falls back to a heuristic guard count. Tests drive the real solver deterministically;
the rare timeout/unsat branches are forced with tiny fake solvers.
"""

import sys

import z3

import miesc.adapters.vuln_verifier_adapter as mod
from miesc.adapters.vuln_verifier_adapter import VulnVerifierAdapter
from miesc.core.tool_protocol import ToolStatus


def _a():
    return VulnVerifierAdapter()


def _finding(vtype="arithmetic overflow", line=2, fn="f"):
    return {
        "type": vtype,
        "severity": "High",
        "confidence": 0.8,
        "message": "vuln",
        "location": {"function": fn, "line": line, "file": "C.sol"},
    }


# --------------------------------------------------------------------------- #
# metadata / availability
# --------------------------------------------------------------------------- #
def test_metadata_and_availability():
    a = _a()
    assert a.get_metadata().name == "vuln_verifier"
    assert a.is_available() == ToolStatus.AVAILABLE
    assert a._z3_available is True  # z3 present


def test_is_available_handles_missing_z3(monkeypatch):
    a = _a()
    a._z3_available = None
    monkeypatch.setitem(sys.modules, "z3", None)  # force `import z3` to raise ImportError
    assert a.is_available() == ToolStatus.AVAILABLE
    assert a._z3_available is False


# --------------------------------------------------------------------------- #
# _select_strategy — every branch
# --------------------------------------------------------------------------- #
def test_select_strategy():
    a = _a()
    assert a._select_strategy("integer overflow") == "arithmetic_overflow"
    assert a._select_strategy("underflow") == "arithmetic_overflow"
    assert a._select_strategy("arithmetic") == "arithmetic_overflow"
    assert a._select_strategy("access control") == "access_control"
    assert a._select_strategy("authorization") == "access_control"
    assert a._select_strategy("invariant break") == "invariant_violation"
    assert a._select_strategy("reentrancy") == "reentrancy"
    assert a._select_strategy("something") == "state_manipulation"


# --------------------------------------------------------------------------- #
# _verify_overflow_z3 — sat (verified), unsat (refuted), unknown
# --------------------------------------------------------------------------- #
def test_overflow_verified_sat():
    a = _a()
    solver = z3.Solver()
    res = a._verify_overflow_z3(_finding(), "", "C.sol", z3, solver)
    assert res["status"] == "verified"
    assert "counter_example" in res


def test_overflow_refuted_when_operands_bounded():
    a = _a()
    solver = z3.Solver()
    # bound a,b small so a+b cannot overflow -> ULT(result,a) unsatisfiable -> refuted
    av = z3.BitVec("a", 256)
    bv = z3.BitVec("b", 256)
    solver.add(z3.ULT(av, 1000), z3.ULT(bv, 1000))
    res = a._verify_overflow_z3(_finding(), "", "C.sol", z3, solver)
    assert res["status"] == "refuted"


class _Solver:
    def __init__(self, result):
        self._r = result

    def add(self, *a, **k):
        pass

    def check(self):
        return self._r


def test_overflow_unknown_on_timeout():
    a = _a()
    res = a._verify_overflow_z3(_finding(), "", "C.sol", z3, _Solver(z3.unknown))
    assert res["status"] == "unknown"


# --------------------------------------------------------------------------- #
# _verify_access_z3
# --------------------------------------------------------------------------- #
def test_access_verified_without_check():
    a = _a()
    solver = z3.Solver()
    src = "line1\nfunction setOwner(address o) external { owner = o; }\nline3"
    res = a._verify_access_z3(_finding("access control", line=2), src, "C.sol", z3, solver)
    assert res["status"] == "verified"


def test_access_refuted_with_onlyOwner():
    a = _a()
    solver = z3.Solver()
    src = "line1\nfunction setOwner(address o) external onlyOwner { owner = o; }\nline3"
    res = a._verify_access_z3(_finding("access control", line=2), src, "C.sol", z3, solver)
    assert res["status"] == "refuted"


# --------------------------------------------------------------------------- #
# _verify_reentrancy_z3
# --------------------------------------------------------------------------- #
def test_reentrancy_verified_without_guard():
    a = _a()
    solver = z3.Solver()
    src = "function withdraw() external { msg.sender.call{value: bal}(''); }"
    res = a._verify_reentrancy_z3(_finding("reentrancy", line=1), src, "C.sol", z3, solver)
    assert res["status"] == "verified"


def test_reentrancy_refuted_with_guard():
    a = _a()
    solver = z3.Solver()
    src = "function withdraw() external nonReentrant { msg.sender.call{value: bal}(''); }"
    res = a._verify_reentrancy_z3(_finding("reentrancy", line=1), src, "C.sol", z3, solver)
    assert res["status"] == "refuted"


def test_reentrancy_unknown_when_unsat():
    a = _a()
    res = a._verify_reentrancy_z3(_finding("reentrancy"), "", "C.sol", z3, _Solver(z3.unsat))
    assert res["status"] == "unknown"


# --------------------------------------------------------------------------- #
# _verify_generic_z3 + _verify_with_z3 dispatch / fallback
# --------------------------------------------------------------------------- #
def test_generic_z3_delegates_to_heuristic():
    a = _a()
    res = a._verify_generic_z3(_finding("state thing"), "x = 1;", "C.sol", z3, z3.Solver())
    assert res["strategy"] == "state_manipulation"


def test_verify_with_z3_dispatches_each_strategy():
    a = _a()
    for strategy in ("arithmetic_overflow", "access_control", "reentrancy", "state_manipulation"):
        res = a._verify_with_z3(_finding(line=1), "function f() external {}", "C.sol", strategy)
        assert res["status"] in ("verified", "refuted", "unknown")


def test_verify_with_z3_falls_back_on_exception(monkeypatch):
    a = _a()
    monkeypatch.setattr(a, "_verify_overflow_z3",
                        lambda *args, **k: (_ for _ in ()).throw(RuntimeError("z3 boom")))
    res = a._verify_with_z3(_finding(), "source", "C.sol", "arithmetic_overflow")
    # exception -> heuristic fallback still returns a dict
    assert res["status"] in ("verified", "refuted", "unknown")


# --------------------------------------------------------------------------- #
# _verify_heuristic — 0 / 1 / >=2 guards
# --------------------------------------------------------------------------- #
def test_heuristic_refuted_many_guards():
    a = _a()
    src = "l1\nfunction f() external onlyOwner { require(x); nonReentrant; }\nl3"
    res = a._verify_heuristic(_finding(line=2), src, "C.sol", "access_control")
    assert res["status"] == "refuted"


def test_heuristic_unknown_single_guard():
    a = _a()
    src = "l1\nfunction f() external { require(x > 0); }\nl3"
    res = a._verify_heuristic(_finding(line=2), src, "C.sol", "access_control")
    assert res["status"] == "unknown"


def test_heuristic_verified_no_guards():
    a = _a()
    src = "l1\nfunction f() external { x = y + z; }\nl3"
    res = a._verify_heuristic(_finding(line=2), src, "C.sol", "arithmetic_overflow")
    assert res["status"] == "verified"


# --------------------------------------------------------------------------- #
# _verify_finding heuristic path (z3 unavailable)
# --------------------------------------------------------------------------- #
def test_verify_finding_uses_heuristic_when_no_z3():
    a = _a()
    a._z3_available = False
    res = a._verify_finding(_finding("reentrancy", line=1), "function f(){}", "C.sol")
    assert res["strategy"] == "reentrancy"


# --------------------------------------------------------------------------- #
# analyze — end to end
# --------------------------------------------------------------------------- #
def test_analyze_no_findings_returns_empty():
    a = _a()
    out = a.analyze("/whatever.sol")
    assert out["status"] == "success"
    assert out["findings"] == []
    assert "no findings" in out["metadata"]["reason"]


def test_analyze_missing_file_returns_error():
    a = _a()
    out = a.analyze("/nonexistent/C.sol", findings=[_finding()])
    assert out["status"] == "error"
    assert out["error"]


def test_analyze_verifies_overflow_finding(tmp_path):
    a = _a()
    a.is_available()  # resolves z3 availability (as the orchestrator does before analyze)
    sol = tmp_path / "C.sol"
    sol.write_text("contract C { function add(uint a, uint b) public { uint c = a + b; } }")
    out = a.analyze(str(sol), findings=[_finding("integer overflow", line=1)])
    assert out["status"] == "success"
    assert out["metadata"]["findings_checked"] == 1
    assert out["metadata"]["z3_available"] is True
    assert out["findings"][0]["tool"] == "vuln_verifier"


# --------------------------------------------------------------------------- #
# normalize_findings
# --------------------------------------------------------------------------- #
def test_normalize_findings_statuses_counter_example_and_skip():
    a = _a()
    raw = [
        {"status": "verified", "strategy": "arithmetic_overflow", "file": "C.sol", "line": 3,
         "counter_example": {"a": "1", "b": "2"}, "original_finding": _finding()},
        {"status": "refuted", "strategy": "access_control", "file": "C.sol", "line": 4,
         "original_finding": _finding()},
        {"status": "unknown", "strategy": "reentrancy", "file": "C.sol", "line": 5,
         "original_finding": _finding()},
        "not-a-dict",
    ]
    out = a.normalize_findings(raw)
    assert len(out) == 3
    verified = next(f for f in out if f["type"] == "verified_arithmetic_overflow")
    assert verified["severity"] == "High"
    assert "Counter-example" in verified["message"]
    assert any(f["type"] == "refuted_access_control" and f["severity"] == "Info" for f in out)
    assert any(f["type"] == "unverified_reentrancy" for f in out)


def test_normalize_findings_empty():
    assert _a().normalize_findings([]) == []
    assert _a().normalize_findings(None) == []
