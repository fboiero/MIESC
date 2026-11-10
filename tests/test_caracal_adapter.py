"""
Unit tests for the Caracal (Cairo/Starknet) adapter.

These run WITHOUT the caracal binary: normalization is tested against the raw
JSON captured in tests/fixtures/caracal/, and the honest-error contract is
tested by stubbing the subprocess. Integration tests that need the real binary
live in test_cairo_integration.py and skip when it is absent.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL-3.0
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from miesc.adapters.caracal_adapter import CaracalAdapter
from miesc.core.tool_protocol import ToolStatus

FIXTURES = Path(__file__).parent / "fixtures" / "caracal"
POC = Path(__file__).parent.parent / "examples" / "contracts" / "cairo" / "caracal_poc"


def _load(name: str) -> list:
    return json.loads((FIXTURES / name).read_text())


# --------------------------------------------------------------------------- #
# normalize_findings — parsing + per-detector mapping                         #
# --------------------------------------------------------------------------- #


def test_normalize_reentrancy_fixture() -> None:
    adapter = CaracalAdapter()
    findings = adapter.normalize_findings(_load("reentrancy.json"))
    assert findings, "reentrancy fixture should produce findings"
    re_findings = [f for f in findings if f["type"] == "reentrancy"]
    assert re_findings
    f = re_findings[0]
    assert f["severity"] in {"Critical", "High", "Medium", "Low", "Info"}
    assert f["cwe_id"] == "CWE-841"
    assert f["owasp_category"] == "SC01: Reentrancy"
    assert f["chain"] == "starknet"
    assert f["swc_id"] is None  # SWC is EVM-specific
    assert f["_caracal_detector"] == "reentrancy"


def test_function_parsed_from_message() -> None:
    """Caracal emits no function field; the adapter parses it from the message
    so distinct findings keep distinct functions (dedup granularity)."""
    adapter = CaracalAdapter()
    findings = adapter.normalize_findings(_load("reentrancy.json"))
    funcs = {f["location"]["function"] for f in findings}
    assert funcs - {""}, f"expected at least one parsed function, got {funcs}"
    # Wrapper prefix stripped
    assert not any(fn.startswith("__wrapper__") for fn in funcs)


@pytest.mark.parametrize(
    "fixture,detector,cwe,owasp",
    [
        ("felt252_overflow.json", "felt252-unsafe-arithmetic", "CWE-190", "SC03: Arithmetic"),
        ("tx_origin.json", "tx-origin", "CWE-477", "SC02: Access Control"),
        ("controlled_library_call.json", "controlled-library-call", "CWE-829", "SC02: Access Control"),
        ("unchecked_transfer.json", "unchecked-transfer", "CWE-252", "SC04: Unchecked Return Values"),
    ],
)
def test_detector_mapping(fixture: str, detector: str, cwe: str, owasp: str) -> None:
    adapter = CaracalAdapter()
    findings = adapter.normalize_findings(_load(fixture))
    matches = [f for f in findings if f["type"] == detector]
    assert matches, f"{detector} not found in {fixture}"
    assert matches[0]["cwe_id"] == cwe
    assert matches[0]["owasp_category"] == owasp


def test_normalize_empty_list() -> None:
    assert CaracalAdapter().normalize_findings([]) == []


def test_normalize_non_list_is_safe() -> None:
    assert CaracalAdapter().normalize_findings({"not": "a list"}) == []


def test_confidence_mapping() -> None:
    adapter = CaracalAdapter()
    raw = [{"detector": "reentrancy", "impact": "Medium", "confidence": "High",
            "message": "Reentrancy in a::b::C::foo", "locations": [{"file": "a.cairo", "line": 1, "col": 1}]}]
    assert adapter.normalize_findings(raw)[0]["confidence"] == 0.9


# --------------------------------------------------------------------------- #
# analyze() — honest-error contract (subprocess stubbed, no binary)           #
# --------------------------------------------------------------------------- #

_EXISTING = str(POC / "vulnerable" / "reentrancy.cairo")


def _available(adapter: CaracalAdapter, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(adapter, "is_available", lambda: ToolStatus.AVAILABLE)


def test_analyze_exit2_is_error(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = CaracalAdapter()
    _available(adapter, monkeypatch)
    monkeypatch.setattr(adapter, "run_subprocess", lambda *a, **k: (2, "", "Error: Contract not found."))
    r = adapter.analyze(_EXISTING)
    assert r["status"] == "error"
    assert r["findings"] == []
    assert "exit code 2" in (r["error"] or "")


def test_analyze_panic_exit101_is_error(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = CaracalAdapter()
    _available(adapter, monkeypatch)
    monkeypatch.setattr(adapter, "run_subprocess", lambda *a, **k: (101, "", "thread 'main' panicked"))
    r = adapter.analyze(_EXISTING)
    assert r["status"] == "error"
    assert r["findings"] == []


def test_analyze_exit0_invalid_json_is_error(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = CaracalAdapter()
    _available(adapter, monkeypatch)
    monkeypatch.setattr(adapter, "run_subprocess", lambda *a, **k: (0, "not json at all", ""))
    r = adapter.analyze(_EXISTING)
    assert r["status"] == "error"


def test_analyze_exit0_empty_is_success_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    """exit 0 with an empty JSON array is a legitimate clean result, NOT an error."""
    adapter = CaracalAdapter()
    _available(adapter, monkeypatch)
    monkeypatch.setattr(adapter, "run_subprocess", lambda *a, **k: (0, "[]", ""))
    r = adapter.analyze(_EXISTING)
    assert r["status"] == "success"
    assert r["findings"] == []


def test_analyze_exit0_with_findings(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = CaracalAdapter()
    _available(adapter, monkeypatch)
    payload = json.dumps(_load("reentrancy.json"))
    monkeypatch.setattr(adapter, "run_subprocess", lambda *a, **k: (0, payload, ""))
    r = adapter.analyze(_EXISTING)
    assert r["status"] == "success"
    assert len(r["findings"]) == 11


def test_analyze_missing_path_is_error() -> None:
    r = CaracalAdapter().analyze("/does/not/exist.cairo")
    assert r["status"] == "error"
    assert r["findings"] == []


def test_analyze_unavailable_is_error(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = CaracalAdapter()
    monkeypatch.setattr(adapter, "is_available", lambda: ToolStatus.NOT_INSTALLED)
    r = adapter.analyze(_EXISTING)
    assert r["status"] == "error"
    assert "not available" in (r["error"] or "")


# --------------------------------------------------------------------------- #
# can_analyze — Cairo only, never steals the EVM routing                      #
# --------------------------------------------------------------------------- #


def test_can_analyze_cairo_file() -> None:
    assert CaracalAdapter().can_analyze(_EXISTING) is True


def test_can_analyze_rejects_sol() -> None:
    assert CaracalAdapter().can_analyze("Contract.sol") is False


def test_can_analyze_scarb_dir(tmp_path: Path) -> None:
    (tmp_path / "Scarb.toml").write_text("[package]\nname='x'\n")
    assert CaracalAdapter().can_analyze(str(tmp_path)) is True


def test_is_available_missing_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CARACAL_BIN", "/nonexistent/caracal-binary")
    assert CaracalAdapter().is_available() == ToolStatus.NOT_INSTALLED


def test_metadata() -> None:
    md = CaracalAdapter().get_metadata()
    assert md.name == "caracal"
    assert md.license == "AGPL-3.0"
    assert md.is_optional is True
    assert md.requires_llm is False
