"""
Unit tests for Cairo scan routing, cross-tool corroboration and taxonomy.

No binary needed. Covers:
- _is_cairo_target: Cairo inputs route to the Cairo path, Solidity does not.
- _cairo_corroborate: confidence rises (and findings are flagged) when both
  Caracal and the pattern adapter agree on (file, canonical category).
- End-to-end alignment: a real captured Caracal finding and real pattern-adapter
  output for the same class corroborate (guards the category map, which the
  synthetic tests above do not — they hand-pick already-aligned categories).
- finding_taxonomy: Cairo slugs map to canonical categories, and the generic
  keys stay OUT of the shared map (additive constraint — EVM unchanged).

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL-3.0
"""

from __future__ import annotations

import json
from pathlib import Path

from miesc.adapters.cairo_adapter import CairoPatternAdapter
from miesc.adapters.caracal_adapter import CaracalAdapter
from miesc.cli.commands.scan import _cairo_corroborate, _is_cairo_target
from miesc.core.finding_taxonomy import CanonicalCategory, normalize_finding_type

_REPO = Path(__file__).resolve().parent.parent
_CARACAL_FIXTURES = _REPO / "tests" / "fixtures" / "caracal"
_CAIRO_SAMPLES = _REPO / "examples" / "contracts" / "cairo" / "caracal_poc" / "vulnerable"

# --------------------------------------------------------------------------- #
# _is_cairo_target                                                            #
# --------------------------------------------------------------------------- #


def test_cairo_file_is_cairo(tmp_path: Path) -> None:
    f = tmp_path / "c.cairo"
    f.write_text("x")
    assert _is_cairo_target(f) is True


def test_sol_file_is_not_cairo(tmp_path: Path) -> None:
    f = tmp_path / "c.sol"
    f.write_text("x")
    assert _is_cairo_target(f) is False


def test_scarb_dir_is_cairo(tmp_path: Path) -> None:
    (tmp_path / "Scarb.toml").write_text("[package]\nname='x'\n")
    assert _is_cairo_target(tmp_path) is True


def test_cairo_only_dir_is_cairo(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.cairo").write_text("x")
    assert _is_cairo_target(tmp_path) is True


def test_mixed_dir_stays_evm(tmp_path: Path) -> None:
    (tmp_path / "a.cairo").write_text("x")
    (tmp_path / "b.sol").write_text("x")
    assert _is_cairo_target(tmp_path) is False


def test_empty_dir_is_not_cairo(tmp_path: Path) -> None:
    assert _is_cairo_target(tmp_path) is False


# --------------------------------------------------------------------------- #
# _cairo_corroborate — DoD "confidence rises when they coincide"              #
# --------------------------------------------------------------------------- #


def _finding(tool: str, ftype: str, file: str, conf: float) -> dict:
    return {
        "tool": tool,
        "type": ftype,
        "confidence": conf,
        "location": {"file": file, "line": 1, "function": "f"},
    }


def test_corroboration_boosts_when_both_agree() -> None:
    # Caracal uses a relative filename, the pattern adapter a full path:
    # corroboration keys on the basename, so they must still match.
    results = [
        {
            "tool": "caracal",
            "findings": [_finding("caracal", "unprotected-replace-class", "up.cairo", 0.4)],
        },
        {
            "tool": "cairo",
            "findings": [_finding("cairo", "proxy_upgrade", "/abs/path/up.cairo", 0.4)],
        },
    ]
    boosted = _cairo_corroborate(results)
    assert boosted == 2
    for r in results:
        f = r["findings"][0]
        assert f["cross_tool_corroborated"] == ["cairo", "caracal"]  # sorted
        assert f["confidence"] == 0.55  # 0.40 + 0.15


def test_no_corroboration_for_single_tool() -> None:
    results = [
        {"tool": "caracal", "findings": [_finding("caracal", "tx-origin", "a.cairo", 0.8)]},
        {"tool": "cairo", "findings": [_finding("cairo", "proxy_upgrade", "a.cairo", 0.4)]},
    ]
    boosted = _cairo_corroborate(results)
    assert boosted == 0
    for r in results:
        assert "cross_tool_corroborated" not in r["findings"][0]


def test_corroboration_confidence_capped() -> None:
    results = [
        {"tool": "caracal", "findings": [_finding("caracal", "reentrancy", "a.cairo", 0.95)]},
        {"tool": "cairo", "findings": [_finding("cairo", "reentrancy", "a.cairo", 0.95)]},
    ]
    _cairo_corroborate(results)
    assert results[0]["findings"][0]["confidence"] <= 0.99


# --------------------------------------------------------------------------- #
# End-to-end alignment: REAL Caracal output + REAL pattern output corroborate  #
# --------------------------------------------------------------------------- #


def test_real_caracal_and_pattern_outputs_corroborate() -> None:
    """A captured Caracal finding and the pattern adapter's own output for the
    felt-arithmetic class must cross-validate.

    This guards the *category alignment* end-to-end: the two tools emit
    DIFFERENT raw type names (`felt252-unsafe-arithmetic` vs `felt_overflow`),
    and corroboration only fires if both still canonicalize to the same category.
    The synthetic tests above hand-pick already-aligned categories, so they would
    not catch a regression in the taxonomy map; this one would. No binary: Caracal
    output comes from a committed fixture, the pattern adapter runs in-process.
    """
    sample = _CAIRO_SAMPLES / "felt252_overflow.cairo"
    raw = json.loads((_CARACAL_FIXTURES / "felt252_overflow.json").read_text())

    caracal = CaracalAdapter().normalize_findings(raw)
    for f in caracal:
        f["tool"] = "caracal"  # run_tool tags the tool name; normalize_findings does not
    pattern = CairoPatternAdapter().analyze(str(sample)).get("findings", [])
    for f in pattern:
        f["tool"] = "cairo"

    # The two tools genuinely disagree on the raw slug for this class...
    assert any(f.get("type") == "felt252-unsafe-arithmetic" for f in caracal)
    assert any(f.get("type") == "felt_overflow" for f in pattern)
    # ...yet both must land on the same canonical category (the alignment guard).
    assert normalize_finding_type({"type": "felt252-unsafe-arithmetic"}) is (
        CanonicalCategory.ARITHMETIC
    )
    assert normalize_finding_type({"type": "felt_overflow"}) is CanonicalCategory.ARITHMETIC

    results = [
        {"tool": "caracal", "findings": caracal},
        {"tool": "cairo", "findings": pattern},
    ]
    boosted = _cairo_corroborate(results)
    assert boosted > 0, "real Caracal + pattern output must cross-validate on felt arithmetic"

    corroborated = [f for f in caracal + pattern if f.get("cross_tool_corroborated")]
    assert corroborated, "at least one finding must be flagged cross_tool_corroborated"
    assert all(f["cross_tool_corroborated"] == ["cairo", "caracal"] for f in corroborated)
    # both tools appear among the corroborated findings (not one tool twice)
    assert {f["tool"] for f in corroborated} == {"caracal", "cairo"}


# --------------------------------------------------------------------------- #
# finding_taxonomy — Cairo mappings + additive guard                          #
# --------------------------------------------------------------------------- #


def test_cairo_slugs_map_to_canonical() -> None:
    assert normalize_finding_type("reentrancy") is CanonicalCategory.REENTRANCY
    assert normalize_finding_type("read-only-reentrancy") is CanonicalCategory.REENTRANCY
    assert normalize_finding_type("felt252-unsafe-arithmetic") is CanonicalCategory.ARITHMETIC
    assert normalize_finding_type("controlled-library-call") is CanonicalCategory.ACCESS_CONTROL
    assert normalize_finding_type("unprotected-replace-class") is CanonicalCategory.PROXY_UPGRADE
    assert normalize_finding_type("proxy_upgrade") is CanonicalCategory.PROXY_UPGRADE
    assert normalize_finding_type("unchecked-l1-handler-from") is CanonicalCategory.INPUT_VALIDATION
    assert normalize_finding_type("tx-origin") is CanonicalCategory.ACCESS_CONTROL


def test_caracal_and_pattern_share_proxy_upgrade() -> None:
    # The real corroboration case: Caracal's slug and the pattern value collapse
    # to the same canonical category.
    assert normalize_finding_type("unprotected-replace-class") is normalize_finding_type(
        "proxy_upgrade"
    )


def test_generic_keys_not_added_to_shared_map() -> None:
    """Additive guard: these exact strings are emitted by EVM / other-chain
    adapters, so the Cairo work must NOT have mapped them globally (that would
    change EVM classification). They must resolve to no canonical category."""
    assert normalize_finding_type("storage_collision") is None
    assert normalize_finding_type("access_control") is None
    assert normalize_finding_type("arithmetic") is None
