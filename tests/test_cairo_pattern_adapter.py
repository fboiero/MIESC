"""
Unit tests for CairoPatternAdapter (the pattern-based Cairo correlation pair).

Pure Python, no binary. Covers normalization, the STORAGE_COLLISION upgrade gate
(it must not fire on every contract) and the Cairo-only can_analyze routing.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL-3.0
"""

from __future__ import annotations

from pathlib import Path

from miesc.adapters.cairo_adapter import CairoAnalyzer, CairoPatternAdapter
from miesc.core.tool_protocol import ToolStatus

POC = Path(__file__).parent.parent / "examples" / "contracts" / "cairo" / "caracal_poc"


def test_metadata_and_availability() -> None:
    adapter = CairoPatternAdapter()
    md = adapter.get_metadata()
    assert md.name == "cairo"
    assert md.license == "AGPL-3.0"
    assert adapter.is_available() == ToolStatus.AVAILABLE  # pure Python


def test_normalize_sets_cairo_fields() -> None:
    adapter = CairoPatternAdapter()
    result = adapter.analyze(str(POC / "vulnerable" / "unprotected_replace_class.cairo"))
    assert result["status"] == "success"
    assert result["findings"], "pattern adapter should flag the upgradeable contract"
    for f in result["findings"]:
        assert f["chain"] == "starknet"
        assert f["_cairo_pattern"] is True
        assert 0.0 <= f["confidence"] <= 1.0
        # Heuristic source: confidence stays modest so Caracal dominates.
        assert f["confidence"] <= 0.6


def test_storage_collision_gated_off_for_non_upgradeable(tmp_path: Path) -> None:
    """STORAGE_COLLISION must NOT fire on a contract with no upgrade path
    (otherwise it flags every Starknet contract, which all have a Storage struct)."""
    contract = tmp_path / "plain.cairo"
    contract.write_text(
        "#[starknet::contract]\nmod Plain {\n    #[storage]\n    struct Storage { v: u128 }\n}\n"
    )
    analyzer = CairoAnalyzer()
    types = {f["type"] for f in analyzer.analyze(str(contract))["findings"]}
    assert "storage_collision" not in types


def test_storage_collision_fires_for_upgradeable(tmp_path: Path) -> None:
    contract = tmp_path / "up.cairo"
    contract.write_text(
        "#[starknet::contract]\nmod Up {\n    #[storage]\n    struct Storage { v: u128 }\n"
        "    fn upgrade(c: felt252) { replace_class_syscall(c); }\n}\n"
    )
    analyzer = CairoAnalyzer()
    types = {f["type"] for f in analyzer.analyze(str(contract))["findings"]}
    assert "storage_collision" in types


def test_can_analyze_cairo_only() -> None:
    adapter = CairoPatternAdapter()
    assert adapter.can_analyze(str(POC / "clean" / "counter_clean.cairo")) is True
    assert adapter.can_analyze("Contract.sol") is False


def test_analyze_directory_aggregates(tmp_path: Path) -> None:
    (tmp_path / "a.cairo").write_text(
        "#[starknet::contract]\nmod A { #[storage] struct Storage {} }\n"
    )
    (tmp_path / "b.cairo").write_text(
        "#[starknet::contract]\nmod B { #[storage] struct Storage {} }\n"
    )
    result = CairoPatternAdapter().analyze(str(tmp_path))
    assert result["status"] == "success"
    assert result["metadata"]["files_scanned"] == 2


def test_analyze_missing_path_is_error() -> None:
    r = CairoPatternAdapter().analyze("/does/not/exist.cairo")
    assert r["status"] == "error"
