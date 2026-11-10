"""
Integration + E2E tests for the Cairo/Caracal pipeline.

These need the real caracal binary and are SKIPPED when it is not available
(e.g. CI without CARACAL_BIN set). On a machine with Caracal installed (or
CARACAL_BIN pointing at a build) they run the analyzer against the committed
fixtures and compare to expected_findings.json, and exercise the CLI end to end.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL-3.0
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from miesc.adapters.caracal_adapter import CaracalAdapter
from miesc.core.tool_protocol import ToolStatus

POC = Path(__file__).parent.parent / "examples" / "contracts" / "cairo" / "caracal_poc"
EXPECTED = json.loads((POC / "expected_findings.json").read_text())

_caracal_available = CaracalAdapter().is_available() == ToolStatus.AVAILABLE
pytestmark = pytest.mark.skipif(
    not _caracal_available,
    reason="caracal binary not available (set CARACAL_BIN or install caracal)",
)


@pytest.mark.parametrize(
    "rel,expected",
    [(rel, meta) for rel, meta in EXPECTED["fixtures"].items() if meta.get("primary_detector_fires")],
)
def test_primary_detector_fires(rel: str, expected: dict) -> None:
    result = CaracalAdapter().analyze(str(POC / rel))
    assert result["status"] == "success"
    detectors = {f["type"] for f in result["findings"]}
    assert expected["primary_detector"] in detectors, (
        f"{rel}: expected {expected['primary_detector']} in {sorted(detectors)}"
    )


def test_clean_contract_zero_findings() -> None:
    result = CaracalAdapter().analyze(str(POC / "clean" / "counter_clean.cairo"))
    assert result["status"] == "success"
    assert result["findings"] == []


def test_uncompilable_is_honest_error() -> None:
    result = CaracalAdapter().analyze(str(POC / "error_cases" / "uncompilable.cairo"))
    assert result["status"] == "error"
    assert result["findings"] == []


def test_scarb_project_route() -> None:
    result = CaracalAdapter().analyze(str(POC / "scarb_project"))
    assert result["status"] == "success"
    detectors = {f["type"] for f in result["findings"]}
    assert "unused-arguments" in detectors


def test_dead_code_documented_inert() -> None:
    """dead-code is registered but inert on Cairo 2.x — assert the expected
    ground truth records it so a future compiler change that revives it is
    noticed (the fixture fires other detectors, not dead-code)."""
    result = CaracalAdapter().analyze(str(POC / "vulnerable" / "dead_code.cairo"))
    detectors = {f["type"] for f in result["findings"]}
    assert "dead-code" not in detectors
    assert "dead-code" in EXPECTED["not_applicable"]


# --------------------------------------------------------------------------- #
# E2E CLI: miesc scan on a Scarb project -> both adapters, deduped, SARIF      #
# --------------------------------------------------------------------------- #


def test_e2e_cli_scan_scarb_project(tmp_path: Path) -> None:
    from click.testing import CliRunner

    from miesc.cli.commands.scan import scan

    out = tmp_path / "report.json"
    runner = CliRunner()
    result = runner.invoke(
        scan,
        [str(POC / "scarb_project"), "-o", str(out), "--quiet"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    data = json.loads(out.read_text())
    # Both Cairo adapters ran (plus the intelligence consolidation).
    assert "caracal" in data["tools"]
    assert "cairo" in data["tools"]
    assert data["total_findings"] >= 1


def test_e2e_cli_sarif_export(tmp_path: Path) -> None:
    from click.testing import CliRunner

    from miesc.cli.commands.export import export
    from miesc.cli.commands.scan import scan

    report = tmp_path / "report.json"
    runner = CliRunner()
    scan_res = runner.invoke(
        scan,
        [str(POC / "vulnerable" / "reentrancy.cairo"), "-o", str(report), "--quiet", "--fp-strictness", "off"],
        catch_exceptions=False,
    )
    assert scan_res.exit_code == 0, scan_res.output

    sarif_out = tmp_path / "report.sarif.json"
    exp_res = runner.invoke(
        export, [str(report), "-f", "sarif", "-o", str(sarif_out)], catch_exceptions=False
    )
    assert exp_res.exit_code == 0, exp_res.output
    sarif = json.loads(sarif_out.read_text())
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"], "SARIF should contain Cairo findings"
