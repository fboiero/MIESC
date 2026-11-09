"""
Tests for the source-level access-control detector wired into ``miesc scan``.

The default quick-scan path (Slither/Aderyn/Solhint + intelligence engine) is
augmented with a regex/source-level access-control detector so that scan still
surfaces access-control issues when the external tools fail to compile a
contract (old pragmas, Parity-style multi-owner proxies). The detector's
findings flow through the intelligence engine's dedup + FP suppression, and a
confidence gate keeps only high-signal rules.

Author: Fernando Boiero
"""

from unittest.mock import patch

from click.testing import CliRunner

from miesc.cli.commands.scan import run_access_control_semantic, scan

# A contract with a privileged owner-reassignment function and NO access modifier.
VULN_SOL = (
    "// SPDX-License-Identifier: MIT\n"
    "pragma solidity ^0.8.0;\n"
    "contract Vault {\n"
    "    address public owner;\n"
    "    function setOwner(address next) external {\n"
    "        owner = next;\n"
    "    }\n"
    "}\n"
)


class TestRunAccessControlSemantic:
    def test_flags_unprotected_privileged_function(self, tmp_path):
        contract = tmp_path / "Vault.sol"
        contract.write_text(VULN_SOL, encoding="utf-8")

        result = run_access_control_semantic(str(contract))

        assert result is not None
        assert result["tool"] == "access-control-semantic"
        assert result["status"] == "success"
        types = {f["type"] for f in result["findings"]}
        assert "unprotected-privileged-function" in types
        # Every emitted finding is tagged with the detector's tool name.
        assert all(f["tool"] == "access-control-semantic" for f in result["findings"])

    def test_confidence_gate_drops_low_signal_rule(self, tmp_path):
        # The broad ``missing-access-control`` rule fires at confidence 0.65 and
        # must be gated out; only >= 0.75 findings survive.
        contract = tmp_path / "Vault.sol"
        contract.write_text(VULN_SOL, encoding="utf-8")

        result = run_access_control_semantic(str(contract))

        assert result is not None
        assert all(float(f.get("confidence", 0.0)) >= 0.75 for f in result["findings"])
        assert "missing-access-control" not in {f["type"] for f in result["findings"]}

    def test_returns_none_for_missing_source(self, tmp_path):
        assert run_access_control_semantic(str(tmp_path / "does_not_exist.sol")) is None


class TestScanSurfacesAccessControl:
    def test_scan_feeds_access_control_into_pipeline_when_tools_fail(self, tmp_path):
        """When every external tool returns nothing (as when they fail to
        compile a contract), scan still feeds the source-level access-control
        finding into the intelligence-engine consolidation. We assert on the
        findings handed to ``enhance_findings`` — the deterministic wiring
        boundary — rather than the post-display report, which the Rich/CLI
        capture layer collapses under pytest for all tools alike."""
        contract = tmp_path / "Vault.sol"
        contract.write_text(VULN_SOL, encoding="utf-8")
        out = tmp_path / "report.json"

        seen: dict[str, list] = {}
        import miesc.core.intelligence as intelligence

        original = intelligence.enhance_findings

        def _spy(findings, **kwargs):
            seen["flat"] = list(findings)
            return original(findings, **kwargs)

        # Simulate external tools that produce no findings; spy the consolidation.
        with (
            patch(
                "miesc.cli.commands.scan.run_tool",
                return_value={"tool": "slither", "status": "success", "findings": []},
            ),
            patch("miesc.core.intelligence.enhance_findings", side_effect=_spy),
        ):
            runner = CliRunner()
            result = runner.invoke(
                scan,
                [str(contract), "--quiet", "--fp-strictness", "off", "-o", str(out)],
            )

        assert result.exit_code in (0, 1), result.output
        assert "flat" in seen, "intelligence consolidation was never reached"
        pipeline_types = {f.get("type") for f in seen["flat"]}
        pipeline_tools = {f.get("tool") for f in seen["flat"]}
        assert "access-control-semantic" in pipeline_tools
        assert "unprotected-privileged-function" in pipeline_types
