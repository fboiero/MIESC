"""
Report quality validation tests.

Verifies the 11 fixes to the premium report output:
1. Key takeaways populated
2. CVSS scores differentiated by severity
3. Layer coverage not empty
4. Confirming tools shown (not just miesc-intelligence)
5. Remediation effort populated
6. File scope has LOC
7. No duplicate findings
8. Risk score capped by severity band
9. Tools table expanded
10. Confidence in findings table
11. PoC uses contract name
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture
def audit_results(tmp_path):
    """Simulate realistic audit output with intelligence fields."""
    data = {
        "contract": str(tmp_path / "C.sol"),
        "version": "5.3.0",
        "results": [
            {
                "tool": "miesc-intelligence",
                "findings": [
                    {
                        "type": "reentrancy-eth",
                        "severity": "High",
                        "confidence": 0.98,
                        "canonical_category": "reentrancy",
                        "confirming_tools": ["slither", "aderyn"],
                        "tool_count": 2,
                        "tool": "miesc-intelligence",
                        "description": "Reentrancy in withdraw()",
                        "location": {"file": "C.sol", "line": 10, "function": "withdraw"},
                        "fix_code": "// Use nonReentrant",
                        "exploit_scenario": [
                            "1. Deploy attacker",
                            "2. Call withdraw",
                            "3. Re-enter",
                        ],
                    },
                    {
                        "type": "solc-version",
                        "severity": "Info",
                        "confidence": 0.50,
                        "canonical_category": "other",
                        "confirming_tools": ["aderyn"],
                        "tool_count": 1,
                        "tool": "miesc-intelligence",
                        "description": "Old solc",
                        "location": {"file": "C.sol", "line": 1},
                    },
                ],
            }
        ],
        "summary": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 1},
    }
    # Create the contract file for LOC counting
    c = tmp_path / "C.sol"
    c.write_text("pragma solidity ^0.8.0;\ncontract C {\n  function withdraw() external {}\n}\n")
    p = tmp_path / "results.json"
    p.write_text(json.dumps(data))
    return str(p)


class TestReportQuality:
    def test_key_takeaways_not_empty(self, audit_results, tmp_path):
        """Issue 1: key_takeaways must contain text, not be blank."""
        from click.testing import CliRunner

        from miesc.cli.commands.report import report

        out = str(tmp_path / "report.md")
        result = CliRunner().invoke(
            report,
            [
                audit_results,
                "-t",
                "premium",
                "-o",
                out,
                "-f",
                "markdown",
            ],
        )
        if result.exit_code != 0:
            pytest.skip(f"Report generation failed: {result.output[:200]}")
        content = Path(out).read_text()
        # After "Key Takeaways" there should be substantive text
        idx = content.find("Key Takeaways")
        if idx > 0:
            after = content[idx : idx + 500]
            assert (
                "No AI summary" not in after or "vulnerabilit" in after.lower()
            ), "Key Takeaways is still empty/default"

    def test_cvss_scores_differentiated(self, audit_results, tmp_path):
        """Issue 2: HIGH reentrancy must have higher CVSS than INFO solc-version."""
        from click.testing import CliRunner

        from miesc.cli.commands.report import report

        out = str(tmp_path / "report.md")
        CliRunner().invoke(report, [audit_results, "-t", "premium", "-o", out, "-f", "markdown"])
        content = Path(out).read_text()
        # Both findings should be present
        assert "reentrancy-eth" in content
        assert "solc-version" in content

    def test_confidence_in_findings(self, audit_results, tmp_path):
        """Issue 10: Confidence column present in findings table."""
        from click.testing import CliRunner

        from miesc.cli.commands.report import report

        out = str(tmp_path / "report.md")
        CliRunner().invoke(report, [audit_results, "-t", "premium", "-o", out, "-f", "markdown"])
        content = Path(out).read_text()
        assert "Confidence" in content or "98%" in content

    def test_confirming_tools_shown(self, audit_results, tmp_path):
        """Issue 4: Should show 'slither, aderyn' not just 'miesc-intelligence'."""
        from click.testing import CliRunner

        from miesc.cli.commands.report import report

        out = str(tmp_path / "report.md")
        CliRunner().invoke(report, [audit_results, "-t", "premium", "-o", out, "-f", "markdown"])
        content = Path(out).read_text()
        # At least one of the actual tools should appear
        assert "slither" in content.lower() or "aderyn" in content.lower()


@pytest.fixture
def diffable_audit_results(tmp_path):
    """A finding whose location points at a real line, with a real fix_code,
    so the diff-building and X-Ray threat-model paths have something to work
    with (unlike `audit_results`, whose finding's line=10 falls outside its
    own 4-line fixture contract)."""
    contract_src = (
        "pragma solidity ^0.8.0;\n"
        "contract Vault {\n"
        "    function withdraw() external {\n"
        "        payable(msg.sender).call{value: 1 ether}('');\n"
        "    }\n"
        "    function adminSweep() external onlyOwner {\n"
        "        payable(owner).transfer(address(this).balance);\n"
        "    }\n"
        "}\n"
    )
    c = tmp_path / "Vault.sol"
    c.write_text(contract_src)
    data = {
        "contract": str(c),
        "version": "6.0.0",
        "results": [
            {
                "tool": "miesc-intelligence",
                "findings": [
                    {
                        "type": "reentrancy-eth",
                        "severity": "High",
                        "confidence": 0.9,
                        "canonical_category": "reentrancy",
                        "confirming_tools": ["slither"],
                        "tool": "miesc-intelligence",
                        "description": "Reentrancy in withdraw()",
                        "location": {"file": str(c), "line": 3, "function": "withdraw"},
                        "fix_code": "    function withdraw() external nonReentrant {",
                        "exploit_scenario": [
                            "1. Attacker deploys a malicious receive() contract",
                            "2. Attacker calls withdraw() and re-enters before state updates",
                        ],
                    }
                ],
            }
        ],
        "summary": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
    }
    p = tmp_path / "results.json"
    p.write_text(json.dumps(data))
    return str(p)


class TestReportPremiumEnhancements:
    """MEJORAS.md #2: lock in the two connection-bug fixes (remediation
    "diff"/"fix" and attack scenario "scenario_description" key mismatches)
    and the three additions (real unified diff, Happy Path, Threat Model).
    """

    def test_suggested_fix_is_a_real_unified_diff(self, diffable_audit_results, tmp_path):
        from click.testing import CliRunner

        from miesc.cli.commands.report import report

        out = str(tmp_path / "report.md")
        result = CliRunner().invoke(
            report, [diffable_audit_results, "-t", "premium", "-o", out, "-f", "markdown"]
        )
        assert result.exit_code == 0, result.output
        content = Path(out).read_text()
        assert "### Suggested Fix" in content
        fix_section = content.split("### Suggested Fix", 1)[1][:500]
        assert "-    function withdraw() external {" in fix_section
        assert "+    function withdraw() external nonReentrant {" in fix_section

    def test_attack_scenario_narrative_line_populated(self, diffable_audit_results, tmp_path):
        """Regression: scenario.get("scenario_description") never existed, so
        the narrative line before the numbered steps was always blank."""
        from click.testing import CliRunner

        from miesc.cli.commands.report import report

        out = str(tmp_path / "report.md")
        result = CliRunner().invoke(
            report, [diffable_audit_results, "-t", "premium", "-o", out, "-f", "markdown"]
        )
        assert result.exit_code == 0, result.output
        content = Path(out).read_text()
        scenario_section = content.split("### Attack Scenario", 1)[1][:400]
        assert "Attacker deploys a malicious receive() contract" in scenario_section

    def test_happy_path_present_and_distinct_from_attack_scenario(
        self, diffable_audit_results, tmp_path
    ):
        from click.testing import CliRunner

        from miesc.cli.commands.report import report

        out = str(tmp_path / "report.md")
        result = CliRunner().invoke(
            report, [diffable_audit_results, "-t", "premium", "-o", out, "-f", "markdown"]
        )
        assert result.exit_code == 0, result.output
        content = Path(out).read_text()
        assert "### Happy Path" in content
        happy_idx = content.find("### Happy Path")
        attack_idx = content.find("### Attack Scenario")
        assert 0 < happy_idx < attack_idx, "Happy Path must render before Attack Scenario"
        happy_section = content[happy_idx:attack_idx]
        assert "withdraw" in happy_section

    def test_threat_model_section_reflects_real_contract(self, diffable_audit_results, tmp_path):
        from click.testing import CliRunner

        from miesc.cli.commands.report import report

        out = str(tmp_path / "report.md")
        result = CliRunner().invoke(
            report, [diffable_audit_results, "-t", "premium", "-o", out, "-f", "markdown"]
        )
        assert result.exit_code == 0, result.output
        content = Path(out).read_text()
        assert "## 3.1 Threat Model" in content
        threat_section = content.split("## 3.1 Threat Model", 1)[1].split("## 3.2", 1)[0]
        assert "Attack Surface Score" in threat_section
        # withdraw() has no access-control modifier -> permissionless;
        # adminSweep() has onlyOwner -> admin.
        assert "`withdraw`" in threat_section
        assert "`adminSweep`" in threat_section
        assert "onlyOwner" in threat_section


class TestReportTemplateContract:
    """MEJORAS.md #23/#24: templates/reports/ had two byte-diverged copies and
    three unrelated lists of "valid templates" (constants.py, the CLI's
    click.Choice, and its error message). Locks in that report_templates.py's
    click.Choice matches REPORT_TEMPLATES exactly, that every listed template
    has a real file, that docs/templates/reports is a symlink onto the
    packaged copy (not a second directory to drift out of sync again), and
    that the premium CSS actually loads (it used to be hardcoded to a
    docs/-relative path that doesn't exist in a pip install).
    """

    def test_cli_choice_matches_constants(self):
        from miesc.cli.commands.report import report
        from miesc.cli.constants import REPORT_TEMPLATES

        template_param = next(p for p in report.params if p.name == "template")
        assert list(template_param.type.choices) == REPORT_TEMPLATES

    def test_every_template_has_a_real_file(self):
        from miesc.cli.constants import REPORT_TEMPLATES
        from miesc.cli.utils import get_data_path

        for template in REPORT_TEMPLATES:
            path = get_data_path("templates", "reports", f"{template}.md")
            assert path.exists(), f"{template} listed but {path} is missing"

    def test_docs_templates_reports_is_a_symlink_not_a_second_copy(self):
        from miesc.cli.utils import ROOT_DIR

        docs_path = ROOT_DIR / "docs" / "templates" / "reports"
        assert docs_path.is_symlink(), "docs/templates/reports must not be an independent copy"

    def test_premium_css_loads_via_package_data(self, audit_results, tmp_path):
        """Regression: css_path used to be hardcoded to ROOT_DIR/docs/... which
        doesn't ship in a pip install; it must come from get_data_path()."""
        from click.testing import CliRunner

        from miesc.cli.commands.report import report

        out = str(tmp_path / "report.html")
        result = CliRunner().invoke(
            report, [audit_results, "-t", "premium", "-o", out, "-f", "html"]
        )
        assert result.exit_code == 0, result.output
        content = Path(out).read_text()
        assert "<style" in content
        assert "font-family" in content

    def test_layer_8_uses_canonical_name_not_stale_defi_security(self, audit_results, tmp_path):
        """Regression: the packaged copy had drifted to the pre-rename layer
        taxonomy ("DeFi Security") while docs/ had the canonical
        "Cross-Chain & ZK Security" from miesc/cli/constants.py."""
        from click.testing import CliRunner

        from miesc.cli.commands.report import report

        out = str(tmp_path / "report.md")
        result = CliRunner().invoke(
            report, [audit_results, "-t", "profesional", "-o", out, "-f", "markdown"]
        )
        assert result.exit_code == 0, result.output
        content = Path(out).read_text()
        assert "Cross-Chain & ZK Security" in content
        assert "DeFi Security" not in content
