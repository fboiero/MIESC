"""Tests for miesc compliance command."""

import json

import pytest
from click.testing import CliRunner

from miesc.cli.commands.compliance import COMPLIANCE_MAP, compliance


@pytest.fixture
def results_json(tmp_path):
    data = {
        "findings": [
            {
                "type": "reentrancy-eth",
                "severity": "High",
                "confidence": 0.98,
                "canonical_category": "reentrancy",
                "recommendation": "Apply CEI",
            },
            {
                "type": "access-control",
                "severity": "High",
                "confidence": 0.85,
                "canonical_category": "access_control",
                "recommendation": "Add onlyOwner",
            },
            {
                "type": "unknown-type",
                "severity": "Low",
                "confidence": 0.5,
                "canonical_category": "other",
            },
        ],
    }
    p = tmp_path / "results.json"
    p.write_text(json.dumps(data))
    return str(p)


class TestComplianceMap:
    def test_reentrancy_has_all_standards(self):
        m = COMPLIANCE_MAP["reentrancy"]
        assert "SWC" in m
        assert "CWE" in m
        assert "ISO_27001" in m
        assert "MiCA" in m

    def test_all_categories_have_swc(self):
        for cat, mapping in COMPLIANCE_MAP.items():
            assert "SWC" in mapping, f"{cat} missing SWC"

    def test_map_covers_top_categories(self):
        expected = {
            "reentrancy",
            "access_control",
            "oracle_manipulation",
            "arithmetic",
            "unchecked_call",
            "flash_loan",
        }
        assert expected.issubset(COMPLIANCE_MAP.keys())


class TestComplianceCommand:
    def test_help(self):
        result = CliRunner().invoke(compliance, ["--help"])
        assert result.exit_code == 0
        assert "MiCA" in result.output

    def test_markdown_output(self, results_json):
        result = CliRunner().invoke(compliance, [results_json, "--quiet"])
        assert result.exit_code == 0
        assert "SWC-107" in result.output
        assert "reentrancy" in result.output.lower()

    def test_json_output(self, results_json, tmp_path):
        out = str(tmp_path / "map.json")
        result = CliRunner().invoke(compliance, [results_json, "-f", "json", "-o", out, "--quiet"])
        assert result.exit_code == 0
        data = json.loads(open(out).read())
        assert data["mapped_findings"] >= 2
        assert len(data["mappings"]) >= 2

    def test_filter_by_standard(self, results_json):
        result = CliRunner().invoke(compliance, [results_json, "--standard", "mica", "--quiet"])
        assert result.exit_code == 0
        assert "MiCA" in result.output
        # Should NOT contain ISO 27001 since filtered
        lines = result.output.split("\n")
        mica_lines = [l for l in lines if "MiCA" in l]
        assert len(mica_lines) >= 1

    def test_no_findings(self, tmp_path):
        p = tmp_path / "empty.json"
        p.write_text('{"findings": []}')
        result = CliRunner().invoke(compliance, [str(p), "--quiet"])
        assert result.exit_code == 0

    def test_other_category_not_mapped(self, results_json):
        result = CliRunner().invoke(compliance, [results_json, "-f", "json", "--quiet"])
        # "other" category has no mapping → should not appear
        assert "unknown-type" not in result.output
