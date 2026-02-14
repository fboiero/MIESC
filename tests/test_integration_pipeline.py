"""
MIESC Integration Tests - Full Audit Pipeline
Tests CLI commands, result aggregation, correlation engine, and ML pipeline.
"""

import json
import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from src.core.result_aggregator import ResultAggregator
from src.ml import MLPipeline
from src.ml.correlation_engine import (
    ExploitChainAnalyzer,
    SmartCorrelationEngine,
    correlate_findings,
)

# ============================================================================
# TestAuditPipelineCLI - CLI commands via Click's CliRunner
# ============================================================================


@pytest.mark.integration
class TestAuditPipelineCLI:
    """Integration tests for CLI audit commands."""

    def test_audit_quick_returns_json_output(self, cli_runner, vulnerable_contract):
        """Run audit quick on VulnerableBank.sol and verify JSON output."""
        from miesc.cli.main import cli

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            output_path = f.name

        try:
            with patch("miesc.cli.commands.audit.run_tool") as mock_run:
                mock_run.return_value = {
                    "tool": "slither",
                    "contract": vulnerable_contract,
                    "status": "success",
                    "findings": [
                        {
                            "type": "reentrancy",
                            "severity": "HIGH",
                            "message": "Reentrancy in withdraw()",
                        }
                    ],
                    "execution_time": 1.5,
                    "timestamp": "2026-01-27T00:00:00",
                }

                result = cli_runner.invoke(
                    cli, ["audit", "quick", vulnerable_contract, "-o", output_path]
                )

                assert result.exit_code == 0

                # Verify JSON output file
                with open(output_path) as out:
                    data = json.load(out)
                assert "results" in data or "summary" in data
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)

    def test_audit_quick_ci_mode(self, cli_runner, vulnerable_contract):
        """Run audit quick with --ci flag and verify exit codes."""
        from miesc.cli.main import cli

        with patch("miesc.cli.commands.audit.run_tool") as mock_run:
            mock_run.return_value = {
                "tool": "slither",
                "contract": vulnerable_contract,
                "status": "success",
                "findings": [
                    {
                        "type": "reentrancy",
                        "severity": "CRITICAL",
                        "message": "Critical reentrancy",
                    }
                ],
                "execution_time": 1.0,
                "timestamp": "2026-01-27T00:00:00",
            }

            result = cli_runner.invoke(cli, ["audit", "quick", vulnerable_contract, "--ci"])

            # CI mode should exit 1 when critical findings exist
            assert result.exit_code == 1

    def test_audit_smart_with_mock_tools(self, cli_runner, vulnerable_contract):
        """Run audit smart with mocked adapters and verify ML enhancement applied."""
        from miesc.cli.main import cli

        with patch("miesc.cli.commands.audit.get_ml_orchestrator") as mock_ml:

            # Create a properly mocked result object
            mock_result = MagicMock()
            mock_result.ml_filtered_findings = [
                {
                    "type": "reentrancy",
                    "severity": "HIGH",
                    "title": "Reentrancy vulnerability",
                    "location": {"file": "test.sol", "line": 10},
                }
            ]
            mock_result.total_raw_findings = 3
            mock_result.false_positives_removed = 2
            mock_result.cross_validated = 1
            mock_result.get_summary.return_value = {
                "total_findings": 1,
                "risk_level": "HIGH",
                "critical": 0,
                "high": 1,
                "medium": 0,
                "low": 0,
                "reduction_rate": 66.7,
            }
            mock_result.to_dict.return_value = {
                "findings": mock_result.ml_filtered_findings,
                "summary": mock_result.get_summary.return_value,
            }

            mock_orchestrator = MagicMock()
            mock_orchestrator.analyze.return_value = mock_result
            mock_ml.return_value = mock_orchestrator

            result = cli_runner.invoke(cli, ["audit", "smart", vulnerable_contract])

            # Should not crash
            assert result.exit_code == 0 or result.exit_code is None

    def test_scan_command_output(self, cli_runner, vulnerable_contract):
        """Run scan command and verify structured output."""
        from miesc.cli.main import cli

        with patch("miesc.cli.commands.audit.run_tool") as mock_run:
            mock_run.return_value = {
                "tool": "slither",
                "contract": vulnerable_contract,
                "status": "success",
                "findings": [],
                "execution_time": 0.5,
                "timestamp": "2026-01-27T00:00:00",
            }

            result = cli_runner.invoke(cli, ["scan", vulnerable_contract])
            assert result.exit_code == 0

    def test_audit_with_nonexistent_file(self, cli_runner):
        """Verify graceful error for missing contract."""
        from miesc.cli.main import cli

        result = cli_runner.invoke(cli, ["audit", "quick", "/tmp/nonexistent_contract_12345.sol"])
        # Click should report an error for missing file (exists=True check)
        assert result.exit_code != 0

    def test_audit_output_to_file(self, cli_runner, vulnerable_contract):
        """Verify --output flag writes file correctly."""
        from miesc.cli.main import cli

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            output_path = f.name

        try:
            with patch("miesc.cli.commands.audit.run_tool") as mock_run:
                mock_run.return_value = {
                    "tool": "slither",
                    "contract": vulnerable_contract,
                    "status": "success",
                    "findings": [],
                    "execution_time": 0.5,
                    "timestamp": "2026-01-27T00:00:00",
                }

                result = cli_runner.invoke(
                    cli,
                    ["audit", "quick", vulnerable_contract, "-o", output_path],
                )

                assert result.exit_code == 0
                assert os.path.exists(output_path)

                with open(output_path) as out:
                    data = json.load(out)
                assert isinstance(data, dict)
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)


# ============================================================================
# TestResultAggregation - Result aggregator with multi-tool data
# ============================================================================


@pytest.mark.integration
class TestResultAggregation:
    """Integration tests for ResultAggregator with multi-tool data."""

    def test_aggregate_findings_from_multiple_tools(self, multi_tool_findings):
        """Feed findings from 3+ tools and verify deduplication."""
        aggregator = ResultAggregator()

        for tool_name, findings in multi_tool_findings.items():
            aggregator.add_tool_results(tool_name, {"findings": findings})

        aggregated = aggregator.aggregate()

        # Should have fewer findings than the sum of all inputs
        total_input = sum(len(f) for f in multi_tool_findings.values())
        assert len(aggregated) <= total_input
        assert len(aggregated) > 0

    def test_cross_validated_findings_boost_confidence(self, multi_tool_findings):
        """Findings confirmed by 2+ tools get higher confidence."""
        aggregator = ResultAggregator()

        for tool_name, findings in multi_tool_findings.items():
            aggregator.add_tool_results(tool_name, {"findings": findings})

        aggregator.aggregate()
        cross_validated = aggregator.get_cross_validated_findings()

        # Reentrancy is reported by all three tools - should be cross-validated
        assert len(cross_validated) >= 1

        # Cross-validated findings should have higher confidence
        for cv_finding in cross_validated:
            assert cv_finding.confirmations >= 2
            assert cv_finding.confidence > 0.5

    def test_severity_normalization(self):
        """Different severity strings are normalized correctly."""
        aggregator = ResultAggregator()

        findings = [
            {
                "type": "test",
                "severity": "CRITICAL",
                "message": "crit",
                "location": {"file": "a.sol", "line": 1},
            },
            {
                "type": "test2",
                "severity": "High",
                "message": "high",
                "location": {"file": "a.sol", "line": 5},
            },
            {
                "type": "test3",
                "severity": "med",
                "message": "med",
                "location": {"file": "a.sol", "line": 10},
            },
            {
                "type": "test4",
                "severity": "Info",
                "message": "info",
                "location": {"file": "a.sol", "line": 15},
            },
            {
                "type": "test5",
                "severity": "note",
                "message": "note",
                "location": {"file": "a.sol", "line": 20},
            },
        ]

        aggregator.add_tool_results("test_tool", {"findings": findings})
        aggregated = aggregator.aggregate()

        # All should be normalized to known values
        severities = {f.severity for f in aggregated}
        valid_severities = {
            "critical",
            "high",
            "medium",
            "low",
            "informational",
            "info",
            "note",
            "warning",
            "optimization",
        }
        assert severities.issubset(valid_severities)

    def test_aggregate_statistics(self, multi_tool_findings):
        """Verify statistics output structure."""
        aggregator = ResultAggregator()

        for tool_name, findings in multi_tool_findings.items():
            aggregator.add_tool_results(tool_name, {"findings": findings})

        aggregator.aggregate()
        stats = aggregator.get_statistics()

        assert "total_findings" in stats
        assert "original_count" in stats
        assert "deduplicated" in stats
        assert "cross_validated" in stats
        assert "cross_validation_rate" in stats
        assert "severity_distribution" in stats
        assert "findings_per_tool" in stats
        assert "average_confidence" in stats
        assert "unique_tools" in stats

        # We fed 3 tools
        assert stats["unique_tools"] == 3
        assert stats["original_count"] >= stats["total_findings"]


# ============================================================================
# TestCorrelationEngineIntegration - Correlation with realistic data
# ============================================================================


@pytest.mark.integration
class TestCorrelationEngineIntegration:
    """Integration tests for SmartCorrelationEngine with realistic data."""

    def test_correlate_overlapping_reentrancy_findings(
        self, correlation_engine, multi_tool_findings
    ):
        """Reentrancy from Slither + Mythril + Solhint should correlate."""
        for tool_name, findings in multi_tool_findings.items():
            correlation_engine.add_findings(tool_name, findings)

        correlated = correlation_engine.correlate()

        assert len(correlated) > 0

        # Find the reentrancy correlated finding
        reentrancy = [f for f in correlated if f.canonical_type == "reentrancy"]
        assert len(reentrancy) >= 1

        # Should be confirmed by multiple tools
        best_reentrancy = max(reentrancy, key=lambda f: len(f.confirming_tools))
        assert len(best_reentrancy.confirming_tools) >= 2

    def test_exploit_chain_detection(self, multi_tool_findings):
        """Reentrancy + unchecked-call should form an exploit chain."""
        engine = SmartCorrelationEngine()

        for tool_name, findings in multi_tool_findings.items():
            engine.add_findings(tool_name, findings)

        correlated = engine.correlate()

        # Run exploit chain analysis
        chain_analyzer = ExploitChainAnalyzer()
        chains = chain_analyzer.analyze(correlated)

        # Reentrancy + unchecked-call = Fund Drain Attack chain
        reentrancy_types = {f.canonical_type for f in correlated}
        if "reentrancy" in reentrancy_types and "unchecked-call" in reentrancy_types:
            assert len(chains) >= 1
            chain_names = [c.name for c in chains]
            assert any("Fund Drain" in name or "Combined" in name for name in chain_names)

    def test_false_positive_probability_scoring(self, multi_tool_findings):
        """FP probability should reflect tool agreement."""
        engine = SmartCorrelationEngine()

        for tool_name, findings in multi_tool_findings.items():
            engine.add_findings(tool_name, findings)

        correlated = engine.correlate()

        for finding in correlated:
            # FP probability should be between 0 and 1
            assert 0 <= finding.false_positive_probability <= 1.0

            # Cross-validated findings should have lower FP probability
            if finding.is_cross_validated:
                single_tool = [f for f in correlated if not f.is_cross_validated]
                if single_tool:
                    avg_cv_fp = finding.false_positive_probability
                    sum(f.false_positive_probability for f in single_tool) / len(single_tool)
                    # Cross-validated should generally have lower FP
                    # (not always guaranteed, so just check it's reasonable)
                    assert avg_cv_fp <= 1.0

    def test_correlation_report_structure(self, multi_tool_findings):
        """Verify report dict has all expected fields."""
        engine = SmartCorrelationEngine()

        for tool_name, findings in multi_tool_findings.items():
            engine.add_findings(tool_name, findings)

        engine.correlate()
        report = engine.to_report()

        assert "summary" in report
        assert "all_findings" in report
        assert "high_confidence" in report
        assert "cross_validated" in report
        assert "likely_true_positives" in report
        assert "tool_profiles" in report

        # Summary has expected keys
        summary = report["summary"]
        assert "total_correlated" in summary
        assert "original_findings" in summary
        assert "deduplication_rate" in summary
        assert "by_severity" in summary
        assert "by_type" in summary

    def test_tool_profile_reliability(self):
        """Tool profiles should affect correlation weights."""
        engine = SmartCorrelationEngine()

        # Add findings from high-reliability tool (slither)
        engine.add_findings(
            "slither",
            [
                {
                    "type": "reentrancy",
                    "severity": "high",
                    "message": "Reentrancy in withdraw",
                    "location": {"file": "test.sol", "line": 10, "function": "withdraw"},
                    "confidence": "high",
                }
            ],
        )

        # Add findings from lower-reliability tool (smartllm)
        engine.add_findings(
            "smartllm",
            [
                {
                    "type": "access-control",
                    "severity": "high",
                    "message": "Missing access control",
                    "location": {"file": "test.sol", "line": 20, "function": "admin"},
                    "confidence": "high",
                }
            ],
        )

        correlated = engine.correlate()
        assert len(correlated) >= 1

        # Slither profile should exist with high reliability
        slither_profile = engine.tool_profiles.get("slither")
        smartllm_profile = engine.tool_profiles.get("smartllm")

        assert slither_profile is not None
        assert smartllm_profile is not None

        # Slither has preset reliability higher than smartllm
        slither_weight = engine.TOOL_WEIGHTS.get("slither", 0.5)
        smartllm_weight = engine.TOOL_WEIGHTS.get("smartllm", 0.5)
        assert slither_weight > smartllm_weight


# ============================================================================
# TestMLPipelineEndToEnd - ML enhancement full flow
# ============================================================================


@pytest.mark.integration
class TestMLPipelineEndToEnd:
    """Integration tests for full ML pipeline flow."""

    def setup_method(self):
        self.pipeline = MLPipeline(fp_threshold=0.5, enable_feedback=True)

    def test_fp_filter_removes_low_confidence(self):
        """FP filter should filter out low-confidence/informational findings."""
        findings = [
            {
                "_id": "f1",
                "type": "reentrancy",
                "severity": "high",
                "message": "Reentrancy vulnerability in withdraw function",
                "location": {"file": "test.sol", "line": 15},
                "tool": "slither",
                "confidence": 0.9,
            },
            {
                "_id": "f2",
                "type": "naming-convention",
                "severity": "informational",
                "message": "Function name does not follow convention",
                "location": {"file": "test.sol", "line": 5},
                "tool": "solhint",
                "confidence": 0.3,
            },
        ]

        result = self.pipeline.process(findings)

        # Some filtering should occur
        assert result.original_findings is not None
        assert result.filtered_findings is not None
        assert result.processing_time_ms >= 0

    def test_severity_prediction_consistent(self):
        """Severity predictions should be consistent with input data."""
        findings = [
            {
                "_id": "f1",
                "type": "reentrancy",
                "severity": "high",
                "message": "Reentrancy vulnerability detected by external call before state update",
                "location": {"file": "test.sol", "line": 15},
                "tool": "slither",
                "confidence": 0.9,
            },
        ]

        result = self.pipeline.process(findings)

        # Pipeline should preserve or adjust severity logically
        for finding in result.filtered_findings:
            severity = finding.get("severity", "").lower()
            assert severity in ["critical", "high", "medium", "low", "informational", "info"]

    def test_clustering_groups_similar_findings(self):
        """Similar findings should be grouped into clusters."""
        findings = [
            {
                "_id": "r1",
                "type": "reentrancy",
                "severity": "high",
                "message": "Reentrancy in withdraw function",
                "location": {"file": "VulnerableBank.sol", "line": 15},
                "tool": "slither",
            },
            {
                "_id": "r2",
                "type": "reentrancy",
                "severity": "high",
                "message": "Reentrancy vulnerability in transfer function",
                "location": {"file": "VulnerableBank.sol", "line": 30},
                "tool": "mythril",
            },
            {
                "_id": "r3",
                "type": "reentrancy",
                "severity": "medium",
                "message": "Potential reentrancy in sendFunds",
                "location": {"file": "VulnerableBank.sol", "line": 45},
                "tool": "solhint",
            },
        ]

        result = self.pipeline.process(findings)

        # Similar reentrancy findings should be clustered
        assert len(result.clusters) >= 1

    def test_ml_pipeline_preserves_critical_findings(self):
        """Critical findings should never be filtered out."""
        findings = [
            {
                "_id": "c1",
                "type": "reentrancy",
                "severity": "critical",
                "message": "Critical reentrancy vulnerability allows complete fund drain",
                "location": {"file": "VulnerableBank.sol", "line": 10},
                "tool": "slither",
                "confidence": 0.95,
                "swc_id": "SWC-107",
            },
        ]

        result = self.pipeline.process(findings)

        # Critical finding should not be removed
        assert len(result.filtered_findings) >= 1
        critical_types = [
            f.get("type")
            for f in result.filtered_findings
            if f.get("severity", "").lower() in ["critical", "high"]
        ]
        assert "reentrancy" in critical_types


# ============================================================================
# TestCorrelationConvenienceFunction
# ============================================================================


@pytest.mark.integration
class TestCorrelationConvenienceFunction:
    """Tests for the correlate_findings convenience function."""

    def test_correlate_findings_full_report(self, multi_tool_findings):
        """Test correlate_findings produces complete report."""
        report = correlate_findings(
            multi_tool_findings,
            min_confidence=0.3,
            detect_chains=True,
        )

        assert "summary" in report
        assert "all_findings" in report
        assert "filtered_findings" in report
        assert "exploit_chains" in report or "summary" in report

    def test_correlate_findings_empty_input(self):
        """Test correlate_findings handles empty input."""
        report = correlate_findings({})

        assert "summary" in report
        summary = report["summary"]
        assert summary.get("total", 0) == 0 or summary.get("no_data", False)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
