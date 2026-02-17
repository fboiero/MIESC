"""
Tests for Result Aggregator module.

Tests the finding aggregation and correlation system.
"""

import pytest

from src.core.result_aggregator import (
    AggregatedFinding,
    Finding,
    ResultAggregator,
)


class TestFinding:
    """Test Finding dataclass."""

    def test_create_finding(self):
        """Test creating finding."""
        finding = Finding(
            id="f123",
            tool="slither",
            severity="high",
            type="reentrancy",
            message="Reentrancy vulnerability detected",
            file="Token.sol",
            line=50,
            function="withdraw",
        )
        assert finding.id == "f123"
        assert finding.tool == "slither"
        assert finding.severity == "high"
        assert finding.line == 50

    def test_default_values(self):
        """Test default values."""
        finding = Finding(
            id="f1",
            tool="test",
            severity="medium",
            type="test",
            message="test",
        )
        assert finding.file == ""
        assert finding.line == 0
        assert finding.function == ""
        assert finding.swc_id is None
        assert finding.cwe_id is None
        assert finding.confidence == 1.0
        assert finding.raw_data == {}

    def test_to_dict(self):
        """Test dictionary conversion."""
        finding = Finding(
            id="f1",
            tool="slither",
            severity="high",
            type="reentrancy",
            message="Test",
            file="Test.sol",
            line=10,
            swc_id="SWC-107",
        )
        d = finding.to_dict()
        assert d["id"] == "f1"
        assert d["tool"] == "slither"
        assert d["severity"] == "high"
        assert d["swc_id"] == "SWC-107"


class TestAggregatedFinding:
    """Test AggregatedFinding dataclass."""

    @pytest.fixture
    def original_findings(self):
        """Create original findings."""
        return [
            Finding(id="f1", tool="slither", severity="high", type="reentrancy", message="Test"),
            Finding(id="f2", tool="mythril", severity="high", type="reentrancy", message="Test"),
        ]

    def test_create_aggregated(self, original_findings):
        """Test creating aggregated finding."""
        agg = AggregatedFinding(
            id="AGG-123",
            severity="high",
            type="reentrancy",
            message="Reentrancy vulnerability",
            file="Token.sol",
            line=50,
            function="withdraw",
            swc_id="SWC-107",
            cwe_id=None,
            confidence=0.95,
            tools=["slither", "mythril"],
            confirmations=2,
            original_findings=original_findings,
        )
        assert agg.id == "AGG-123"
        assert agg.confirmations == 2
        assert len(agg.tools) == 2

    def test_to_dict(self, original_findings):
        """Test dictionary conversion."""
        agg = AggregatedFinding(
            id="AGG-123",
            severity="high",
            type="reentrancy",
            message="Test",
            file="Test.sol",
            line=10,
            function="test",
            swc_id="SWC-107",
            cwe_id=None,
            confidence=0.9,
            tools=["slither", "mythril"],
            confirmations=2,
            original_findings=original_findings,
        )
        d = agg.to_dict()
        assert d["id"] == "AGG-123"
        assert d["severity"] == "high"
        assert "location" in d
        assert d["location"]["file"] == "Test.sol"
        assert d["cross_validated"] is True
        assert d["confirmations"] == 2


class TestResultAggregator:
    """Test ResultAggregator class."""

    @pytest.fixture
    def aggregator(self):
        """Create aggregator instance."""
        return ResultAggregator()

    def test_init_default(self):
        """Test default initialization."""
        agg = ResultAggregator()
        assert agg.similarity_threshold == 0.85
        assert agg.min_confirmations == 2
        assert agg.confidence_boost == 0.15

    def test_init_custom(self):
        """Test custom initialization."""
        agg = ResultAggregator(
            similarity_threshold=0.9,
            min_confirmations=3,
            confidence_boost=0.2,
        )
        assert agg.similarity_threshold == 0.9
        assert agg.min_confirmations == 3

    def test_severity_map(self, aggregator):
        """Test severity mapping exists."""
        assert aggregator.SEVERITY_MAP["critical"] == 10
        assert aggregator.SEVERITY_MAP["high"] == 8
        assert aggregator.SEVERITY_MAP["medium"] == 5
        assert aggregator.SEVERITY_MAP["low"] == 2

    def test_type_aliases(self, aggregator):
        """Test type aliases exist."""
        assert "reentrancy" in aggregator.TYPE_ALIASES
        assert "overflow" in aggregator.TYPE_ALIASES
        assert "access-control" in aggregator.TYPE_ALIASES


class TestResultAggregatorAddResults:
    """Test adding tool results."""

    @pytest.fixture
    def aggregator(self):
        """Create aggregator."""
        return ResultAggregator()

    def test_add_tool_results(self, aggregator):
        """Test adding results."""
        results = {
            "findings": [
                {"type": "reentrancy", "severity": "high", "message": "Test"},
                {"type": "overflow", "severity": "medium", "message": "Test2"},
            ]
        }
        count = aggregator.add_tool_results("slither", results)
        assert count == 2
        assert len(aggregator._findings) == 2

    def test_add_empty_results(self, aggregator):
        """Test adding empty results."""
        count = aggregator.add_tool_results("slither", {"findings": []})
        assert count == 0

    def test_add_missing_findings_key(self, aggregator):
        """Test adding results without findings key."""
        count = aggregator.add_tool_results("slither", {})
        assert count == 0


class TestResultAggregatorNormalize:
    """Test normalization functions."""

    @pytest.fixture
    def aggregator(self):
        """Create aggregator."""
        return ResultAggregator()

    def test_normalize_severity_direct(self, aggregator):
        """Test direct severity normalization."""
        assert aggregator._normalize_severity("critical") == "critical"
        assert aggregator._normalize_severity("high") == "high"
        assert aggregator._normalize_severity("medium") == "medium"
        assert aggregator._normalize_severity("low") == "low"

    def test_normalize_severity_contains(self, aggregator):
        """Test severity normalization by content."""
        assert aggregator._normalize_severity("CRITICAL") == "critical"
        assert aggregator._normalize_severity("High Impact") == "high"
        assert aggregator._normalize_severity("Med") == "medium"
        assert aggregator._normalize_severity("informational") == "informational"

    def test_normalize_severity_default(self, aggregator):
        """Test severity defaults to medium."""
        assert aggregator._normalize_severity("unknown") == "medium"

    def test_normalize_type_canonical(self, aggregator):
        """Test normalizing to canonical type."""
        assert aggregator._normalize_type("reentrancy-eth") == "reentrancy"
        assert aggregator._normalize_type("integer-overflow") == "overflow"
        assert aggregator._normalize_type("unprotected-upgrade") == "access-control"

    def test_normalize_type_unchanged(self, aggregator):
        """Test type unchanged if no alias."""
        assert aggregator._normalize_type("custom-type") == "custom-type"

    def test_normalize_finding(self, aggregator):
        """Test normalizing finding."""
        raw = {
            "type": "reentrancy",
            "severity": "high",
            "message": "Reentrancy found",
            "location": {"file": "Token.sol", "line": 50},
        }
        finding = aggregator._normalize_finding("slither", raw)

        assert finding is not None
        assert finding.tool == "slither"
        assert finding.severity == "high"
        assert finding.type == "reentrancy"
        assert finding.file == "Token.sol"
        assert finding.line == 50

    def test_normalize_finding_with_alternate_fields(self, aggregator):
        """Test normalizing with alternate field names."""
        raw = {
            "check": "overflow",
            "impact": "medium",
            "description": "Integer overflow",
            "filename": "Test.sol",
            "lineno": 100,
        }
        finding = aggregator._normalize_finding("mythril", raw)

        assert finding is not None
        assert finding.type == "overflow"
        assert finding.severity == "medium"
        assert finding.message == "Integer overflow"
        assert finding.file == "Test.sol"
        assert finding.line == 100

    def test_normalize_finding_confidence_string(self, aggregator):
        """Test normalizing string confidence."""
        raw = {"type": "test", "severity": "medium", "message": "test", "confidence": "high"}
        finding = aggregator._normalize_finding("tool", raw)
        assert finding.confidence == 0.9


class TestResultAggregatorSimilarity:
    """Test similarity detection."""

    @pytest.fixture
    def aggregator(self):
        """Create aggregator."""
        return ResultAggregator()

    def test_are_similar_same(self, aggregator):
        """Test identical findings are similar."""
        f1 = Finding(
            id="f1",
            tool="slither",
            severity="high",
            type="reentrancy",
            message="Test message",
            file="Token.sol",
            line=50,
        )
        f2 = Finding(
            id="f2",
            tool="mythril",
            severity="high",
            type="reentrancy",
            message="Test message",
            file="Token.sol",
            line=51,
        )
        assert aggregator._are_similar(f1, f2)

    def test_are_similar_different_file(self, aggregator):
        """Test different files are not similar."""
        f1 = Finding(
            id="f1",
            tool="slither",
            severity="high",
            type="reentrancy",
            message="Test",
            file="Token.sol",
            line=50,
        )
        f2 = Finding(
            id="f2",
            tool="mythril",
            severity="high",
            type="reentrancy",
            message="Test",
            file="Other.sol",
            line=50,
        )
        assert not aggregator._are_similar(f1, f2)

    def test_are_similar_far_lines(self, aggregator):
        """Test far apart lines are not similar."""
        f1 = Finding(
            id="f1",
            tool="slither",
            severity="high",
            type="reentrancy",
            message="Test",
            file="Token.sol",
            line=50,
        )
        f2 = Finding(
            id="f2",
            tool="mythril",
            severity="high",
            type="reentrancy",
            message="Test",
            file="Token.sol",
            line=100,
        )
        assert not aggregator._are_similar(f1, f2)


class TestResultAggregatorAggregate:
    """Test aggregation."""

    @pytest.fixture
    def aggregator(self):
        """Create aggregator."""
        return ResultAggregator()

    def test_aggregate_empty(self, aggregator):
        """Test aggregating empty findings."""
        result = aggregator.aggregate()
        assert result == []

    def test_aggregate_single(self, aggregator):
        """Test aggregating single finding."""
        aggregator.add_tool_results(
            "slither", {"findings": [{"type": "reentrancy", "severity": "high", "message": "Test"}]}
        )
        result = aggregator.aggregate()
        assert len(result) == 1
        assert result[0].confirmations == 1

    def test_aggregate_deduplication(self, aggregator):
        """Test deduplication."""
        # Add similar findings from different tools
        aggregator.add_tool_results(
            "slither",
            {
                "findings": [
                    {
                        "type": "reentrancy",
                        "severity": "high",
                        "message": "Reentrancy vulnerability",
                        "location": {"file": "Token.sol", "line": 50},
                    }
                ]
            },
        )
        aggregator.add_tool_results(
            "mythril",
            {
                "findings": [
                    {
                        "type": "reentrancy",
                        "severity": "high",
                        "message": "Reentrancy vulnerability",
                        "location": {"file": "Token.sol", "line": 51},
                    }
                ]
            },
        )

        result = aggregator.aggregate()
        # Should be deduplicated to one
        assert len(result) == 1
        assert result[0].confirmations == 2
        assert "slither" in result[0].tools
        assert "mythril" in result[0].tools

    def test_aggregate_sorted_by_severity(self, aggregator):
        """Test aggregation sorts by severity."""
        aggregator.add_tool_results(
            "tool",
            {
                "findings": [
                    {"type": "info", "severity": "informational", "message": "Info"},
                    {"type": "crit", "severity": "critical", "message": "Critical"},
                    {"type": "med", "severity": "medium", "message": "Medium"},
                ]
            },
        )
        result = aggregator.aggregate()
        assert result[0].severity == "critical"


class TestResultAggregatorMerge:
    """Test merging groups."""

    @pytest.fixture
    def aggregator(self):
        """Create aggregator."""
        return ResultAggregator()

    def test_merge_group(self, aggregator):
        """Test merging group of findings."""
        findings = [
            Finding(
                id="f1",
                tool="slither",
                severity="high",
                type="reentrancy",
                message="Short message",
                file="Token.sol",
                line=50,
                confidence=0.8,
            ),
            Finding(
                id="f2",
                tool="mythril",
                severity="high",
                type="reentrancy",
                message="This is a much longer and more descriptive message",
                file="Token.sol",
                line=50,
                confidence=0.9,
                swc_id="SWC-107",
            ),
        ]
        aggregated = aggregator._merge_group(findings)

        assert "AGG-" in aggregated.id
        assert aggregated.severity == "high"
        assert aggregated.confirmations == 2
        # Should use longer message
        assert "longer" in aggregated.message
        # Should have boosted confidence
        assert aggregated.confidence > 0.9


class TestResultAggregatorStatistics:
    """Test statistics generation."""

    @pytest.fixture
    def aggregator(self):
        """Create aggregator."""
        return ResultAggregator()

    def test_get_statistics_empty(self, aggregator):
        """Test statistics with no findings."""
        stats = aggregator.get_statistics()
        assert stats["total_findings"] == 0

    def test_get_statistics(self, aggregator):
        """Test statistics generation."""
        aggregator.add_tool_results(
            "slither",
            {
                "findings": [
                    {"type": "reentrancy", "severity": "high", "message": "Test1"},
                    {"type": "overflow", "severity": "medium", "message": "Test2"},
                ]
            },
        )
        aggregator.add_tool_results(
            "mythril",
            {
                "findings": [
                    {"type": "reentrancy", "severity": "high", "message": "Test1"},
                ]
            },
        )

        stats = aggregator.get_statistics()

        assert stats["original_count"] >= 2
        assert "severity_distribution" in stats
        assert "findings_per_tool" in stats
        assert "average_confidence" in stats


class TestResultAggregatorFilters:
    """Test filtering functions."""

    @pytest.fixture
    def aggregator(self):
        """Create aggregator with data."""
        agg = ResultAggregator()
        agg.add_tool_results(
            "slither",
            {
                "findings": [
                    {
                        "type": "reentrancy",
                        "severity": "high",
                        "message": "High confidence",
                        "confidence": 0.95,
                    },
                    {
                        "type": "overflow",
                        "severity": "medium",
                        "message": "Low confidence",
                        "confidence": 0.5,
                    },
                ]
            },
        )
        agg.add_tool_results(
            "mythril",
            {
                "findings": [
                    {"type": "reentrancy", "severity": "high", "message": "High confidence"},
                ]
            },
        )
        return agg

    def test_get_high_confidence_findings(self, aggregator):
        """Test getting high confidence findings."""
        high_conf = aggregator.get_high_confidence_findings(min_confidence=0.8)
        assert all(f.confidence >= 0.8 for f in high_conf)

    def test_get_cross_validated_findings(self, aggregator):
        """Test getting cross-validated findings."""
        cross_val = aggregator.get_cross_validated_findings()
        assert all(f.confirmations >= 2 for f in cross_val)


class TestResultAggregatorReport:
    """Test report generation."""

    @pytest.fixture
    def aggregator(self):
        """Create aggregator."""
        return ResultAggregator()

    def test_to_report(self, aggregator):
        """Test report generation."""
        aggregator.add_tool_results(
            "slither", {"findings": [{"type": "reentrancy", "severity": "high", "message": "Test"}]}
        )

        report = aggregator.to_report()

        assert "summary" in report
        assert "findings" in report
        assert "high_confidence" in report
        assert "cross_validated" in report

    def test_clear(self, aggregator):
        """Test clearing aggregator."""
        aggregator.add_tool_results(
            "slither", {"findings": [{"type": "test", "severity": "high", "message": "Test"}]}
        )
        aggregator.aggregate()

        aggregator.clear()

        assert aggregator._findings == []
        assert aggregator._aggregated == []
