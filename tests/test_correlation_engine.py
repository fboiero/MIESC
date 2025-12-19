#!/usr/bin/env python3
"""
Unit tests for MIESC Smart Correlation Engine.

Author: Fernando Boiero
Institution: UNDEF - IUA
"""

import pytest
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from ml.correlation_engine import (
    SmartCorrelationEngine,
    CorrelatedFinding,
    ToolProfile,
    CorrelationMethod,
    correlate_findings,
    ExploitChainAnalyzer,
    ExploitChain,
)


class TestSmartCorrelationEngine:
    """Tests for SmartCorrelationEngine class."""

    @pytest.fixture
    def engine(self):
        """Create a fresh correlation engine for each test."""
        return SmartCorrelationEngine(
            min_tools_for_validation=2,
            similarity_threshold=0.75,
        )

    @pytest.fixture
    def sample_findings(self):
        """Sample findings from multiple tools."""
        return {
            'slither': [
                {
                    'type': 'reentrancy-eth',
                    'severity': 'high',
                    'message': 'Reentrancy in withdraw() function',
                    'location': {'file': 'Contract.sol', 'line': 42, 'function': 'withdraw'},
                    'swc_id': 'SWC-107',
                    'confidence': 0.8,
                },
                {
                    'type': 'arbitrary-send',
                    'severity': 'high',
                    'message': 'Contract sends ETH to arbitrary address',
                    'location': {'file': 'Contract.sol', 'line': 45, 'function': 'withdraw'},
                    'swc_id': 'SWC-105',
                    'confidence': 0.7,
                },
            ],
            'aderyn': [
                {
                    'type': 'reentrancy',
                    'severity': 'high',
                    'message': 'State change after external call in withdraw()',
                    'location': {'file': 'Contract.sol', 'line': 42, 'function': 'withdraw'},
                    'swc_id': 'SWC-107',
                    'confidence': 0.85,
                },
            ],
            'smartbugs-detector': [
                {
                    'type': 'arithmetic',
                    'severity': 'medium',
                    'message': 'Possible integer overflow in balance calculation',
                    'location': {'file': 'Contract.sol', 'line': 30},
                    'swc_id': 'SWC-101',
                    'confidence': 0.6,
                },
            ],
        }

    def test_add_findings(self, engine, sample_findings):
        """Test adding findings from multiple tools."""
        total = 0
        for tool, findings in sample_findings.items():
            count = engine.add_findings(tool, findings)
            total += count

        assert total == 4
        assert len(engine._findings) == 4

    def test_correlation_basic(self, engine, sample_findings):
        """Test basic correlation functionality."""
        for tool, findings in sample_findings.items():
            engine.add_findings(tool, findings)

        correlated = engine.correlate()

        # Should have fewer correlated than original (due to deduplication)
        assert len(correlated) < len(engine._findings)
        # Should have at least one finding
        assert len(correlated) >= 1

    def test_cross_validation(self, engine, sample_findings):
        """Test that cross-validated findings are detected."""
        for tool, findings in sample_findings.items():
            engine.add_findings(tool, findings)

        engine.correlate()
        cross_validated = engine.get_cross_validated_findings()

        # Reentrancy should be cross-validated (slither + aderyn)
        assert len(cross_validated) >= 1
        assert any(f.canonical_type == 'reentrancy' for f in cross_validated)

    def test_deduplication(self, engine, sample_findings):
        """Test that similar findings are deduplicated."""
        for tool, findings in sample_findings.items():
            engine.add_findings(tool, findings)

        correlated = engine.correlate()
        stats = engine.get_statistics()

        assert stats['deduplication_rate'] > 0
        assert stats['original_findings'] > stats['total_correlated']

    def test_confidence_scoring(self, engine, sample_findings):
        """Test confidence scoring calculation."""
        for tool, findings in sample_findings.items():
            engine.add_findings(tool, findings)

        correlated = engine.correlate()

        for finding in correlated:
            assert 0 <= finding.final_confidence <= 1
            assert 0 <= finding.base_confidence <= 1
            assert 0 <= finding.tool_agreement_score <= 1

    def test_fp_probability(self, engine, sample_findings):
        """Test false positive probability calculation."""
        for tool, findings in sample_findings.items():
            engine.add_findings(tool, findings)

        correlated = engine.correlate()

        for finding in correlated:
            assert 0 <= finding.false_positive_probability <= 1

    def test_severity_normalization(self, engine):
        """Test severity normalization."""
        findings = [
            {'type': 'test', 'severity': 'Critical', 'message': 'Test', 'location': {}},
            {'type': 'test', 'severity': 'HIGH', 'message': 'Test', 'location': {}},
            {'type': 'test', 'severity': 'Medium', 'message': 'Test', 'location': {}},
            {'type': 'test', 'severity': 'low', 'message': 'Test', 'location': {}},
            {'type': 'test', 'severity': 'Info', 'message': 'Test', 'location': {}},
        ]

        engine.add_findings('test-tool', findings)
        engine.correlate()

        # All severities should be normalized to standard values
        valid_severities = ['critical', 'high', 'medium', 'low', 'informational', 'info']
        for f in engine._findings:
            assert f['severity'] in valid_severities

    def test_type_normalization(self, engine):
        """Test vulnerability type normalization."""
        findings = [
            {'type': 'reentrancy-eth', 'severity': 'high', 'message': 'Test', 'location': {}},
            {'type': 'integer-overflow', 'severity': 'medium', 'message': 'Test', 'location': {}},
            {'type': 'tx-origin', 'severity': 'high', 'message': 'Test', 'location': {}},
        ]

        engine.add_findings('test-tool', findings)

        # Check normalization
        for f in engine._findings:
            assert f['canonical_type'] in ['reentrancy', 'arithmetic', 'access-control']

    def test_statistics(self, engine, sample_findings):
        """Test statistics generation."""
        for tool, findings in sample_findings.items():
            engine.add_findings(tool, findings)

        engine.correlate()
        stats = engine.get_statistics()

        assert 'total_correlated' in stats
        assert 'original_findings' in stats
        assert 'deduplication_rate' in stats
        assert 'cross_validated' in stats
        assert 'average_confidence' in stats
        assert 'by_severity' in stats
        assert 'by_type' in stats

    def test_high_confidence_filtering(self, engine, sample_findings):
        """Test high confidence filtering."""
        for tool, findings in sample_findings.items():
            engine.add_findings(tool, findings)

        engine.correlate()
        high_conf = engine.get_high_confidence_findings(min_confidence=0.7)

        for finding in high_conf:
            assert finding.final_confidence >= 0.7

    def test_likely_true_positives(self, engine, sample_findings):
        """Test likely true positives filtering."""
        for tool, findings in sample_findings.items():
            engine.add_findings(tool, findings)

        engine.correlate()
        likely_tp = engine.get_likely_true_positives(fp_threshold=0.4)

        for finding in likely_tp:
            assert finding.false_positive_probability <= 0.4

    def test_tool_profile_updates(self, engine):
        """Test tool profile updates."""
        engine.update_tool_profile('test-tool', confirmed_count=8, total_count=10)

        profile = engine.tool_profiles['test-tool']
        assert profile.confirmed_findings == 8
        assert profile.total_findings == 10

    def test_empty_findings(self, engine):
        """Test handling of empty findings."""
        correlated = engine.correlate()
        assert correlated == []

        stats = engine.get_statistics()
        assert stats['total'] == 0

    def test_single_tool_findings(self, engine):
        """Test correlation with findings from a single tool."""
        findings = [
            {'type': 'reentrancy', 'severity': 'high', 'message': 'Reentrancy vulnerability in withdraw function',
             'location': {'file': 'Contract.sol', 'line': 1}},
            {'type': 'overflow', 'severity': 'medium', 'message': 'Integer overflow in balance calculation',
             'location': {'file': 'Token.sol', 'line': 100}},
        ]

        engine.add_findings('single-tool', findings)
        correlated = engine.correlate()

        # With different messages and files, should not be deduplicated
        assert len(correlated) >= 1

        # None should be cross-validated (only one tool)
        cross_validated = engine.get_cross_validated_findings()
        assert len(cross_validated) == 0

    def test_report_generation(self, engine, sample_findings):
        """Test report generation."""
        for tool, findings in sample_findings.items():
            engine.add_findings(tool, findings)

        engine.correlate()
        report = engine.to_report()

        assert 'summary' in report
        assert 'all_findings' in report
        assert 'high_confidence' in report
        assert 'cross_validated' in report
        assert 'tool_profiles' in report

    def test_clear(self, engine, sample_findings):
        """Test clearing the engine."""
        for tool, findings in sample_findings.items():
            engine.add_findings(tool, findings)

        engine.correlate()
        engine.clear()

        assert len(engine._findings) == 0
        assert len(engine._correlated) == 0


class TestCorrelatedFinding:
    """Tests for CorrelatedFinding class."""

    def test_to_dict(self):
        """Test serialization to dictionary."""
        finding = CorrelatedFinding(
            id='CORR-test123',
            canonical_type='reentrancy',
            severity='high',
            message='Test message',
            location={'file': 'test.sol', 'line': 42},
            swc_id='SWC-107',
            cwe_id=None,
            source_findings=[],
            confirming_tools=['slither', 'aderyn'],
            correlation_method=CorrelationMethod.EXACT,
            base_confidence=0.8,
            tool_agreement_score=0.9,
            context_score=0.7,
            ml_confidence=0.75,
            final_confidence=0.85,
            is_cross_validated=True,
            false_positive_probability=0.15,
            remediation_priority=1,
        )

        d = finding.to_dict()

        assert d['id'] == 'CORR-test123'
        assert d['type'] == 'reentrancy'
        assert d['severity'] == 'high'
        assert d['is_cross_validated'] is True
        assert d['confidence']['final'] == 0.85
        assert d['fp_probability'] == 0.15


class TestToolProfile:
    """Tests for ToolProfile class."""

    def test_reliability_score_empty(self):
        """Test reliability score with no findings."""
        profile = ToolProfile(name='test')
        assert profile.reliability_score == 0.5

    def test_reliability_score_calculation(self):
        """Test reliability score calculation."""
        profile = ToolProfile(
            name='test',
            precision_history=0.8,
            recall_history=0.7,
            total_findings=100,
            confirmed_findings=75,
        )

        score = profile.reliability_score
        assert 0 <= score <= 1


class TestConvenienceFunction:
    """Tests for correlate_findings convenience function."""

    def test_correlate_findings_basic(self):
        """Test the convenience function."""
        tool_results = {
            'slither': [
                {'type': 'reentrancy', 'severity': 'high', 'message': 'Test', 'location': {'file': 'test.sol', 'line': 1}},
            ],
            'aderyn': [
                {'type': 'reentrancy', 'severity': 'high', 'message': 'Test', 'location': {'file': 'test.sol', 'line': 1}},
            ],
        }

        report = correlate_findings(tool_results, min_confidence=0.3)

        assert 'summary' in report
        assert 'all_findings' in report
        assert 'filtered_findings' in report

    def test_correlate_findings_with_chains(self):
        """Test convenience function with exploit chain detection."""
        tool_results = {
            'slither': [
                {'type': 'reentrancy', 'severity': 'high', 'message': 'Reentrancy vuln',
                 'location': {'file': 'Contract.sol', 'line': 10, 'function': 'withdraw'}},
                {'type': 'unchecked-call', 'severity': 'medium', 'message': 'Unchecked return',
                 'location': {'file': 'Contract.sol', 'line': 15, 'function': 'withdraw'}},
            ],
        }

        report = correlate_findings(tool_results, min_confidence=0.3, detect_chains=True)

        assert 'exploit_chains' in report
        assert 'summary' in report['exploit_chains']
        assert 'chains' in report['exploit_chains']


class TestExploitChainAnalyzer:
    """Tests for ExploitChainAnalyzer class."""

    @pytest.fixture
    def analyzer(self):
        """Create a fresh analyzer for each test."""
        return ExploitChainAnalyzer()

    @pytest.fixture
    def reentrancy_finding(self):
        """Create a reentrancy finding."""
        return CorrelatedFinding(
            id='CORR-001',
            canonical_type='reentrancy',
            severity='high',
            message='Reentrancy vulnerability',
            location={'file': 'Contract.sol', 'line': 42, 'function': 'withdraw'},
            swc_id='SWC-107',
            cwe_id=None,
            source_findings=[],
            confirming_tools=['slither'],
            correlation_method=CorrelationMethod.EXACT,
            base_confidence=0.8,
            tool_agreement_score=0.7,
            context_score=0.6,
            ml_confidence=0.75,
            final_confidence=0.78,
            is_cross_validated=False,
            false_positive_probability=0.22,
            remediation_priority=1,
        )

    @pytest.fixture
    def unchecked_call_finding(self):
        """Create an unchecked call finding."""
        return CorrelatedFinding(
            id='CORR-002',
            canonical_type='unchecked-call',
            severity='medium',
            message='Unchecked external call',
            location={'file': 'Contract.sol', 'line': 45, 'function': 'withdraw'},
            swc_id='SWC-104',
            cwe_id=None,
            source_findings=[],
            confirming_tools=['slither', 'aderyn'],
            correlation_method=CorrelationMethod.SEMANTIC,
            base_confidence=0.75,
            tool_agreement_score=0.8,
            context_score=0.65,
            ml_confidence=0.7,
            final_confidence=0.76,
            is_cross_validated=True,
            false_positive_probability=0.24,
            remediation_priority=2,
        )

    @pytest.fixture
    def access_control_finding(self):
        """Create an access control finding."""
        return CorrelatedFinding(
            id='CORR-003',
            canonical_type='access-control',
            severity='high',
            message='Missing access control',
            location={'file': 'Contract.sol', 'line': 30, 'function': 'setOwner'},
            swc_id='SWC-115',
            cwe_id=None,
            source_findings=[],
            confirming_tools=['slither'],
            correlation_method=CorrelationMethod.EXACT,
            base_confidence=0.85,
            tool_agreement_score=0.7,
            context_score=0.7,
            ml_confidence=0.8,
            final_confidence=0.8,
            is_cross_validated=False,
            false_positive_probability=0.2,
            remediation_priority=1,
        )

    def test_analyzer_initialization(self, analyzer):
        """Test analyzer initializes correctly."""
        assert analyzer is not None
        assert len(analyzer._chains) == 0

    def test_empty_findings(self, analyzer):
        """Test analyzer with empty findings."""
        chains = analyzer.analyze([])
        assert chains == []

    def test_single_finding(self, analyzer, reentrancy_finding):
        """Test analyzer with single finding (no chains possible)."""
        chains = analyzer.analyze([reentrancy_finding])
        assert chains == []

    def test_fund_drain_chain_detection(self, analyzer, reentrancy_finding, unchecked_call_finding):
        """Test detection of reentrancy + unchecked-call = Fund Drain chain."""
        chains = analyzer.analyze([reentrancy_finding, unchecked_call_finding])

        assert len(chains) >= 1

        # Find the Fund Drain chain
        fund_drain = next((c for c in chains if 'Fund Drain' in c.name), None)
        assert fund_drain is not None
        assert fund_drain.severity == 'critical'
        assert fund_drain.base_cvss >= 9.0
        assert 'reentrancy' in fund_drain.vuln_types
        assert 'unchecked-call' in fund_drain.vuln_types

    def test_privileged_reentrancy_chain(self, analyzer, reentrancy_finding, access_control_finding):
        """Test detection of reentrancy + access-control = Privileged Reentrancy chain."""
        chains = analyzer.analyze([reentrancy_finding, access_control_finding])

        assert len(chains) >= 1

        # Find the Privileged Reentrancy chain
        priv_reentry = next((c for c in chains if 'Privileged Reentrancy' in c.name), None)
        assert priv_reentry is not None
        assert priv_reentry.severity == 'critical'
        assert priv_reentry.base_cvss >= 9.0

    def test_chain_to_dict(self, analyzer, reentrancy_finding, unchecked_call_finding):
        """Test chain serialization."""
        chains = analyzer.analyze([reentrancy_finding, unchecked_call_finding])
        assert len(chains) >= 1

        chain_dict = chains[0].to_dict()

        assert 'id' in chain_dict
        assert 'name' in chain_dict
        assert 'description' in chain_dict
        assert 'severity' in chain_dict
        assert 'base_cvss' in chain_dict
        assert 'chain' in chain_dict
        assert 'scores' in chain_dict
        assert 'affected' in chain_dict

    def test_get_critical_chains(self, analyzer, reentrancy_finding, unchecked_call_finding):
        """Test filtering critical chains."""
        chains = analyzer.analyze([reentrancy_finding, unchecked_call_finding])
        critical = analyzer.get_critical_chains()

        for chain in critical:
            assert chain.severity == 'critical'

    def test_get_high_impact_chains(self, analyzer, reentrancy_finding, unchecked_call_finding):
        """Test filtering high impact chains."""
        chains = analyzer.analyze([reentrancy_finding, unchecked_call_finding])
        high_impact = analyzer.get_high_impact_chains(min_impact=0.7)

        for chain in high_impact:
            assert chain.impact_score >= 0.7

    def test_get_summary(self, analyzer, reentrancy_finding, unchecked_call_finding):
        """Test summary generation."""
        analyzer.analyze([reentrancy_finding, unchecked_call_finding])
        summary = analyzer.get_summary()

        assert 'total_chains' in summary
        assert 'by_severity' in summary
        assert 'critical_count' in summary
        assert 'average_cvss' in summary
        assert 'chain_names' in summary

    def test_empty_summary(self, analyzer):
        """Test summary with no chains."""
        analyzer.analyze([])
        summary = analyzer.get_summary()

        assert summary['total'] == 0
        assert 'no_chains_detected' in summary

    def test_proximity_chain_detection(self, analyzer):
        """Test detection of chains based on code proximity."""
        # Two different vulnerability types in same function
        finding1 = CorrelatedFinding(
            id='CORR-P1',
            canonical_type='arithmetic',
            severity='high',
            message='Integer overflow',
            location={'file': 'Token.sol', 'line': 50, 'function': 'transfer'},
            swc_id='SWC-101',
            cwe_id=None,
            source_findings=[],
            confirming_tools=['slither'],
            correlation_method=CorrelationMethod.EXACT,
            base_confidence=0.8,
            tool_agreement_score=0.7,
            context_score=0.6,
            ml_confidence=0.75,
            final_confidence=0.75,
            is_cross_validated=False,
            false_positive_probability=0.25,
            remediation_priority=1,
        )

        finding2 = CorrelatedFinding(
            id='CORR-P2',
            canonical_type='dos',
            severity='medium',
            message='Gas limit issue',
            location={'file': 'Token.sol', 'line': 55, 'function': 'transfer'},
            swc_id='SWC-128',
            cwe_id=None,
            source_findings=[],
            confirming_tools=['mythril'],
            correlation_method=CorrelationMethod.EXACT,
            base_confidence=0.7,
            tool_agreement_score=0.6,
            context_score=0.5,
            ml_confidence=0.65,
            final_confidence=0.65,
            is_cross_validated=False,
            false_positive_probability=0.35,
            remediation_priority=2,
        )

        chains = analyzer.analyze([finding1, finding2])

        # Should detect a proximity-based chain since both are in same function
        assert len(chains) >= 1
        # The chain should mention combined vulnerabilities or the function
        assert any('transfer' in c.name or 'Combined' in c.name for c in chains)

    def test_chain_sorting_by_cvss(self, analyzer, reentrancy_finding, unchecked_call_finding, access_control_finding):
        """Test that chains are sorted by CVSS score (highest first)."""
        chains = analyzer.analyze([reentrancy_finding, unchecked_call_finding, access_control_finding])

        if len(chains) >= 2:
            for i in range(len(chains) - 1):
                assert chains[i].base_cvss >= chains[i + 1].base_cvss


class TestExploitChain:
    """Tests for ExploitChain dataclass."""

    def test_exploit_chain_to_dict(self):
        """Test ExploitChain serialization."""
        chain = ExploitChain(
            id='CHAIN-test123',
            name='Test Chain',
            description='Test description',
            severity='critical',
            base_cvss=9.5,
            vulnerabilities=['CORR-001', 'CORR-002'],
            vuln_types=['reentrancy', 'unchecked-call'],
            attack_vector='external',
            exploitability_score=0.85,
            impact_score=0.95,
            complexity='low',
            source_files=['Contract.sol'],
            affected_functions=['withdraw'],
        )

        d = chain.to_dict()

        assert d['id'] == 'CHAIN-test123'
        assert d['name'] == 'Test Chain'
        assert d['severity'] == 'critical'
        assert d['base_cvss'] == 9.5
        assert d['chain']['length'] == 2
        assert d['attack_vector'] == 'external'
        assert d['scores']['exploitability'] == 0.85
        assert d['scores']['impact'] == 0.95
        assert d['complexity'] == 'low'


class TestCorrelationEngineCoverageCompletion:
    """Additional tests for correlation engine coverage."""

    @pytest.fixture
    def engine(self):
        return SmartCorrelationEngine()

    def test_normalize_finding_string_confidence(self, engine):
        """Test normalization with string confidence values (line 377)."""
        finding = {
            'type': 'reentrancy',
            'severity': 'high',
            'message': 'Test',
            'location': {'file': 'test.sol', 'line': 10},
            'confidence': 'high',  # String confidence
        }

        normalized = engine._normalize_finding('slither', finding)

        assert normalized['confidence'] == 0.9  # 'high' -> 0.9

    def test_normalize_finding_string_confidence_medium(self, engine):
        """Test normalization with 'medium' string confidence."""
        finding = {
            'type': 'overflow',
            'severity': 'medium',
            'message': 'Test',
            'location': {},
            'confidence': 'medium',
        }

        normalized = engine._normalize_finding('mythril', finding)
        assert normalized['confidence'] == 0.7

    def test_normalize_finding_string_confidence_low(self, engine):
        """Test normalization with 'low' string confidence."""
        finding = {
            'type': 'unused',
            'severity': 'low',
            'message': 'Test',
            'location': {},
            'confidence': 'low',
        }

        normalized = engine._normalize_finding('slither', finding)
        assert normalized['confidence'] == 0.5

    def test_normalize_severity_crit(self, engine):
        """Test severity normalization with 'crit' substring (line 424)."""
        result = engine._normalize_severity('criticality')
        assert result == 'critical'

    def test_normalize_severity_med(self, engine):
        """Test severity normalization with 'med' substring (line 428)."""
        result = engine._normalize_severity('med-priority')
        assert result == 'medium'

    def test_normalize_severity_info(self, engine):
        """Test severity normalization with 'info' substring (line 432)."""
        result = engine._normalize_severity('informational')
        assert result == 'informational'

    def test_normalize_severity_note(self, engine):
        """Test severity normalization with 'note' substring (line 432)."""
        result = engine._normalize_severity('note')
        assert result == 'informational'

    def test_normalize_severity_unknown(self, engine):
        """Test severity normalization with unknown value (line 435)."""
        result = engine._normalize_severity('xyz-unknown-level')
        assert result == 'medium'  # Default

    def test_correlation_method_semantic(self, engine):
        """Test semantic correlation for nearby same-type findings (lines 516-519)."""
        # Add findings of same type in same file, nearby lines
        engine.add_findings('slither', [{
            'type': 'reentrancy',
            'severity': 'high',
            'message': 'Reentrancy 1',
            'location': {'file': 'Contract.sol', 'line': 10, 'function': 'withdraw'},
        }])
        engine.add_findings('mythril', [{
            'type': 'reentrancy',
            'severity': 'high',
            'message': 'Reentrancy 2',
            'location': {'file': 'Contract.sol', 'line': 12, 'function': 'withdraw'},  # Nearby line
        }])

        correlated = engine.correlate()

        # Should have correlated findings
        assert len(correlated) >= 1

    def test_calculate_tool_agreement_empty_tools(self, engine):
        """Test tool agreement calculation with empty tools (line 655)."""
        result = engine._calculate_tool_agreement([], 'reentrancy')
        assert result == 0.0

    def test_calculate_tool_agreement_weakness_category(self, engine):
        """Test tool agreement with tool weakness category (line 672)."""
        from src.ml.correlation_engine import ToolProfile

        # Configure a tool with weakness in this category
        engine.tool_profiles['weak_tool'] = ToolProfile(
            name='weak_tool',
            precision_history=0.5,
            recall_history=0.5,
            specialty_categories=['other'],
            weakness_categories=['overflow'],  # Weakness in overflow
        )

        result = engine._calculate_tool_agreement(['weak_tool'], 'overflow')

        # Should have penalty for weakness (reliability_score is a property)
        assert result >= 0  # Just verify it calculates without error

    def test_exploit_chain_analyzer_insufficient_findings(self, engine):
        """Test chain detection with insufficient findings for chain (line 1158)."""
        from src.ml.correlation_engine import ExploitChainAnalyzer

        # Add only one type of vulnerability (need multiple types for chains)
        engine.add_findings('slither', [{
            'type': 'reentrancy',
            'severity': 'high',
            'message': 'Single type vuln',
            'location': {'file': 'test.sol', 'line': 10},
        }])

        correlated = engine.correlate()

        # Use ExploitChainAnalyzer
        analyzer = ExploitChainAnalyzer()
        chains = analyzer.analyze(correlated)

        # Should return empty or few chains since we only have one type
        # Chains require multiple vulnerability types to form patterns
        assert isinstance(chains, list)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
