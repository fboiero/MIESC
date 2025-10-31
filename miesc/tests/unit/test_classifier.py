"""
Unit Tests for miesc.core.classifier

Comprehensive test suite for vulnerability classification module.
Target Coverage: >90%

Author: Fernando Boiero
Institution: UNDEF - IUA Córdoba
"""

import pytest
from unittest.mock import Mock, patch
from miesc.core.classifier import VulnerabilityClassifier, classify_vulnerabilities


class TestVulnerabilityClassifier:
    """Test suite for VulnerabilityClassifier class"""

    def test_classifier_initialization(self):
        """Test classifier initialization"""
        classifier = VulnerabilityClassifier(ai_enabled=True, api_key="test-key")

        assert classifier.ai_enabled is True
        assert classifier.api_key == "test-key"
        assert len(classifier.swc_cvss_mapping) > 0
        assert len(classifier.swc_owasp_mapping) > 0

    def test_classifier_default_initialization(self):
        """Test default initialization"""
        classifier = VulnerabilityClassifier()

        assert classifier.ai_enabled is False
        assert classifier.api_key is None

    def test_swc_cvss_mapping(self):
        """Test SWC to CVSS mapping"""
        classifier = VulnerabilityClassifier()

        assert classifier.swc_cvss_mapping["SWC-107"] == 9.1  # Reentrancy
        assert classifier.swc_cvss_mapping["SWC-101"] == 8.1  # Integer overflow

    def test_swc_owasp_mapping(self):
        """Test SWC to OWASP mapping"""
        classifier = VulnerabilityClassifier()

        assert "Reentrancy" in classifier.swc_owasp_mapping["SWC-107"]
        assert "Access Control" in classifier.swc_owasp_mapping["SWC-112"]

    def test_classify_empty_report(self):
        """Test classifying empty report"""
        classifier = VulnerabilityClassifier()
        report = {"findings": []}

        result = classifier.classify(report)

        assert result['classified_findings'] == []
        assert result['statistics']['total_findings'] == 0

    def test_classify_single_finding(self):
        """Test classifying single finding"""
        classifier = VulnerabilityClassifier()
        report = {
            "findings": [
                {
                    "tool": "slither",
                    "vulnerability_type": "reentrancy",
                    "severity": "High",
                    "swc_id": "SWC-107"
                }
            ]
        }

        result = classifier.classify(report)

        assert len(result['classified_findings']) == 1
        assert result['statistics']['total_findings'] == 1

    def test_classify_multiple_findings(self):
        """Test classifying multiple findings"""
        classifier = VulnerabilityClassifier()
        report = {
            "findings": [
                {"tool": "slither", "swc_id": "SWC-107", "severity": "High"},
                {"tool": "mythril", "swc_id": "SWC-101", "severity": "Medium"},
                {"tool": "slither", "swc_id": "SWC-105", "severity": "Critical"}
            ]
        }

        result = classifier.classify(report)

        assert len(result['classified_findings']) == 3
        assert result['statistics']['total_findings'] == 3

    @patch('miesc.core.classifier.VulnerabilityClassifier._ai_triage')
    def test_classify_with_ai_triage(self, mock_ai):
        """Test classification with AI triage enabled"""
        mock_ai.return_value = {"is_false_positive": False}

        classifier = VulnerabilityClassifier(ai_enabled=True, api_key="test")
        report = {"findings": [{"tool": "slither", "severity": "High"}]}

        result = classifier.classify(report, enable_ai_triage=True)

        assert mock_ai.called
        assert result['ai_triage_enabled'] is True

    def test_cvss_score_calculation(self):
        """Test CVSS score calculation"""
        classifier = VulnerabilityClassifier()

        # Test known SWC with CVSS mapping
        finding = {"swc_id": "SWC-107"}
        classified = classifier._classify_finding(finding)

        assert 'cvss_score' in classified
        assert classified['cvss_score'] == 9.1

    def test_owasp_category_assignment(self):
        """Test OWASP category assignment"""
        classifier = VulnerabilityClassifier()

        finding = {"swc_id": "SWC-107"}
        classified = classifier._classify_finding(finding)

        assert 'owasp_category' in classified
        assert "Reentrancy" in classified['owasp_category']

    def test_statistics_calculation(self):
        """Test statistics calculation"""
        classifier = VulnerabilityClassifier()
        report = {
            "findings": [
                {"swc_id": "SWC-107", "severity": "High"},
                {"swc_id": "SWC-101", "severity": "Medium"},
                {"swc_id": "SWC-105", "severity": "Critical"}
            ]
        }

        result = classifier.classify(report)
        stats = result['statistics']

        assert stats['total_findings'] == 3
        assert 'avg_cvss' in stats
        assert stats['by_severity']['High'] >= 1


class TestClassifyVulnerabilitiesFunction:
    """Test suite for classify_vulnerabilities main function"""

    @patch('miesc.core.classifier.VulnerabilityClassifier')
    def test_classify_vulnerabilities_basic(self, mock_classifier_class):
        """Test basic vulnerability classification"""
        mock_classifier = Mock()
        mock_classifier.classify.return_value = {
            'classified_findings': [],
            'statistics': {'total_findings': 0}
        }
        mock_classifier_class.return_value = mock_classifier

        report = {"findings": []}
        result = classify_vulnerabilities(report)

        assert 'classified_findings' in result
        assert 'statistics' in result

    @patch('miesc.core.classifier.VulnerabilityClassifier')
    def test_classify_with_ai_enabled(self, mock_classifier_class):
        """Test classification with AI enabled"""
        mock_classifier = Mock()
        mock_classifier.classify.return_value = {'classified_findings': []}
        mock_classifier_class.return_value = mock_classifier

        classify_vulnerabilities({}, enable_ai_triage=True, ai_api_key="test")

        mock_classifier_class.assert_called_with(ai_enabled=True, api_key="test")


# Run tests
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
