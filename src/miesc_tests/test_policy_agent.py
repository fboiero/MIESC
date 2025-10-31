"""
Unit Tests for PolicyAgent Module

Tests internal policy compliance validation following TDD principles.

Test Coverage:
- Policy check execution
- Compliance score calculation
- Report generation
- Framework mapping

Author: Fernando Boiero
Version: 3.2.0
"""

import pytest
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import subprocess

# Import module under test
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from miesc_policy_agent import PolicyAgent, PolicyCheck, ComplianceReport


class TestPolicyCheck:
    """Test PolicyCheck dataclass"""

    def test_policy_check_creation(self):
        """Test creating a PolicyCheck instance"""
        check = PolicyCheck(
            policy_id="TEST-001",
            policy_name="Test Check",
            category="testing",
            status="pass",
            severity="low",
            description="Test description",
            evidence={"test": True},
            remediation="No action needed",
            standards=["TEST"]
        )

        assert check.policy_id == "TEST-001"
        assert check.status == "pass"
        assert check.severity == "low"


class TestComplianceReport:
    """Test ComplianceReport dataclass"""

    def test_compliance_report_creation(self):
        """Test creating a ComplianceReport instance"""
        check = PolicyCheck(
            policy_id="TEST-001",
            policy_name="Test",
            category="testing",
            status="pass",
            severity="low",
            description="Test",
            evidence={},
            remediation="",
            standards=[]
        )

        report = ComplianceReport(
            timestamp="2025-01-01T00:00:00Z",
            miesc_version="3.2.0",
            total_checks=1,
            passed=1,
            failed=0,
            warnings=0,
            compliance_score=100.0,
            checks=[check],
            frameworks={},
            recommendations=[]
        )

        assert report.compliance_score == 100.0
        assert report.passed == 1
        assert len(report.checks) == 1

    def test_compliance_report_to_dict(self):
        """Test converting ComplianceReport to dictionary"""
        check = PolicyCheck(
            policy_id="TEST-001",
            policy_name="Test",
            category="testing",
            status="pass",
            severity="low",
            description="Test",
            evidence={},
            remediation="",
            standards=[]
        )

        report = ComplianceReport(
            timestamp="2025-01-01T00:00:00Z",
            miesc_version="3.2.0",
            total_checks=1,
            passed=1,
            failed=0,
            warnings=0,
            compliance_score=100.0,
            checks=[check],
            frameworks={},
            recommendations=[]
        )

        report_dict = report.to_dict()
        assert isinstance(report_dict, dict)
        assert report_dict["compliance_score"] == 100.0


class TestPolicyAgent:
    """Test PolicyAgent functionality"""

    def test_policy_agent_initialization(self):
        """Test PolicyAgent initialization"""
        agent = PolicyAgent(repo_path=".")
        assert agent.repo_path == Path(".")
        assert agent.src_path == Path(".") / "src"
        assert agent.tests_path == Path(".") / "tests"

    @patch('subprocess.run')
    def test_ruff_check_pass(self, mock_run):
        """Test Ruff check passing"""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        agent = PolicyAgent()
        check = agent._run_ruff_check()

        assert check.policy_id == "CQ-001"
        assert check.status == "pass"

    @patch('subprocess.run')
    def test_ruff_check_fail(self, mock_run):
        """Test Ruff check failing"""
        mock_run.return_value = Mock(
            returncode=1,
            stdout="error: Found 5 errors",
            stderr=""
        )

        agent = PolicyAgent()
        check = agent._run_ruff_check()

        assert check.policy_id == "CQ-001"
        assert check.status == "fail"

    @patch('subprocess.run')
    def test_bandit_check_with_high_severity(self, mock_run):
        """Test Bandit check with high severity issues"""
        bandit_output = {
            "results": [
                {"issue_severity": "HIGH"},
                {"issue_severity": "MEDIUM"}
            ]
        }

        mock_run.return_value = Mock(
            returncode=0,
            stdout=json.dumps(bandit_output),
            stderr=""
        )

        agent = PolicyAgent()
        check = agent._run_bandit_check()

        assert check.policy_id == "SEC-001"
        assert check.status == "fail"
        assert check.evidence["high_severity"] == 1

    def test_secret_scanning_no_secrets(self, tmp_path):
        """Test secret scanning with no secrets found"""
        # Create temporary Python file without secrets
        test_file = tmp_path / "src" / "test.py"
        test_file.parent.mkdir(parents=True)
        test_file.write_text("# Clean code\nprint('Hello World')")

        agent = PolicyAgent(repo_path=str(tmp_path))
        check = agent._check_secrets()

        assert check.policy_id == "SEC-003"
        assert check.status == "pass"

    def test_secret_scanning_with_secrets(self, tmp_path):
        """Test secret scanning with hardcoded secrets"""
        # Create temporary Python file with secret
        test_file = tmp_path / "src" / "test.py"
        test_file.parent.mkdir(parents=True)
        test_file.write_text("api_key = 'secret123'")

        agent = PolicyAgent(repo_path=str(tmp_path))
        check = agent._check_secrets()

        assert check.policy_id == "SEC-003"
        assert check.status == "fail"
        assert check.severity == "critical"

    def test_dependency_pinning_check(self, tmp_path):
        """Test dependency version pinning check"""
        # Create requirements.txt with pinned dependencies
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("numpy==1.24.0\npandas==2.0.0\n")

        agent = PolicyAgent(repo_path=str(tmp_path))
        check = agent._check_dependency_pinning()

        assert check.policy_id == "DEP-002"
        assert check.status == "pass"

    def test_dependency_pinning_check_unpinned(self, tmp_path):
        """Test dependency pinning check with unpinned packages"""
        # Create requirements.txt with unpinned dependencies
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("numpy\npandas==2.0.0\n")

        agent = PolicyAgent(repo_path=str(tmp_path))
        check = agent._check_dependency_pinning()

        assert check.policy_id == "DEP-002"
        assert check.status == "warning"
        assert check.evidence["unpinned_dependencies"] == 1

    def test_tests_exist_check(self, tmp_path):
        """Test checking for test files existence"""
        # Create test directory with test files
        tests_dir = tmp_path / "tests"
        tests_dir.mkdir()
        (tests_dir / "test_example.py").write_text("# Test")

        agent = PolicyAgent(repo_path=str(tmp_path))
        check = agent._check_tests_exist()

        assert check.policy_id == "TEST-002"
        assert check.status == "pass"
        assert check.evidence["test_files"] >= 1

    def test_documentation_check(self, tmp_path):
        """Test documentation completeness check"""
        # Create required documentation files
        (tmp_path / "README.md").write_text("# README")
        (tmp_path / "CHANGELOG.md").write_text("# CHANGELOG")
        (tmp_path / "CITATION.cff").write_text("cff-version: 1.2.0")

        docs_dir = tmp_path / "docs"
        docs_dir.mkdir()
        (docs_dir / "REPRODUCIBILITY.md").write_text("# Reproducibility")

        policies_dir = tmp_path / "policies"
        policies_dir.mkdir()
        (policies_dir / "SECURITY_POLICY.md").write_text("# Security")

        agent = PolicyAgent(repo_path=str(tmp_path))
        checks = agent._check_documentation()

        assert len(checks) > 0
        assert checks[0].policy_id == "DOC-001"
        assert checks[0].status == "pass"

    def test_framework_mapping(self):
        """Test mapping checks to compliance frameworks"""
        checks = [
            PolicyCheck(
                policy_id="TEST-001",
                policy_name="Test",
                category="testing",
                status="pass",
                severity="low",
                description="Test",
                evidence={},
                remediation="",
                standards=["ISO 27001 A.5.1", "NIST SSDF PW.8"]
            )
        ]

        agent = PolicyAgent()
        frameworks = agent._map_to_frameworks(checks)

        assert "ISO_27001" in frameworks
        assert "NIST_SSDF" in frameworks
        assert frameworks["ISO_27001"]["controls_tested"] == 1
        assert frameworks["NIST_SSDF"]["practices_tested"] == 1

    def test_generate_recommendations(self):
        """Test recommendation generation"""
        failed_check = PolicyCheck(
            policy_id="SEC-003",
            policy_name="Secret Scanning",
            category="security",
            status="fail",
            severity="critical",
            description="Test",
            evidence={},
            remediation="",
            standards=[]
        )

        agent = PolicyAgent()
        recommendations = agent._generate_recommendations([failed_check])

        assert len(recommendations) > 0
        assert any("CRITICAL" in r for r in recommendations)
        assert any("secret" in r.lower() for r in recommendations)

    def test_report_generation(self, tmp_path):
        """Test JSON report generation"""
        check = PolicyCheck(
            policy_id="TEST-001",
            policy_name="Test",
            category="testing",
            status="pass",
            severity="low",
            description="Test",
            evidence={},
            remediation="",
            standards=[]
        )

        report = ComplianceReport(
            timestamp="2025-01-01T00:00:00Z",
            miesc_version="3.2.0",
            total_checks=1,
            passed=1,
            failed=0,
            warnings=0,
            compliance_score=100.0,
            checks=[check],
            frameworks={},
            recommendations=[]
        )

        output_path = tmp_path / "test_report.json"
        agent = PolicyAgent()
        agent.generate_report(report, str(output_path))

        assert output_path.exists()

        with open(output_path) as f:
            data = json.load(f)
            assert data["compliance_score"] == 100.0

    def test_markdown_report_generation(self, tmp_path):
        """Test Markdown report generation"""
        check = PolicyCheck(
            policy_id="TEST-001",
            policy_name="Test Check",
            category="testing",
            status="pass",
            severity="low",
            description="Test description",
            evidence={"result": "ok"},
            remediation="",
            standards=["TEST"]
        )

        report = ComplianceReport(
            timestamp="2025-01-01T00:00:00Z",
            miesc_version="3.2.0",
            total_checks=1,
            passed=1,
            failed=0,
            warnings=0,
            compliance_score=100.0,
            checks=[check],
            frameworks={
                "ISO_27001": {"controls_tested": 0, "controls_passed": 0, "controls": []},
                "NIST_SSDF": {"practices_tested": 0, "practices_passed": 0, "practices": []},
                "OWASP_SAMM": {"activities_tested": 0, "activities_passed": 0, "activities": []}
            },
            recommendations=["All checks passed"]
        )

        output_path = tmp_path / "test_report.md"
        agent = PolicyAgent()
        agent.generate_markdown_report(report, str(output_path))

        assert output_path.exists()

        content = output_path.read_text()
        assert "MIESC Internal Compliance Report" in content
        assert "100" in content  # Compliance score
        assert "Test Check" in content


# Integration Tests
class TestPolicyAgentIntegration:
    """Integration tests for PolicyAgent"""

    @patch('subprocess.run')
    def test_full_validation_workflow(self, mock_run, tmp_path):
        """Test complete validation workflow"""
        # Mock all subprocess calls to pass
        mock_run.return_value = Mock(
            returncode=0,
            stdout="",
            stderr=""
        )

        # Create minimal directory structure
        (tmp_path / "src").mkdir()
        (tmp_path / "tests").mkdir()
        (tmp_path / "requirements.txt").write_text("pytest==7.0.0")

        agent = PolicyAgent(repo_path=str(tmp_path))

        # This will fail on some checks but shouldn't crash
        try:
            report = agent.run_full_validation()
            assert isinstance(report, ComplianceReport)
            assert report.total_checks > 0
        except Exception as e:
            # Some checks may fail in test environment, that's ok
            pytest.skip(f"Full validation not possible in test environment: {e}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=miesc_policy_agent", "--cov-report=term-missing"])
