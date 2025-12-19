"""
MIESC Policy Agent - Internal Security & Compliance Validation

Validates that MIESC itself follows secure development practices and
compliance requirements that it audits in smart contracts.

"Practice what you preach" - Apply defense-in-depth to the framework itself.

Scientific Foundation:
- Shift-Left Security (NIST SP 800-218)
- ISO/IEC 27001:2022 Annex A controls
- OWASP SAMM (Software Assurance Maturity Model)

Author: Fernando Boiero
Thesis: Master's in Cyberdefense - UNDEF
"""

import os
import json
import logging
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import hashlib

logger = logging.getLogger(__name__)


@dataclass
class PolicyCheck:
    """Individual policy check result"""
    policy_id: str
    policy_name: str
    category: str  # code_quality, security, dependency, testing, documentation
    status: str  # pass, fail, warning, not_applicable
    severity: str  # critical, high, medium, low, info
    description: str
    evidence: Dict[str, Any]
    remediation: str
    standards: List[str]  # ISO/NIST/OWASP references


@dataclass
class ComplianceReport:
    """Complete compliance validation report"""
    timestamp: str
    miesc_version: str
    total_checks: int
    passed: int
    failed: int
    warnings: int
    compliance_score: float  # 0-100
    checks: List[PolicyCheck]
    frameworks: Dict[str, Dict[str, Any]]  # ISO, NIST, OWASP compliance
    recommendations: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PolicyAgent:
    """
    Internal policy validation agent for MIESC

    Validates:
    - Code quality (linting, formatting, type safety)
    - Security (SAST, dependency audit)
    - Testing (coverage, TDD compliance)
    - Documentation (completeness, accuracy)
    - Compliance (ISO/NIST/OWASP alignment)
    """

    def __init__(self, repo_path: str = "."):
        """
        Initialize Policy Agent

        Args:
            repo_path: Path to MIESC repository root
        """
        self.repo_path = Path(repo_path)
        self.src_path = self.repo_path / "src"
        self.tests_path = self.repo_path / "tests"
        self.policies_path = self.repo_path / "policies"

    def run_full_validation(self) -> ComplianceReport:
        """
        Execute complete policy validation suite

        Returns:
            ComplianceReport with all validation results
        """
        logger.info("🔍 Starting MIESC internal policy validation...")

        checks: List[PolicyCheck] = []

        # Category 1: Code Quality
        logger.info("  → Validating code quality...")
        checks.extend(self._check_code_quality())

        # Category 2: Security
        logger.info("  → Validating security practices...")
        checks.extend(self._check_security())

        # Category 3: Dependencies
        logger.info("  → Auditing dependencies...")
        checks.extend(self._check_dependencies())

        # Category 4: Testing
        logger.info("  → Validating test coverage...")
        checks.extend(self._check_testing())

        # Category 5: Documentation
        logger.info("  → Checking documentation...")
        checks.extend(self._check_documentation())

        # Calculate compliance score
        passed = len([c for c in checks if c.status == "pass"])
        failed = len([c for c in checks if c.status == "fail"])
        warnings = len([c for c in checks if c.status == "warning"])
        total = len([c for c in checks if c.status != "not_applicable"])

        compliance_score = (passed / total * 100) if total > 0 else 0

        # Map to frameworks
        frameworks = self._map_to_frameworks(checks)

        # Generate recommendations
        recommendations = self._generate_recommendations(checks)

        report = ComplianceReport(
            timestamp=datetime.utcnow().isoformat() + "Z",
            miesc_version="3.2.0",
            total_checks=total,
            passed=passed,
            failed=failed,
            warnings=warnings,
            compliance_score=round(compliance_score, 2),
            checks=checks,
            frameworks=frameworks,
            recommendations=recommendations
        )

        logger.info(f"✅ Validation complete: {compliance_score:.1f}% compliance")
        logger.info(f"   Passed: {passed}, Failed: {failed}, Warnings: {warnings}")

        return report

    def _check_code_quality(self) -> List[PolicyCheck]:
        """Validate code quality standards"""
        checks = []

        # Check 1: Ruff linting
        check = self._run_ruff_check()
        checks.append(check)

        # Check 2: Black formatting
        check = self._run_black_check()
        checks.append(check)

        # Check 3: MyPy type checking
        check = self._run_mypy_check()
        checks.append(check)

        # Check 4: Flake8 compliance
        check = self._run_flake8_check()
        checks.append(check)

        return checks

    def _run_ruff_check(self) -> PolicyCheck:
        """Run Ruff linter"""
        try:
            result = subprocess.run(
                ["ruff", "check", str(self.src_path)],
                capture_output=True,
                text=True,
                timeout=60
            )

            issues = result.stdout.count("error") + result.stdout.count("warning")

            return PolicyCheck(
                policy_id="CQ-001",
                policy_name="Ruff Linting",
                category="code_quality",
                status="pass" if result.returncode == 0 else "fail",
                severity="medium",
                description="Fast Python linter (Rust-based, replaces flake8+pylint)",
                evidence={"issues_found": issues, "output": result.stdout[:500]},
                remediation="Run 'ruff check --fix .' to auto-fix issues",
                standards=["NIST SSDF PW.8", "ISO 27001 A.14.2.5"]
            )
        except FileNotFoundError:
            return PolicyCheck(
                policy_id="CQ-001",
                policy_name="Ruff Linting",
                category="code_quality",
                status="not_applicable",
                severity="info",
                description="Ruff not installed",
                evidence={"error": "Ruff not found in PATH"},
                remediation="pip install ruff",
                standards=[]
            )

    def _run_black_check(self) -> PolicyCheck:
        """Check Black formatting"""
        try:
            result = subprocess.run(
                ["black", "--check", str(self.src_path)],
                capture_output=True,
                text=True,
                timeout=60
            )

            files_reformatted = result.stdout.count("would be reformatted")

            return PolicyCheck(
                policy_id="CQ-002",
                policy_name="Black Code Formatting",
                category="code_quality",
                status="pass" if result.returncode == 0 else "warning",
                severity="low",
                description="Enforce consistent code formatting",
                evidence={"files_need_formatting": files_reformatted},
                remediation="Run 'black src/' to format code",
                standards=["NIST SSDF PW.8"]
            )
        except FileNotFoundError:
            return PolicyCheck(
                policy_id="CQ-002",
                policy_name="Black Code Formatting",
                category="code_quality",
                status="not_applicable",
                severity="info",
                description="Black not installed",
                evidence={},
                remediation="pip install black",
                standards=[]
            )

    def _run_mypy_check(self) -> PolicyCheck:
        """Check type hints with MyPy"""
        try:
            result = subprocess.run(
                ["mypy", str(self.src_path), "--ignore-missing-imports"],
                capture_output=True,
                text=True,
                timeout=120
            )

            errors = result.stdout.count("error")

            return PolicyCheck(
                policy_id="CQ-003",
                policy_name="MyPy Type Checking",
                category="code_quality",
                status="pass" if errors == 0 else "warning",
                severity="medium",
                description="Static type checking for Python",
                evidence={"type_errors": errors},
                remediation="Add type hints and fix type errors",
                standards=["NIST SSDF PW.8", "ISO 27001 A.14.2.5"]
            )
        except FileNotFoundError:
            return PolicyCheck(
                policy_id="CQ-003",
                policy_name="MyPy Type Checking",
                category="code_quality",
                status="not_applicable",
                severity="info",
                description="MyPy not installed",
                evidence={},
                remediation="pip install mypy",
                standards=[]
            )

    def _run_flake8_check(self) -> PolicyCheck:
        """Run Flake8 linting"""
        try:
            result = subprocess.run(
                ["flake8", str(self.src_path), "--max-line-length=100"],
                capture_output=True,
                text=True,
                timeout=60
            )

            violations = len(result.stdout.splitlines())

            return PolicyCheck(
                policy_id="CQ-004",
                policy_name="Flake8 Style Guide",
                category="code_quality",
                status="pass" if result.returncode == 0 else "fail",
                severity="medium",
                description="PEP 8 style guide enforcement",
                evidence={"violations": violations},
                remediation="Fix style violations reported by flake8",
                standards=["NIST SSDF PW.8"]
            )
        except FileNotFoundError:
            return PolicyCheck(
                policy_id="CQ-004",
                policy_name="Flake8 Style Guide",
                category="code_quality",
                status="not_applicable",
                severity="info",
                description="Flake8 not installed",
                evidence={},
                remediation="pip install flake8",
                standards=[]
            )

    def _check_security(self) -> List[PolicyCheck]:
        """Validate security practices (SAST)"""
        checks = []

        # Check 1: Bandit SAST
        check = self._run_bandit_check()
        checks.append(check)

        # Check 2: Semgrep SAST
        check = self._run_semgrep_check()
        checks.append(check)

        # Check 3: Secret scanning
        check = self._check_secrets()
        checks.append(check)

        return checks

    def _run_bandit_check(self) -> PolicyCheck:
        """Run Bandit security scanner"""
        try:
            result = subprocess.run(
                ["bandit", "-r", str(self.src_path), "-f", "json"],
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.stdout:
                data = json.loads(result.stdout)
                issues = data.get("results", [])
                high_severity = len([i for i in issues if i.get("issue_severity") == "HIGH"])
                medium_severity = len([i for i in issues if i.get("issue_severity") == "MEDIUM"])

                status = "fail" if high_severity > 0 else ("warning" if medium_severity > 0 else "pass")

                return PolicyCheck(
                    policy_id="SEC-001",
                    policy_name="Bandit SAST",
                    category="security",
                    status=status,
                    severity="high" if high_severity > 0 else "medium",
                    description="Static application security testing for Python",
                    evidence={
                        "total_issues": len(issues),
                        "high_severity": high_severity,
                        "medium_severity": medium_severity
                    },
                    remediation="Review and fix security issues reported by Bandit",
                    standards=["NIST SSDF PW.8", "ISO 27001 A.8.8", "OWASP SAMM V-ST-1-A"]
                )
        except Exception as e:
            logger.warning(f"Bandit check failed: {e}")

        return PolicyCheck(
            policy_id="SEC-001",
            policy_name="Bandit SAST",
            category="security",
            status="not_applicable",
            severity="info",
            description="Bandit not available",
            evidence={},
            remediation="pip install bandit",
            standards=[]
        )

    def _run_semgrep_check(self) -> PolicyCheck:
        """Run Semgrep security scanner"""
        try:
            result = subprocess.run(
                ["semgrep", "--config=auto", "--json", str(self.src_path)],
                capture_output=True,
                text=True,
                timeout=180
            )

            if result.stdout:
                data = json.loads(result.stdout)
                findings = data.get("results", [])
                errors = len([f for f in findings if f.get("extra", {}).get("severity") == "ERROR"])

                return PolicyCheck(
                    policy_id="SEC-002",
                    policy_name="Semgrep SAST",
                    category="security",
                    status="fail" if errors > 0 else "pass",
                    severity="high" if errors > 0 else "low",
                    description="Advanced static analysis with custom rules",
                    evidence={"findings": len(findings), "errors": errors},
                    remediation="Fix security patterns detected by Semgrep",
                    standards=["NIST SSDF PW.8", "OWASP SAMM V-ST-1-A"]
                )
        except Exception as e:
            logger.warning(f"Semgrep check failed: {e}")

        return PolicyCheck(
            policy_id="SEC-002",
            policy_name="Semgrep SAST",
            category="security",
            status="not_applicable",
            severity="info",
            description="Semgrep not available",
            evidence={},
            remediation="pip install semgrep",
            standards=[]
        )

    def _check_secrets(self) -> PolicyCheck:
        """Check for hardcoded secrets"""
        secrets_found = []
        patterns = [
            (r"api[_-]?key", "API Key"),
            (r"secret[_-]?key", "Secret Key"),
            (r"password\s*=", "Password"),
            (r"token\s*=", "Token"),
        ]

        import re
        for py_file in self.src_path.rglob("*.py"):
            try:
                content = py_file.read_text()
                for pattern, name in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        secrets_found.append(f"{name} in {py_file.name}")
            except Exception:
                pass

        return PolicyCheck(
            policy_id="SEC-003",
            policy_name="Secret Scanning",
            category="security",
            status="fail" if secrets_found else "pass",
            severity="critical" if secrets_found else "low",
            description="Detect hardcoded secrets in source code",
            evidence={"secrets_found": secrets_found},
            remediation="Move secrets to environment variables or secure vault",
            standards=["ISO 27001 A.8.8", "NIST SSDF PW.8"]
        )

    def _check_dependencies(self) -> List[PolicyCheck]:
        """Audit dependencies for vulnerabilities"""
        checks = []

        # Check 1: pip-audit
        check = self._run_pip_audit()
        checks.append(check)

        # Check 2: Dependency pinning
        check = self._check_dependency_pinning()
        checks.append(check)

        return checks

    def _run_pip_audit(self) -> PolicyCheck:
        """Run pip-audit for known vulnerabilities"""
        try:
            result = subprocess.run(
                ["pip-audit", "--format=json"],
                capture_output=True,
                text=True,
                timeout=120
            )

            if result.stdout:
                data = json.loads(result.stdout)
                vulnerabilities = data.get("dependencies", [])
                critical = len([v for v in vulnerabilities if v.get("vulns", [{}])[0].get("severity") == "CRITICAL"])

                return PolicyCheck(
                    policy_id="DEP-001",
                    policy_name="Dependency Vulnerability Audit",
                    category="dependency",
                    status="fail" if critical > 0 else ("warning" if len(vulnerabilities) > 0 else "pass"),
                    severity="critical" if critical > 0 else "medium",
                    description="Scan dependencies for known CVEs",
                    evidence={
                        "vulnerable_packages": len(vulnerabilities),
                        "critical_vulns": critical
                    },
                    remediation="Update vulnerable dependencies: pip install --upgrade <package>",
                    standards=["ISO 27001 A.8.8", "NIST SSDF PW.4"]
                )
        except Exception as e:
            logger.warning(f"pip-audit failed: {e}")

        return PolicyCheck(
            policy_id="DEP-001",
            policy_name="Dependency Vulnerability Audit",
            category="dependency",
            status="not_applicable",
            severity="info",
            description="pip-audit not available",
            evidence={},
            remediation="pip install pip-audit",
            standards=[]
        )

    def _check_dependency_pinning(self) -> PolicyCheck:
        """Check if dependencies are pinned to specific versions"""
        req_file = self.repo_path / "requirements.txt"

        if not req_file.exists():
            return PolicyCheck(
                policy_id="DEP-002",
                policy_name="Dependency Version Pinning",
                category="dependency",
                status="fail",
                severity="high",
                description="Requirements file not found",
                evidence={},
                remediation="Create requirements.txt with pinned versions",
                standards=["NIST SSDF PW.4"]
            )

        content = req_file.read_text()
        lines = [l.strip() for l in content.splitlines() if l.strip() and not l.startswith("#")]
        unpinned = [l for l in lines if "==" not in l and not l.startswith("-")]

        return PolicyCheck(
            policy_id="DEP-002",
            policy_name="Dependency Version Pinning",
            category="dependency",
            status="warning" if unpinned else "pass",
            severity="medium",
            description="Ensure all dependencies have pinned versions",
            evidence={"unpinned_dependencies": len(unpinned), "examples": unpinned[:5]},
            remediation="Pin all dependencies to specific versions (e.g., package==1.2.3)",
            standards=["NIST SSDF PW.4"]
        )

    def _check_testing(self) -> List[PolicyCheck]:
        """Validate testing practices"""
        checks = []

        # Check 1: Test coverage
        check = self._check_test_coverage()
        checks.append(check)

        # Check 2: Test existence
        check = self._check_tests_exist()
        checks.append(check)

        return checks

    def _check_test_coverage(self) -> PolicyCheck:
        """Check test coverage percentage"""
        try:
            result = subprocess.run(
                ["pytest", "--cov=src", "--cov-report=json", "--cov-report=term"],
                capture_output=True,
                text=True,
                timeout=300,
                cwd=str(self.repo_path)
            )

            cov_file = self.repo_path / "coverage.json"
            if cov_file.exists():
                data = json.loads(cov_file.read_text())
                coverage = data.get("totals", {}).get("percent_covered", 0)

                status = "pass" if coverage >= 85 else ("warning" if coverage >= 70 else "fail")

                return PolicyCheck(
                    policy_id="TEST-001",
                    policy_name="Test Coverage",
                    category="testing",
                    status=status,
                    severity="high" if coverage < 70 else "medium",
                    description="Minimum 85% test coverage required",
                    evidence={"coverage_percent": round(coverage, 2), "target": 85},
                    remediation=f"Increase test coverage from {coverage:.1f}% to 85%",
                    standards=["NIST SSDF PW.8", "ISO 27001 A.14.2.9"]
                )
        except Exception as e:
            logger.warning(f"Coverage check failed: {e}")

        return PolicyCheck(
            policy_id="TEST-001",
            policy_name="Test Coverage",
            category="testing",
            status="fail",
            severity="high",
            description="Unable to calculate test coverage",
            evidence={},
            remediation="Install pytest-cov: pip install pytest pytest-cov",
            standards=["NIST SSDF PW.8"]
        )

    def _check_tests_exist(self) -> PolicyCheck:
        """Check if tests directory exists and contains tests"""
        if not self.tests_path.exists():
            return PolicyCheck(
                policy_id="TEST-002",
                policy_name="Test Suite Existence",
                category="testing",
                status="fail",
                severity="critical",
                description="No tests directory found",
                evidence={},
                remediation="Create tests/ directory and add unit tests",
                standards=["NIST SSDF PW.8", "ISO 27001 A.14.2.9"]
            )

        test_files = list(self.tests_path.rglob("test_*.py"))

        return PolicyCheck(
            policy_id="TEST-002",
            policy_name="Test Suite Existence",
            category="testing",
            status="pass" if len(test_files) > 0 else "fail",
            severity="high" if len(test_files) == 0 else "info",
            description="Validate existence of test files",
            evidence={"test_files": len(test_files)},
            remediation="Add test files following naming convention test_*.py",
            standards=["NIST SSDF PW.8"]
        )

    def _check_documentation(self) -> List[PolicyCheck]:
        """Validate documentation completeness"""
        checks = []

        # Check 1: Required docs exist
        required_docs = [
            "README.md",
            "CHANGELOG.md",
            "CITATION.cff",
            "docs/REPRODUCIBILITY.md",
            "policies/SECURITY_POLICY.md"
        ]

        missing = []
        for doc in required_docs:
            if not (self.repo_path / doc).exists():
                missing.append(doc)

        checks.append(PolicyCheck(
            policy_id="DOC-001",
            policy_name="Required Documentation",
            category="documentation",
            status="fail" if missing else "pass",
            severity="medium" if missing else "low",
            description="Essential documentation files must exist",
            evidence={"missing_files": missing},
            remediation=f"Create missing documentation: {', '.join(missing)}",
            standards=["ISO 27001 A.5.1", "NIST SSDF PO.3"]
        ))

        return checks

    def _map_to_frameworks(self, checks: List[PolicyCheck]) -> Dict[str, Dict[str, Any]]:
        """Map checks to compliance frameworks"""
        frameworks = {
            "ISO_27001": {"controls_tested": 0, "controls_passed": 0, "controls": []},
            "NIST_SSDF": {"practices_tested": 0, "practices_passed": 0, "practices": []},
            "OWASP_SAMM": {"activities_tested": 0, "activities_passed": 0, "activities": []}
        }

        for check in checks:
            for standard in check.standards:
                if "ISO 27001" in standard:
                    frameworks["ISO_27001"]["controls_tested"] += 1
                    if check.status == "pass":
                        frameworks["ISO_27001"]["controls_passed"] += 1
                    frameworks["ISO_27001"]["controls"].append(standard)
                elif "NIST SSDF" in standard:
                    frameworks["NIST_SSDF"]["practices_tested"] += 1
                    if check.status == "pass":
                        frameworks["NIST_SSDF"]["practices_passed"] += 1
                    frameworks["NIST_SSDF"]["practices"].append(standard)
                elif "OWASP SAMM" in standard:
                    frameworks["OWASP_SAMM"]["activities_tested"] += 1
                    if check.status == "pass":
                        frameworks["OWASP_SAMM"]["activities_passed"] += 1
                    frameworks["OWASP_SAMM"]["activities"].append(standard)

        return frameworks

    def _generate_recommendations(self, checks: List[PolicyCheck]) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []

        failed = [c for c in checks if c.status == "fail"]
        warnings = [c for c in checks if c.status == "warning"]

        if failed:
            recommendations.append(f"🔴 CRITICAL: {len(failed)} policy checks failed - address immediately")

        # Specific recommendations
        if any(c.policy_id == "SEC-003" and c.status == "fail" for c in checks):
            recommendations.append("⚠️ Hardcoded secrets detected - migrate to environment variables")

        if any(c.policy_id == "TEST-001" and c.status != "pass" for c in checks):
            recommendations.append("📊 Increase test coverage to meet 85% minimum threshold")

        if any(c.policy_id == "DEP-001" and c.status == "fail" for c in checks):
            recommendations.append("🔒 Critical dependency vulnerabilities found - update packages")

        if not failed and not warnings:
            recommendations.append("✅ All policy checks passed - maintain current security posture")

        return recommendations

    def generate_report(self, report: ComplianceReport, output_path: str) -> None:
        """Generate compliance report in JSON format"""
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w') as f:
            json.dump(report.to_dict(), f, indent=2)

        logger.info(f"✅ Compliance report generated: {output_path}")

    def generate_markdown_report(self, report: ComplianceReport, output_path: str) -> None:
        """Generate human-readable Markdown report"""
        md = f"""# MIESC Internal Compliance Report

**Generated:** {report.timestamp}
**MIESC Version:** {report.miesc_version}
**Compliance Score:** {report.compliance_score}%

## Summary

- **Total Checks:** {report.total_checks}
- **✅ Passed:** {report.passed}
- **❌ Failed:** {report.failed}
- **⚠️ Warnings:** {report.warnings}

## Framework Compliance

### ISO/IEC 27001:2022
- Controls Tested: {report.frameworks['ISO_27001']['controls_tested']}
- Controls Passed: {report.frameworks['ISO_27001']['controls_passed']}

### NIST SSDF (SP 800-218)
- Practices Tested: {report.frameworks['NIST_SSDF']['practices_tested']}
- Practices Passed: {report.frameworks['NIST_SSDF']['practices_passed']}

### OWASP SAMM
- Activities Tested: {report.frameworks['OWASP_SAMM']['activities_tested']}
- Activities Passed: {report.frameworks['OWASP_SAMM']['activities_passed']}

## Detailed Results

"""

        # Group by category
        categories = {}
        for check in report.checks:
            if check.category not in categories:
                categories[check.category] = []
            categories[check.category].append(check)

        for category, checks in categories.items():
            md += f"\n### {category.replace('_', ' ').title()}\n\n"
            for check in checks:
                icon = {"pass": "✅", "fail": "❌", "warning": "⚠️", "not_applicable": "ℹ️"}[check.status]
                md += f"**{icon} {check.policy_name}** (`{check.policy_id}`)\n"
                md += f"- Status: {check.status}\n"
                md += f"- Severity: {check.severity}\n"
                md += f"- {check.description}\n"
                if check.evidence:
                    md += f"- Evidence: {json.dumps(check.evidence)}\n"
                if check.remediation and check.status != "pass":
                    md += f"- **Remediation:** {check.remediation}\n"
                md += "\n"

        md += "\n## Recommendations\n\n"
        for rec in report.recommendations:
            md += f"- {rec}\n"

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_text(md)
        logger.info(f"✅ Markdown report generated: {output_path}")


# CLI Interface
if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    parser = argparse.ArgumentParser(description="MIESC Policy Agent - Internal Compliance Validation")
    parser.add_argument("--repo-path", default=".", help="Path to MIESC repository")
    parser.add_argument("--output-json", default="analysis/policy/compliance_report.json",
                        help="Output path for JSON report")
    parser.add_argument("--output-md", default="analysis/policy/compliance_report.md",
                        help="Output path for Markdown report")

    args = parser.parse_args()

    agent = PolicyAgent(args.repo_path)
    report = agent.run_full_validation()

    # Generate reports
    agent.generate_report(report, args.output_json)
    agent.generate_markdown_report(report, args.output_md)

    print(f"\n{'='*60}")
    print(f"🔒 MIESC Internal Compliance Validation")
    print(f"{'='*60}")
    print(f"Compliance Score: {report.compliance_score}%")
    print(f"Passed: {report.passed} | Failed: {report.failed} | Warnings: {report.warnings}")
    print(f"\nReports generated:")
    print(f"  - JSON: {args.output_json}")
    print(f"  - Markdown: {args.output_md}")
    print(f"{'='*60}\n")

    # Exit with error if critical failures
    if report.failed > 0:
        sys.exit(1)
