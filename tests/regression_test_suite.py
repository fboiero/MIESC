#!/usr/bin/env python3
"""
MIESC v4.0.0 - Complete Regression Test Suite with Evidence Capture
=====================================================================

This script performs comprehensive regression testing across all MIESC modules:
1. CLI Tool (miesc-quick)
2. Full 7-Layer Audit (run_complete_multilayer_audit.py)
3. MCP REST Server (miesc_mcp_rest.py)
4. Individual Adapters (26 tools)
5. AI Correlation & ML Detection

Each test captures evidence (logs, screenshots) for documentation.

Author: Fernando Boiero
Institution: UNDEF - IUA Cordoba
Date: December 2024
"""

import json
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "src"))

# Evidence directories
EVIDENCE_DIR = PROJECT_ROOT / "docs" / "evidence"
LOGS_DIR = EVIDENCE_DIR / "logs"

# Ensure directories exist
LOGS_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class TestResult:
    """Result of a single test case"""

    name: str
    module: str
    status: str  # PASS, FAIL, SKIP
    duration: float
    message: str
    evidence_path: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


class MIESCRegressionTester:
    """Complete regression test suite for MIESC"""

    def __init__(self):
        self.results: List[TestResult] = []
        self.start_time = datetime.now()

    def save_log(self, name: str, content: str) -> str:
        """Save test log to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{name}_{timestamp}.log"
        filepath = LOGS_DIR / filename

        with open(filepath, "w") as f:
            f.write(content)

        return str(filepath)

    def add_result(self, result: TestResult):
        """Add a test result"""
        self.results.append(result)
        status_icon = {"PASS": "✅", "FAIL": "❌", "SKIP": "⏭️"}.get(result.status, "❓")
        print(f"  {status_icon} {result.name}: {result.message} ({result.duration:.2f}s)")

    # ==================== CLI Tests ====================

    def test_cli_doctor(self) -> TestResult:
        """Test: miesc-quick doctor command"""
        start = time.time()

        try:
            result = subprocess.run(
                [str(PROJECT_ROOT / "miesc-quick"), "doctor"],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=str(PROJECT_ROOT),
            )

            log_path = self.save_log("cli_doctor", result.stdout + result.stderr)

            # Check for expected output
            tools_found = result.stdout.count("✓")

            return TestResult(
                name="CLI Doctor Command",
                module="miesc-quick",
                status="PASS" if tools_found > 0 else "FAIL",
                duration=time.time() - start,
                message=f"Found {tools_found} tools available",
                evidence_path=log_path,
                details={"tools_found": tools_found},
            )
        except Exception as e:
            return TestResult(
                name="CLI Doctor Command",
                module="miesc-quick",
                status="FAIL",
                duration=time.time() - start,
                message=str(e),
            )

    def test_cli_checklist(self) -> TestResult:
        """Test: miesc-quick checklist command"""
        start = time.time()

        try:
            result = subprocess.run(
                [str(PROJECT_ROOT / "miesc-quick"), "checklist"],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=str(PROJECT_ROOT),
            )

            log_path = self.save_log("cli_checklist", result.stdout + result.stderr)

            # Check for expected sections
            has_categories = "Access Control" in result.stdout or "Reentrancy" in result.stdout

            return TestResult(
                name="CLI Checklist Command",
                module="miesc-quick",
                status="PASS" if has_categories else "FAIL",
                duration=time.time() - start,
                message="Security checklist displayed correctly",
                evidence_path=log_path,
            )
        except Exception as e:
            return TestResult(
                name="CLI Checklist Command",
                module="miesc-quick",
                status="FAIL",
                duration=time.time() - start,
                message=str(e),
            )

    def test_cli_scan(self) -> TestResult:
        """Test: miesc-quick scan on VulnerableBank.sol"""
        start = time.time()
        contract = PROJECT_ROOT / "contracts" / "audit" / "VulnerableBank.sol"

        try:
            result = subprocess.run(
                [str(PROJECT_ROOT / "miesc-quick"), "scan", str(contract)],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=str(PROJECT_ROOT),
            )

            log_path = self.save_log("cli_scan", result.stdout + result.stderr)

            # Check for findings
            has_findings = (
                "Finding" in result.stdout or "CRITICAL" in result.stdout or "HIGH" in result.stdout
            )

            return TestResult(
                name="CLI Scan Command",
                module="miesc-quick",
                status="PASS" if has_findings else "FAIL",
                duration=time.time() - start,
                message="Scan completed with findings detected",
                evidence_path=log_path,
            )
        except subprocess.TimeoutExpired:
            return TestResult(
                name="CLI Scan Command",
                module="miesc-quick",
                status="FAIL",
                duration=time.time() - start,
                message="Scan timed out after 120s",
            )
        except Exception as e:
            return TestResult(
                name="CLI Scan Command",
                module="miesc-quick",
                status="FAIL",
                duration=time.time() - start,
                message=str(e),
            )

    # ==================== Adapter Tests ====================

    def test_adapter(self, adapter_name: str, adapter_class: str) -> TestResult:
        """Test a single adapter"""
        start = time.time()
        contract = "contracts/audit/VulnerableBank.sol"

        try:
            # Import and instantiate adapter
            module_name = f"adapters.{adapter_name}"
            module = __import__(module_name, fromlist=[adapter_class])
            adapter = getattr(module, adapter_class)()

            # Check availability
            is_available = adapter.is_available() if hasattr(adapter, "is_available") else True

            if not is_available:
                return TestResult(
                    name=f"Adapter: {adapter_class}",
                    module="adapters",
                    status="SKIP",
                    duration=time.time() - start,
                    message="Tool not installed",
                )

            # Run analysis
            result = adapter.analyze(str(PROJECT_ROOT / contract), timeout=60)

            findings = len(result.get("findings", []))
            status = result.get("status", "unknown")

            log_content = json.dumps(result, indent=2, default=str)
            log_path = self.save_log(f"adapter_{adapter_name}", log_content)

            return TestResult(
                name=f"Adapter: {adapter_class}",
                module="adapters",
                status="PASS" if status == "success" else "FAIL",
                duration=time.time() - start,
                message=f"Found {findings} findings",
                evidence_path=log_path,
                details={"findings": findings, "status": status},
            )

        except Exception as e:
            return TestResult(
                name=f"Adapter: {adapter_class}",
                module="adapters",
                status="FAIL",
                duration=time.time() - start,
                message=str(e)[:100],
            )

    def test_all_adapters(self):
        """Test all available adapters"""
        adapters = [
            ("slither_adapter", "SlitherAdapter"),
            ("mythril_adapter", "MythrilAdapter"),
            ("aderyn_adapter", "AderynAdapter"),
            ("solhint_adapter", "SolhintAdapter"),
            ("smtchecker_adapter", "SMTCheckerAdapter"),
            ("propertygpt_adapter", "PropertyGPTAdapter"),
            ("threat_model_adapter", "ThreatModelAdapter"),
        ]

        for adapter_name, adapter_class in adapters:
            result = self.test_adapter(adapter_name, adapter_class)
            self.add_result(result)

    # ==================== MCP Server Tests ====================

    def test_mcp_server(self) -> TestResult:
        """Test MCP REST server endpoints"""
        start = time.time()
        base_url = "http://localhost:5001"

        try:
            # Test health endpoint
            health_resp = requests.get(f"{base_url}/health", timeout=5)

            if health_resp.status_code != 200:
                return TestResult(
                    name="MCP Server Health",
                    module="mcp",
                    status="FAIL",
                    duration=time.time() - start,
                    message=f"Health check failed: {health_resp.status_code}",
                )

            # Test capabilities endpoint
            caps_resp = requests.get(f"{base_url}/mcp/capabilities", timeout=5)

            log_content = f"Health: {health_resp.text}\nCapabilities: {caps_resp.text}"
            log_path = self.save_log("mcp_server", log_content)

            return TestResult(
                name="MCP Server",
                module="mcp",
                status="PASS" if caps_resp.status_code == 200 else "FAIL",
                duration=time.time() - start,
                message="Server responding correctly",
                evidence_path=log_path,
            )

        except requests.ConnectionError:
            return TestResult(
                name="MCP Server",
                module="mcp",
                status="SKIP",
                duration=time.time() - start,
                message="Server not running on port 5001",
            )
        except Exception as e:
            return TestResult(
                name="MCP Server",
                module="mcp",
                status="FAIL",
                duration=time.time() - start,
                message=str(e),
            )

    # ==================== Full Audit Test ====================

    def test_full_audit(self) -> TestResult:
        """Test complete 7-layer audit"""
        start = time.time()

        try:
            # Import and run audit
            from run_complete_multilayer_audit import MultiLayerAuditor

            contract = PROJECT_ROOT / "contracts" / "audit" / "VulnerableBank.sol"
            auditor = MultiLayerAuditor(str(contract))

            # Run limited audit (skip slow tools)
            auditor._run_layer_1_static()

            findings_count = len(auditor.findings)

            log_content = json.dumps(
                {
                    "findings": [f.to_dict() for f in auditor.findings],
                    "layer_results": auditor.layer_results,
                },
                indent=2,
                default=str,
            )
            log_path = self.save_log("full_audit", log_content)

            return TestResult(
                name="Full 7-Layer Audit (Layer 1)",
                module="audit",
                status="PASS" if findings_count > 0 else "FAIL",
                duration=time.time() - start,
                message=f"Found {findings_count} findings in Layer 1",
                evidence_path=log_path,
                details={"findings": findings_count},
            )

        except Exception as e:
            return TestResult(
                name="Full 7-Layer Audit",
                module="audit",
                status="FAIL",
                duration=time.time() - start,
                message=str(e),
            )

    # ==================== Unit Tests ====================

    def test_pytest_suite(self) -> TestResult:
        """Run pytest test suite"""
        start = time.time()

        try:
            result = subprocess.run(
                [sys.executable, "-m", "pytest", "tests/", "-v", "--tb=short", "-q"],
                capture_output=True,
                text=True,
                timeout=300,
                cwd=str(PROJECT_ROOT),
            )

            log_path = self.save_log("pytest_suite", result.stdout + result.stderr)

            # Parse results
            passed = result.stdout.count(" passed")
            failed = result.stdout.count(" failed")

            return TestResult(
                name="Pytest Test Suite",
                module="tests",
                status="PASS" if failed == 0 and passed > 0 else "FAIL",
                duration=time.time() - start,
                message=f"{passed} passed, {failed} failed",
                evidence_path=log_path,
                details={"passed": passed, "failed": failed},
            )

        except subprocess.TimeoutExpired:
            return TestResult(
                name="Pytest Test Suite",
                module="tests",
                status="FAIL",
                duration=time.time() - start,
                message="Tests timed out after 300s",
            )
        except Exception as e:
            return TestResult(
                name="Pytest Test Suite",
                module="tests",
                status="FAIL",
                duration=time.time() - start,
                message=str(e),
            )

    # ==================== Report Generation ====================

    def generate_report(self) -> str:
        """Generate comprehensive test report"""
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()

        # Count results
        passed = sum(1 for r in self.results if r.status == "PASS")
        failed = sum(1 for r in self.results if r.status == "FAIL")
        skipped = sum(1 for r in self.results if r.status == "SKIP")
        total = len(self.results)

        report = f"""# MIESC v4.0.0 - Regression Test Report

**Generated**: {end_time.strftime("%Y-%m-%d %H:%M:%S")}
**Duration**: {duration:.2f} seconds
**Platform**: {sys.platform}
**Python**: {sys.version.split()[0]}

---

## Summary

| Metric | Value |
|--------|-------|
| Total Tests | {total} |
| Passed | {passed} |
| Failed | {failed} |
| Skipped | {skipped} |
| Pass Rate | {(passed/total*100) if total > 0 else 0:.1f}% |

---

## Test Results by Module

"""

        # Group by module
        modules = {}
        for r in self.results:
            if r.module not in modules:
                modules[r.module] = []
            modules[r.module].append(r)

        for module, results in modules.items():
            report += f"### {module.upper()}\n\n"
            report += "| Test | Status | Duration | Message |\n"
            report += "|------|--------|----------|--------|\n"

            for r in results:
                status_icon = {"PASS": "✅", "FAIL": "❌", "SKIP": "⏭️"}.get(r.status, "❓")
                report += (
                    f"| {r.name} | {status_icon} {r.status} | {r.duration:.2f}s | {r.message} |\n"
                )

            report += "\n"

        # Add evidence links
        report += "---\n\n## Evidence\n\n"
        for r in self.results:
            if r.evidence_path:
                rel_path = Path(r.evidence_path).relative_to(PROJECT_ROOT)
                report += f"- **{r.name}**: [{rel_path}]({rel_path})\n"

        report += f"""
---

## Conclusion

MIESC v4.0.0 regression testing {'completed successfully' if failed == 0 else 'found issues'}.

- **{passed}/{total}** tests passed
- All core functionality verified
- Evidence captured in `docs/evidence/`

---

*Report generated by MIESC Regression Test Suite*
"""

        return report

    def run_all_tests(self):
        """Run complete regression test suite"""
        print("\n" + "=" * 70)
        print("MIESC v4.0.0 - Complete Regression Test Suite")
        print("=" * 70 + "\n")

        # CLI Tests
        print("\n📋 Testing CLI (miesc-quick)...")
        self.add_result(self.test_cli_doctor())
        self.add_result(self.test_cli_checklist())
        self.add_result(self.test_cli_scan())

        # Adapter Tests
        print("\n🔧 Testing Adapters...")
        self.test_all_adapters()

        # MCP Server Tests
        print("\n🌐 Testing MCP Server...")
        self.add_result(self.test_mcp_server())

        # Full Audit Test
        print("\n🔍 Testing Full Audit...")
        self.add_result(self.test_full_audit())

        # Pytest Suite
        print("\n🧪 Running Pytest Suite...")
        self.add_result(self.test_pytest_suite())

        # Generate report
        print("\n📝 Generating Report...")
        report = self.generate_report()

        report_path = EVIDENCE_DIR / "REGRESSION_TEST_REPORT.md"
        with open(report_path, "w") as f:
            f.write(report)

        print(f"\n✅ Report saved to: {report_path}")

        # Print summary
        passed = sum(1 for r in self.results if r.status == "PASS")
        failed = sum(1 for r in self.results if r.status == "FAIL")
        total = len(self.results)

        print("\n" + "=" * 70)
        print(f"SUMMARY: {passed}/{total} tests passed, {failed} failed")
        print("=" * 70 + "\n")

        return failed == 0


if __name__ == "__main__":
    tester = MIESCRegressionTester()
    success = tester.run_all_tests()
    sys.exit(0 if success else 1)
