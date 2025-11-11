"""
Deployment Verification Script for MIESC 2025
==============================================

Verifies that all components of MIESC 2025 are correctly deployed and functional.
Tests Docker environment, adapter availability, and integration points.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: November 10, 2025
"""

import sys
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.adapters import register_all_adapters, get_adapter_status_report
from src.core.tool_protocol import ToolStatus


class DeploymentVerifier:
    """Verifies MIESC deployment status"""

    def __init__(self):
        self.results: List[Tuple[str, bool, str]] = []
        self.failed_checks = 0
        self.passed_checks = 0

    def check(self, name: str, condition: bool, message: str = ""):
        """Record a verification check"""
        self.results.append((name, condition, message))
        if condition:
            self.passed_checks += 1
            print(f"✅ {name}")
            if message:
                print(f"   {message}")
        else:
            self.failed_checks += 1
            print(f"❌ {name}")
            if message:
                print(f"   {message}")

    def verify_python_environment(self) -> bool:
        """Verify Python environment and dependencies"""
        print("\n" + "="*70)
        print("PYTHON ENVIRONMENT")
        print("="*70)

        # Check Python version
        python_version = sys.version_info
        version_ok = python_version >= (3, 8)
        self.check(
            "Python Version",
            version_ok,
            f"Python {python_version.major}.{python_version.minor}.{python_version.micro}"
        )

        # Check critical imports
        try:
            import pytest
            self.check("pytest installed", True, f"Version: {pytest.__version__}")
        except ImportError as e:
            self.check("pytest installed", False, str(e))

        try:
            from src.adapters import AderynAdapter, MedusaAdapter
            self.check("MIESC adapters importable", True)
        except ImportError as e:
            self.check("MIESC adapters importable", False, str(e))

        try:
            from src.core.tool_protocol import ToolAdapter, ToolMetadata
            self.check("Tool Protocol importable", True)
        except ImportError as e:
            self.check("Tool Protocol importable", False, str(e))

        return self.failed_checks == 0

    def verify_adapter_registry(self) -> bool:
        """Verify adapter registry and tool availability"""
        print("\n" + "="*70)
        print("ADAPTER REGISTRY")
        print("="*70)

        try:
            report = register_all_adapters()

            self.check(
                "Adapter registration",
                report["failed"] == 0,
                f"{report['registered']}/{report['total_adapters']} adapters registered"
            )

            # Verify 2025 adapters specifically
            adapter_names = [a["name"] for a in report["adapters"]]

            self.check(
                "Aderyn adapter registered",
                "aderyn" in adapter_names
            )

            self.check(
                "Medusa adapter registered",
                "medusa" in adapter_names
            )

            # Check DPGA compliance
            all_optional = all(a["optional"] for a in report["adapters"])
            self.check(
                "DPGA compliance (all adapters optional)",
                all_optional
            )

            # Check available adapters
            available = [a for a in report["adapters"] if a["status"] == "available"]
            self.check(
                "Built-in adapters available",
                len(available) >= 3,  # At least GasAnalyzer, MEVDetector, ThreatModel
                f"{len(available)} adapters available"
            )

            return True

        except Exception as e:
            self.check("Adapter registry", False, str(e))
            return False

    def verify_tool_availability(self) -> Dict[str, str]:
        """Check availability of external tools"""
        print("\n" + "="*70)
        print("EXTERNAL TOOLS")
        print("="*70)

        tools_status = {}

        # Aderyn
        try:
            result = subprocess.run(
                ["aderyn", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                tools_status["aderyn"] = "available"
                self.check("Aderyn", True, result.stdout.strip())
            else:
                tools_status["aderyn"] = "not_installed"
                self.check("Aderyn", False, "Not installed (optional)")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            tools_status["aderyn"] = "not_installed"
            self.check("Aderyn", False, "Not installed (optional)")

        # Medusa
        try:
            result = subprocess.run(
                ["medusa", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                tools_status["medusa"] = "available"
                self.check("Medusa", True, result.stdout.strip())
            else:
                tools_status["medusa"] = "not_installed"
                self.check("Medusa", False, "Not installed (optional)")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            tools_status["medusa"] = "not_installed"
            self.check("Medusa", False, "Not installed (optional)")

        # Slither
        try:
            result = subprocess.run(
                ["slither", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                tools_status["slither"] = "available"
                self.check("Slither", True, result.stdout.strip())
            else:
                tools_status["slither"] = "not_installed"
                self.check("Slither", False, "Not installed (optional)")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            tools_status["slither"] = "not_installed"
            self.check("Slither", False, "Not installed (optional)")

        return tools_status

    def verify_docker_environment(self) -> bool:
        """Verify Docker availability"""
        print("\n" + "="*70)
        print("DOCKER ENVIRONMENT")
        print("="*70)

        # Check Docker
        try:
            result = subprocess.run(
                ["docker", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            docker_available = result.returncode == 0
            self.check(
                "Docker installed",
                docker_available,
                result.stdout.strip() if docker_available else "Not installed"
            )

            if docker_available:
                # Check if Docker daemon is running
                result = subprocess.run(
                    ["docker", "ps"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                daemon_running = result.returncode == 0
                self.check(
                    "Docker daemon running",
                    daemon_running,
                    "Daemon accessible" if daemon_running else "Daemon not running"
                )

                # Check for MIESC image
                result = subprocess.run(
                    ["docker", "images", "miesc", "--format", "{{.Repository}}:{{.Tag}}"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                images = result.stdout.strip().split("\n") if result.stdout.strip() else []
                self.check(
                    "MIESC Docker image",
                    len(images) > 0,
                    f"Found: {', '.join(images)}" if images else "Image not built"
                )

            return docker_available

        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            self.check("Docker installed", False, str(e))
            return False

    def verify_test_suite(self) -> bool:
        """Verify test suite functionality"""
        print("\n" + "="*70)
        print("TEST SUITE")
        print("="*70)

        try:
            # Run quick test to verify test infrastructure
            result = subprocess.run(
                ["python", "-m", "pytest", "--collect-only", "-q"],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=Path(__file__).parent.parent
            )

            tests_collected = "test" in result.stdout.lower()
            self.check(
                "Test collection",
                tests_collected,
                f"Tests discoverable" if tests_collected else "No tests found"
            )

            # Check for 2025 adapter tests
            test_files = [
                "tests/adapters/test_aderyn_adapter.py",
                "tests/adapters/test_medusa_adapter.py",
                "tests/adapters/test_all_adapters.py",
                "tests/e2e/test_complete_analysis.py"
            ]

            for test_file in test_files:
                file_path = Path(__file__).parent.parent / test_file
                exists = file_path.exists()
                self.check(
                    f"Test file: {test_file}",
                    exists
                )

            return True

        except Exception as e:
            self.check("Test suite", False, str(e))
            return False

    def verify_documentation(self) -> bool:
        """Verify documentation completeness"""
        print("\n" + "="*70)
        print("DOCUMENTATION")
        print("="*70)

        doc_files = [
            "docs/ADERYN_ADAPTER.md",
            "docs/MEDUSA_ADAPTER.md",
            "docs/IMPLEMENTATION_PROGRESS_2025.md"
        ]

        for doc_file in doc_files:
            file_path = Path(__file__).parent.parent / doc_file
            exists = file_path.exists()

            if exists:
                # Check file size to ensure it's not empty
                size = file_path.stat().st_size
                self.check(
                    f"Documentation: {doc_file}",
                    size > 1000,  # At least 1KB
                    f"{size} bytes"
                )
            else:
                self.check(f"Documentation: {doc_file}", False, "Not found")

        return True

    def generate_report(self) -> str:
        """Generate verification report"""
        total_checks = len(self.results)
        pass_rate = (self.passed_checks / total_checks * 100) if total_checks > 0 else 0

        report = f"""
{'='*70}
MIESC 2025 DEPLOYMENT VERIFICATION REPORT
{'='*70}

Total Checks: {total_checks}
Passed: {self.passed_checks}
Failed: {self.failed_checks}
Pass Rate: {pass_rate:.1f}%

Status: {'✅ READY FOR DEPLOYMENT' if self.failed_checks == 0 else '⚠️ ISSUES DETECTED'}
"""

        if self.failed_checks > 0:
            report += "\nFailed Checks:\n"
            for name, passed, message in self.results:
                if not passed:
                    report += f"  ❌ {name}\n"
                    if message:
                        report += f"     {message}\n"

        report += f"\n{'='*70}\n"

        return report


def main():
    """Main verification execution"""
    print("="*70)
    print("MIESC 2025 SECURITY IMPROVEMENTS - DEPLOYMENT VERIFICATION")
    print("="*70)
    print("\nVerifying deployment components...")

    verifier = DeploymentVerifier()

    # Run all verifications
    verifier.verify_python_environment()
    verifier.verify_adapter_registry()
    verifier.verify_tool_availability()
    verifier.verify_docker_environment()
    verifier.verify_test_suite()
    verifier.verify_documentation()

    # Generate and display report
    report = verifier.generate_report()
    print(report)

    # Save report to file
    output_dir = Path(__file__).parent.parent / "outputs" / "deployment"
    output_dir.mkdir(parents=True, exist_ok=True)

    from datetime import datetime
    report_file = output_dir / f"deployment_verification_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

    with open(report_file, 'w') as f:
        f.write(report)

    print(f"Report saved to: {report_file}")

    # Exit with appropriate code
    sys.exit(0 if verifier.failed_checks == 0 else 1)


if __name__ == "__main__":
    main()
