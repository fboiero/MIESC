"""
Medusa Agent - Parallel Smart Contract Fuzzer

Medusa is a cross-platform smart contract fuzzer developed by Cyfrin.
It provides parallel fuzzing with property-based testing and coverage tracking.

Features:
- Parallel fuzzing with multiple workers
- Property-based testing (assertions and properties)
- Coverage-guided fuzzing
- Corpus optimization
- Call sequence generation
- Built on go-ethereum

Integration: Part of MIESC Framework v2.1
"""

import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.agents.base_agent import BaseAgent


class MedusaAgent(BaseAgent):
    """Parallel fuzzing agent using Medusa"""

    def __init__(self):
        super().__init__(
            agent_name="MedusaAgent",
            capabilities=[
                "parallel_fuzzing",
                "property_based_testing",
                "coverage_tracking",
                "corpus_optimization",
                "assertion_testing"
            ],
            agent_type="dynamic"
        )
        self.medusa_path = self._find_medusa()

        # Subscribe to relevant channels
        self.bus.subscribe("audit_request", self.handle_message)

    def _find_medusa(self) -> Optional[str]:
        """Find Medusa binary in system"""
        # Check common locations
        locations = [
            os.path.expanduser("~/go/bin/medusa"),
            "/usr/local/bin/medusa",
            "medusa"  # PATH
        ]

        for location in locations:
            try:
                result = subprocess.run(
                    [location, "--help"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0 and "solidity smart contract fuzzing" in result.stdout:
                    return location
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue

        return None

    def is_available(self) -> bool:
        """Check if Medusa is available"""
        return self.medusa_path is not None

    def get_context_types(self) -> List[str]:
        """Return list of context types this agent publishes"""
        return ["dynamic_findings", "medusa_results"]

    def analyze(self, contract_path: str, test_limit: Optional[int] = None, **kwargs) -> Dict[str, Any]:
        """
        Run Medusa fuzzing on contracts

        Args:
            contract_path: Path to contract file or project directory
            test_limit: Optional test limit (default: 10000)
            **kwargs: Additional Medusa options

        Returns:
            Dictionary with findings and stats
        """
        if not self.is_available():
            return {
                "error": "Medusa not installed",
                "suggestion": "Install with: go install github.com/crytic/medusa@latest"
            }

        try:
            # Prepare paths
            contract_path = Path(contract_path)

            # Determine project root
            if contract_path.is_file():
                project_root = contract_path.parent
            else:
                project_root = contract_path

            # Look for foundry.toml or medusa.json
            while project_root != project_root.parent:
                if (project_root / "foundry.toml").exists() or (project_root / "medusa.json").exists():
                    break
                project_root = project_root.parent
            else:
                project_root = contract_path.parent if contract_path.is_file() else contract_path

            # Build Medusa command
            cmd = [self.medusa_path, "fuzz"]

            # Add test limit
            if test_limit:
                cmd.extend(["--test-limit", str(test_limit)])
            else:
                cmd.extend(["--test-limit", "10000"])  # Default

            # Add workers
            workers = kwargs.get("workers", 4)
            cmd.extend(["--workers", str(workers)])

            # Add timeout
            timeout_seconds = kwargs.get("timeout", 300)  # 5 minutes default
            cmd.extend(["--timeout", str(timeout_seconds)])

            # Add compilation platform
            cmd.extend(["--compilation-platform", "crytic-compile"])

            # Run Medusa
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds + 30,  # Add buffer
                cwd=str(project_root)
            )

            # Parse output
            findings = self._parse_medusa_output(result.stdout, result.stderr)

            # Add execution info
            findings["execution"] = {
                "returncode": result.returncode,
                "project_root": str(project_root),
                "command": " ".join(cmd)
            }

            # Publish to MCP bus
            self._publish_findings(str(contract_path), findings)

            return {
                "tool": "Medusa",
                "version": "1.3.1",
                "status": "success" if result.returncode == 0 else "completed_with_findings",
                "findings": findings
            }

        except subprocess.TimeoutExpired:
            return {"error": f"Medusa analysis timed out (>{timeout_seconds}s)"}
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}"}

    def _parse_medusa_output(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """Parse Medusa output"""
        findings = {
            "passed": [],
            "failed": [],
            "coverage": {},
            "stats": {}
        }

        lines = stdout.split('\n') + stderr.split('\n')

        for line in lines:
            line = line.strip()

            # Parse test results
            if "[PASSED]" in line or "PASSED" in line:
                test_name = line.split("PASSED")[-1].strip() if "PASSED" in line else line
                findings["passed"].append({
                    "test": test_name,
                    "status": "pass"
                })
            elif "[FAILED]" in line or "FAILED" in line:
                test_name = line.split("FAILED")[-1].strip() if "FAILED" in line else line
                findings["failed"].append({
                    "test": test_name,
                    "status": "fail",
                    "severity": "high"
                })

            # Parse coverage
            if "Coverage:" in line or "coverage:" in line:
                try:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        coverage_str = parts[-1].strip().replace("%", "")
                        findings["coverage"]["percentage"] = float(coverage_str)
                except (ValueError, IndexError):
                    pass

            # Parse statistics
            if "Test cases:" in line:
                try:
                    count = line.split(":")[-1].strip()
                    findings["stats"]["test_cases"] = int(count)
                except (ValueError, IndexError):
                    pass
            elif "Sequences:" in line:
                try:
                    count = line.split(":")[-1].strip()
                    findings["stats"]["sequences"] = int(count)
                except (ValueError, IndexError):
                    pass

        return findings

    def _publish_findings(self, contract: str, findings: Dict):
        """Publish findings to MCP context bus"""
        try:
            self.contract_path = contract
            self.publish_findings(
                context_type="dynamic_findings",
                findings={
                    "tool": "Medusa",
                    "findings": findings,
                    "timestamp": str(Path(contract).stat().st_mtime) if Path(contract).exists() else "unknown"
                },
                metadata={"tool_version": "1.3.1"}
            )
        except Exception as e:
            # Non-critical, just log
            print(f"Warning: Failed to publish to MCP bus: {e}")

    def quick_fuzz(self, contract_path: str) -> Dict:
        """
        Quick fuzz - fast mode with reduced test limit

        Args:
            contract_path: Path to contract

        Returns:
            Summary of findings
        """
        result = self.analyze(
            contract_path,
            test_limit=1000,  # Quick mode
            workers=2,
            timeout=60  # 1 minute
        )

        if "error" in result:
            return result

        # Extract critical info
        findings = result.get("findings", {})
        failed = findings.get("failed", [])
        passed = findings.get("passed", [])

        return {
            "tool": "Medusa (Quick Fuzz)",
            "failed_tests": len(failed),
            "passed_tests": len(passed),
            "status": "pass" if len(failed) == 0 else "fail",
            "critical_failures": failed[:3]  # Top 3
        }

    def get_capabilities(self) -> List[str]:
        """Return list of capabilities"""
        return [
            "Parallel fuzzing with multiple workers",
            "Property-based testing",
            "Coverage-guided fuzzing",
            "Assertion testing",
            "Call sequence generation",
            "Corpus optimization"
        ]

    def handle_message(self, message):
        """Handle MCP messages"""
        if message.context_type == "audit_request":
            contract = message.data.get("contract")
            if contract:
                result = self.quick_fuzz(contract)
                # Publish result
                self.contract_path = contract
                self.publish_findings(
                    context_type="audit_response",
                    findings=result,
                    metadata={"request_source": message.agent}
                )
