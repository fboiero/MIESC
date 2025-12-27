"""
Halmos Agent - Symbolic Testing for Ethereum Smart Contracts

Halmos is a symbolic testing tool that leverages symbolic execution
to explore all possible execution paths in Solidity smart contracts.

Features:
- Symbolic execution of Foundry tests
- Property-based testing without fuzzing
- Path exploration with constraint solving
- Integration with Foundry test framework
- Fast execution via z3-solver

Integration: Part of MIESC Framework v2.1
"""

import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.agents.base_agent import BaseAgent


class HalmosAgent(BaseAgent):
    """Symbolic testing agent using Halmos"""

    def __init__(self):
        super().__init__(
            agent_name="HalmosAgent",
            capabilities=[
                "symbolic_execution",
                "property_based_testing",
                "path_exploration",
                "constraint_solving",
                "foundry_integration"
            ],
            agent_type="symbolic"
        )
        self.halmos_path = self._find_halmos()

        # Subscribe to relevant channels
        self.bus.subscribe("audit_request", self.handle_message)

    def _find_halmos(self) -> Optional[str]:
        """Find Halmos binary in system"""
        # Check common locations
        locations = [
            "halmos",  # PATH
            os.path.expanduser("~/.local/bin/halmos"),
            "/usr/local/bin/halmos"
        ]

        for location in locations:
            try:
                result = subprocess.run(
                    [location, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    return location
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue

        return None

    def is_available(self) -> bool:
        """Check if Halmos is available"""
        return self.halmos_path is not None

    def get_context_types(self) -> List[str]:
        """Return list of context types this agent publishes"""
        return ["symbolic_findings", "halmos_results"]

    def analyze(self, contract_path: str, test_path: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        """
        Run Halmos symbolic testing on contracts

        Args:
            contract_path: Path to contract file or directory
            test_path: Optional path to test file
            **kwargs: Additional Halmos options

        Returns:
            Dictionary with findings and stats
        """
        if not self.is_available():
            return {
                "error": "Halmos not installed",
                "suggestion": "Install with: pip install halmos"
            }

        try:
            # Prepare paths
            contract_path = Path(contract_path)

            # Determine project root (look for foundry.toml)
            if contract_path.is_file():
                project_root = contract_path.parent
            else:
                project_root = contract_path

            # Look for foundry.toml
            while project_root != project_root.parent:
                if (project_root / "foundry.toml").exists():
                    break
                project_root = project_root.parent
            else:
                # No foundry.toml found, use contract directory
                project_root = contract_path.parent if contract_path.is_file() else contract_path

            # Build Halmos command
            cmd = [self.halmos_path]

            # Add solver timeout
            solver_timeout = kwargs.get("solver_timeout", 60000)  # 60 seconds default
            cmd.extend(["--solver-timeout-assertion", str(solver_timeout)])

            # Add depth limit
            loop_bound = kwargs.get("loop_bound", 2)
            cmd.extend(["--loop", str(loop_bound)])

            # Add specific test if provided
            if test_path:
                cmd.extend(["--test", str(test_path)])

            # Run Halmos
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180,  # 3 minutes timeout
                cwd=str(project_root)
            )

            # Parse output
            findings = self._parse_halmos_output(result.stdout, result.stderr)

            # Add execution info
            findings["execution"] = {
                "returncode": result.returncode,
                "project_root": str(project_root),
                "command": " ".join(cmd)
            }

            # Publish to MCP bus
            self._publish_findings(str(contract_path), findings)

            return {
                "tool": "Halmos",
                "version": self._get_version(),
                "status": "success" if result.returncode == 0 else "completed_with_findings",
                "findings": findings
            }

        except subprocess.TimeoutExpired:
            return {"error": "Halmos analysis timed out (>3 minutes)"}
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}"}

    def _get_version(self) -> str:
        """Get Halmos version"""
        try:
            result = subprocess.run(
                [self.halmos_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return "unknown"

    def _parse_halmos_output(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """Parse Halmos output"""
        findings = {
            "passed": [],
            "failed": [],
            "warnings": [],
            "stats": {}
        }

        lines = stdout.split('\n') + stderr.split('\n')

        for line in lines:
            line = line.strip()

            # Parse test results
            if "[PASS]" in line:
                test_name = line.split("[PASS]")[1].strip()
                findings["passed"].append({
                    "test": test_name,
                    "status": "pass"
                })
            elif "[FAIL]" in line:
                test_name = line.split("[FAIL]")[1].strip()
                findings["failed"].append({
                    "test": test_name,
                    "status": "fail",
                    "severity": "high"
                })

            # Parse warnings
            if "WARNING" in line or "Warning" in line:
                findings["warnings"].append(line)

            # Parse statistics
            if "Paths explored:" in line:
                try:
                    count = line.split(":")[-1].strip()
                    findings["stats"]["paths_explored"] = int(count)
                except (ValueError, IndexError):
                    pass
            elif "tests passed" in line:
                try:
                    parts = line.split()
                    passed = int(parts[0])
                    total = int(parts[3])
                    findings["stats"]["tests_passed"] = passed
                    findings["stats"]["tests_total"] = total
                except (ValueError, IndexError):
                    pass

        return findings

    def _publish_findings(self, contract: str, findings: Dict):
        """Publish findings to MCP context bus"""
        try:
            self.contract_path = contract
            self.publish_findings(
                context_type="symbolic_findings",
                findings={
                    "tool": "Halmos",
                    "findings": findings,
                    "timestamp": str(Path(contract).stat().st_mtime) if Path(contract).exists() else "unknown"
                },
                metadata={"tool_version": self._get_version()}
            )
        except Exception as e:
            # Non-critical, just log
            print(f"Warning: Failed to publish to MCP bus: {e}")

    def quick_check(self, contract_path: str) -> Dict:
        """
        Quick symbolic check - fast mode with reduced bounds

        Args:
            contract_path: Path to contract

        Returns:
            Summary of findings
        """
        result = self.analyze(
            contract_path,
            solver_timeout=10000,  # 10 seconds
            loop_bound=1  # Minimal loop bound
        )

        if "error" in result:
            return result

        # Extract critical info
        findings = result.get("findings", {})
        failed = findings.get("failed", [])
        passed = findings.get("passed", [])

        return {
            "tool": "Halmos (Quick Check)",
            "failed_tests": len(failed),
            "passed_tests": len(passed),
            "status": "pass" if len(failed) == 0 else "fail",
            "critical_failures": failed[:3]  # Top 3
        }

    def get_capabilities(self) -> List[str]:
        """Return list of capabilities"""
        return [
            "Symbolic execution of Foundry tests",
            "Property-based testing",
            "Path exploration",
            "Constraint solving with z3",
            "No fuzzing required",
            "Exhaustive testing"
        ]

    def handle_message(self, message):
        """Handle MCP messages"""
        if message.context_type == "audit_request":
            contract = message.data.get("contract")
            if contract:
                result = self.quick_check(contract)
                # Publish result
                self.contract_path = contract
                self.publish_findings(
                    context_type="audit_response",
                    findings=result,
                    metadata={"request_source": message.agent}
                )
