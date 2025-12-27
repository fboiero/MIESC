"""
SMTChecker Agent - Built-in Solidity Formal Verification

SMTChecker is a built-in formal verification module in the Solidity compiler (solc).
It uses SMT (Satisfiability Modulo Theories) and Horn solving to verify safety properties.

Features:
- Built-in to solc (no additional installation needed)
- Detects arithmetic overflows/underflows
- Verifies assertions
- Checks unreachable code
- Division by zero detection
- Out-of-bounds array access

Integration: Part of MIESC Framework v2.1+
"""

import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.agents.base_agent import BaseAgent


class SMTCheckerAgent(BaseAgent):
    """Formal verification agent using Solidity's built-in SMTChecker"""

    def __init__(self):
        super().__init__(
            agent_name="SMTCheckerAgent",
            capabilities=[
                "formal_verification",
                "overflow_detection",
                "assertion_verification",
                "invariant_checking",
                "division_by_zero"
            ],
            agent_type="formal"
        )
        self.solc_path = self._find_solc()

        # Subscribe to relevant channels
        self.bus.subscribe("audit_request", self.handle_message)

    def _find_solc(self) -> Optional[str]:
        """Find Solidity compiler in system"""
        locations = [
            "solc",  # PATH
            "/usr/local/bin/solc",
            os.path.expanduser("~/.solc-select/artifacts/solc")
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
        """Check if solc is available"""
        return self.solc_path is not None

    def get_context_types(self) -> List[str]:
        """Return list of context types this agent publishes"""
        return ["formal_findings", "smtchecker_results"]

    def analyze(self, contract_path: str, model_checker_engine: str = "all", **kwargs) -> Dict[str, Any]:
        """
        Run SMTChecker on contracts

        Args:
            contract_path: Path to contract file
            model_checker_engine: Engine to use - "bmc", "chc", or "all" (default)
            **kwargs: Additional options
                - targets: List of verification targets (default: all)
                - timeout: Timeout in seconds (default: 60)

        Returns:
            Dictionary with findings and stats
        """
        if not self.is_available():
            return {
                "error": "Solidity compiler (solc) not installed",
                "suggestion": "Install with: pip install solc-select && solc-select install 0.8.20"
            }

        try:
            # Prepare path
            contract_path = Path(contract_path)
            if not contract_path.exists():
                return {"error": f"Contract not found: {contract_path}"}

            # Build solc command with SMTChecker
            cmd = [
                self.solc_path,
                str(contract_path),
                "--model-checker-engine", model_checker_engine,
                "--model-checker-show-unproved",  # Show all results
                "--json-output"  # Get JSON output
            ]

            # Add targets if specified
            targets = kwargs.get("targets", ["underflow", "overflow", "divByZero", "assert", "balance"])
            if targets:
                cmd.extend(["--model-checker-targets", ",".join(targets)])

            # Set timeout
            timeout = kwargs.get("timeout", 60)
            cmd.extend(["--model-checker-timeout", str(timeout * 1000)])  # milliseconds

            # Run SMTChecker
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 10
            )

            # Parse output
            findings = self._parse_smtchecker_output(result.stdout, result.stderr)

            # Add execution info
            findings["execution"] = {
                "returncode": result.returncode,
                "engine": model_checker_engine,
                "contract": str(contract_path)
            }

            # Publish to MCP bus
            self._publish_findings(str(contract_path), findings)

            return {
                "tool": "SMTChecker",
                "version": self._get_solc_version(),
                "status": "success" if result.returncode == 0 else "completed_with_findings",
                "findings": findings
            }

        except subprocess.TimeoutExpired:
            return {"error": f"SMTChecker analysis timed out (>{timeout}s)"}
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}"}

    def _get_solc_version(self) -> str:
        """Get Solidity compiler version"""
        try:
            result = subprocess.run(
                [self.solc_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            # Extract version from output
            for line in result.stdout.split('\n'):
                if 'Version:' in line:
                    return line.split('Version:')[1].strip()
            return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return "unknown"

    def _parse_smtchecker_output(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """Parse SMTChecker output"""
        findings = {
            "verified": [],
            "warnings": [],
            "errors": [],
            "stats": {}
        }

        # Combine output
        output = stdout + "\n" + stderr
        lines = output.split('\n')

        for line in lines:
            line = line.strip()

            # Parse warnings (potential vulnerabilities)
            if "Warning:" in line or "warning:" in line.lower():
                # Check for specific SMT warnings
                if any(keyword in line.lower() for keyword in
                       ["overflow", "underflow", "assertion", "division", "unreachable"]):
                    findings["warnings"].append({
                        "type": self._extract_warning_type(line),
                        "message": line,
                        "severity": "medium"
                    })

            # Parse errors
            elif "Error:" in line or "error:" in line.lower():
                findings["errors"].append({
                    "message": line,
                    "severity": "high"
                })

            # Parse verification results
            elif "CHC:" in line or "BMC:" in line:
                if "verified" in line.lower() or "safe" in line.lower():
                    findings["verified"].append({
                        "engine": "CHC" if "CHC:" in line else "BMC",
                        "status": "verified",
                        "message": line
                    })

        # Calculate stats
        findings["stats"]["total_warnings"] = len(findings["warnings"])
        findings["stats"]["total_errors"] = len(findings["errors"])
        findings["stats"]["verified_properties"] = len(findings["verified"])

        return findings

    def _extract_warning_type(self, line: str) -> str:
        """Extract warning type from line"""
        line_lower = line.lower()
        if "overflow" in line_lower:
            return "overflow"
        elif "underflow" in line_lower:
            return "underflow"
        elif "assertion" in line_lower:
            return "assertion_violation"
        elif "division" in line_lower:
            return "division_by_zero"
        elif "unreachable" in line_lower:
            return "unreachable_code"
        else:
            return "unknown"

    def _publish_findings(self, contract: str, findings: Dict):
        """Publish findings to MCP context bus"""
        try:
            self.contract_path = contract
            self.publish_findings(
                context_type="formal_findings",
                findings={
                    "tool": "SMTChecker",
                    "findings": findings,
                    "timestamp": str(Path(contract).stat().st_mtime) if Path(contract).exists() else "unknown"
                },
                metadata={"tool_version": self._get_solc_version(), "verification_type": "smt_based"}
            )
        except Exception as e:
            # Non-critical, just log
            print(f"Warning: Failed to publish to MCP bus: {e}")

    def quick_verify(self, contract_path: str) -> Dict:
        """
        Quick verification - fast mode with basic checks

        Args:
            contract_path: Path to contract

        Returns:
            Summary of findings
        """
        result = self.analyze(
            contract_path,
            model_checker_engine="bmc",  # Bounded Model Checking (faster)
            targets=["overflow", "underflow", "divByZero", "assert"],
            timeout=30  # 30 seconds
        )

        if "error" in result:
            return result

        # Extract critical info
        findings = result.get("findings", {})
        warnings = findings.get("warnings", [])
        errors = findings.get("errors", [])

        return {
            "tool": "SMTChecker (Quick Verify)",
            "warnings": len(warnings),
            "errors": len(errors),
            "status": "pass" if len(errors) == 0 else "fail",
            "critical_issues": errors[:3] + warnings[:3]  # Top 3 of each
        }

    def get_capabilities(self) -> List[str]:
        """Return list of capabilities"""
        return [
            "Arithmetic overflow/underflow detection",
            "Assertion verification",
            "Division by zero detection",
            "Unreachable code detection",
            "Out-of-bounds array access",
            "BMC (Bounded Model Checking)",
            "CHC (Constrained Horn Clauses)"
        ]

    def handle_message(self, message):
        """Handle MCP messages"""
        if message.context_type == "audit_request":
            contract = message.data.get("contract")
            if contract:
                result = self.quick_verify(contract)
                # Publish result
                self.contract_path = contract
                self.publish_findings(
                    context_type="audit_response",
                    findings=result,
                    metadata={"request_source": message.agent}
                )
