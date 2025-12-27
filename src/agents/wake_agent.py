"""
Wake Agent - Python-Based Solidity Development Framework

Wake is a Python-based development framework for Solidity with testing,
fuzzing, and static analysis capabilities. Developed by Ackee Blockchain.

Features:
- Property-based fuzzing with Python
- Static analysis and vulnerability detection
- LSP server for IDE integration
- Advanced testing framework
- Deployment scripting

Integration: Part of MIESC Framework v2.1
"""

import os
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.agents.base_agent import BaseAgent


class WakeAgent(BaseAgent):
    """Python-based testing and analysis agent using Wake"""

    def __init__(self):
        super().__init__(
            agent_name="WakeAgent",
            capabilities=[
                "python_based_testing",
                "property_fuzzing",
                "static_analysis",
                "vulnerability_detection",
                "deployment_scripting"
            ],
            agent_type="hybrid"  # Can do both static and dynamic
        )
        self.wake_path = self._find_wake()

        # Subscribe to relevant channels
        self.bus.subscribe("audit_request", self.handle_message)

    def _find_wake(self) -> Optional[str]:
        """Find Wake binary in system"""
        # Wake is usually in venv or PATH
        locations = [
            "wake",  # PATH (usually venv)
            os.path.expanduser("~/.local/bin/wake"),
            "/usr/local/bin/wake"
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
        """Check if Wake is available"""
        return self.wake_path is not None

    def get_context_types(self) -> List[str]:
        """Return list of context types this agent publishes"""
        return ["static_findings", "dynamic_findings", "wake_results"]

    def analyze(self, contract_path: str, mode: str = "detect", **kwargs) -> Dict[str, Any]:
        """
        Run Wake analysis on contracts

        Args:
            contract_path: Path to contract file or project directory
            mode: Analysis mode - "detect" (static), "test" (fuzzing), or "compile"
            **kwargs: Additional Wake options

        Returns:
            Dictionary with findings and stats
        """
        if not self.is_available():
            return {
                "error": "Wake not installed",
                "suggestion": "Install with: pip install eth-wake"
            }

        try:
            # Prepare paths
            contract_path = Path(contract_path)

            # Determine project root
            if contract_path.is_file():
                project_root = contract_path.parent
            else:
                project_root = contract_path

            # Look for wake.toml
            while project_root != project_root.parent:
                if (project_root / "wake.toml").exists():
                    break
                project_root = project_root.parent
            else:
                project_root = contract_path.parent if contract_path.is_file() else contract_path

            # Build Wake command based on mode
            if mode == "detect":
                result = self._run_detect(project_root, **kwargs)
            elif mode == "test":
                result = self._run_test(project_root, **kwargs)
            elif mode == "compile":
                result = self._run_compile(project_root, **kwargs)
            else:
                return {"error": f"Unknown mode: {mode}"}

            return result

        except subprocess.TimeoutExpired:
            return {"error": f"Wake {mode} timed out"}
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}"}

    def _run_detect(self, project_root: Path, **kwargs) -> Dict[str, Any]:
        """Run Wake vulnerability detection"""
        cmd = [self.wake_path, "detect", "all"]

        # Add paths if specified
        paths = kwargs.get("paths", [])
        if paths:
            cmd.extend(paths)

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(project_root)
        )

        # Parse output
        findings = self._parse_detect_output(result.stdout, result.stderr)

        # Publish to MCP bus
        self._publish_findings(str(project_root), findings, "static")

        return {
            "tool": "Wake",
            "mode": "detect",
            "version": self._get_version(),
            "status": "success" if result.returncode == 0 else "completed_with_findings",
            "findings": findings
        }

    def _run_test(self, project_root: Path, **kwargs) -> Dict[str, Any]:
        """Run Wake tests (fuzzing)"""
        cmd = [self.wake_path, "test"]

        # Add test paths if specified
        test_paths = kwargs.get("test_paths", [])
        if test_paths:
            cmd.extend(test_paths)

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minutes for fuzzing
            cwd=str(project_root)
        )

        # Parse output
        findings = self._parse_test_output(result.stdout, result.stderr)

        # Publish to MCP bus
        self._publish_findings(str(project_root), findings, "dynamic")

        return {
            "tool": "Wake",
            "mode": "test",
            "version": self._get_version(),
            "status": "success" if result.returncode == 0 else "completed_with_findings",
            "findings": findings
        }

    def _run_compile(self, project_root: Path, **kwargs) -> Dict[str, Any]:
        """Run Wake compilation"""
        cmd = [self.wake_path, "compile"]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(project_root)
        )

        return {
            "tool": "Wake",
            "mode": "compile",
            "version": self._get_version(),
            "status": "success" if result.returncode == 0 else "failed",
            "stdout": result.stdout,
            "stderr": result.stderr
        }

    def _get_version(self) -> str:
        """Get Wake version"""
        try:
            result = subprocess.run(
                [self.wake_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return "unknown"

    def _parse_detect_output(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """Parse Wake detect output"""
        findings = {
            "vulnerabilities": [],
            "warnings": [],
            "stats": {}
        }

        lines = (stdout + "\n" + stderr).split('\n')

        vuln_count = 0
        warning_count = 0

        for line in lines:
            line = line.strip()

            # Parse vulnerability reports
            if "Vulnerability:" in line or "vulnerability" in line.lower():
                vuln_count += 1
                findings["vulnerabilities"].append({
                    "description": line,
                    "severity": "high"
                })
            elif "Warning:" in line or "warning" in line.lower():
                warning_count += 1
                findings["warnings"].append(line)

        findings["stats"]["vulnerabilities"] = vuln_count
        findings["stats"]["warnings"] = warning_count

        return findings

    def _parse_test_output(self, stdout: str, stderr: str) -> Dict[str, Any]:
        """Parse Wake test output"""
        findings = {
            "passed": [],
            "failed": [],
            "stats": {}
        }

        lines = (stdout + "\n" + stderr).split('\n')

        for line in lines:
            line = line.strip()

            # Parse test results
            if "PASSED" in line or "passed" in line:
                findings["passed"].append({
                    "test": line,
                    "status": "pass"
                })
            elif "FAILED" in line or "failed" in line:
                findings["failed"].append({
                    "test": line,
                    "status": "fail",
                    "severity": "high"
                })

        findings["stats"]["passed"] = len(findings["passed"])
        findings["stats"]["failed"] = len(findings["failed"])

        return findings

    def _publish_findings(self, contract: str, findings: Dict, analysis_type: str):
        """Publish findings to MCP context bus"""
        try:
            self.contract_path = contract
            context_type = "static_findings" if analysis_type == "static" else "dynamic_findings"

            self.publish_findings(
                context_type=context_type,
                findings={
                    "tool": "Wake",
                    "findings": findings,
                    "timestamp": str(Path(contract).stat().st_mtime) if Path(contract).exists() else "unknown"
                },
                metadata={"tool_version": self._get_version(), "analysis_type": analysis_type}
            )
        except Exception as e:
            # Non-critical, just log
            print(f"Warning: Failed to publish to MCP bus: {e}")

    def quick_detect(self, contract_path: str) -> Dict:
        """
        Quick vulnerability detection

        Args:
            contract_path: Path to contract

        Returns:
            Summary of findings
        """
        result = self.analyze(contract_path, mode="detect")

        if "error" in result:
            return result

        # Extract critical info
        findings = result.get("findings", {})
        vulns = findings.get("vulnerabilities", [])
        warnings = findings.get("warnings", [])

        return {
            "tool": "Wake (Quick Detect)",
            "vulnerabilities": len(vulns),
            "warnings": len(warnings),
            "status": "pass" if len(vulns) == 0 else "fail",
            "critical_vulns": vulns[:3]  # Top 3
        }

    def get_capabilities(self) -> List[str]:
        """Return list of capabilities"""
        return [
            "Python-based testing",
            "Property-based fuzzing",
            "Vulnerability detection",
            "Static analysis",
            "Deployment scripting",
            "LSP server integration"
        ]

    def handle_message(self, message):
        """Handle MCP messages"""
        if message.context_type == "audit_request":
            contract = message.data.get("contract")
            if contract:
                result = self.quick_detect(contract)
                # Publish result
                self.contract_path = contract
                self.publish_findings(
                    context_type="audit_response",
                    findings=result,
                    metadata={"request_source": message.agent}
                )
