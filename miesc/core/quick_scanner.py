"""
MIESC Quick Scanner

Fast security scanning using only static analysis tools.
Optimized for development workflow (~30 seconds).
"""

import os
import json
import subprocess
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

logger = logging.getLogger(__name__)


class QuickScanner:
    """
    Quick scanner for fast security feedback.

    Uses only static analysis tools (Slither, Aderyn, Solhint)
    for rapid feedback during development.

    Typical execution time: ~30 seconds
    """

    TOOLS = ["slither", "aderyn", "solhint"]

    def __init__(self):
        """Initialize quick scanner."""
        self.available_tools = self._check_tools()

    def _check_tools(self) -> Dict[str, bool]:
        """Check which tools are available."""
        tools = {}
        checks = {
            "slither": ["slither", "--version"],
            "aderyn": ["aderyn", "--version"],
            "solhint": ["solhint", "--version"],
        }

        for tool, cmd in checks.items():
            try:
                result = subprocess.run(cmd, capture_output=True, timeout=10)
                tools[tool] = result.returncode == 0
            except:
                tools[tool] = False

        return tools

    def scan(self, contract_path: str, verbose: bool = False) -> Dict[str, Any]:
        """
        Perform quick scan on contract.

        Args:
            contract_path: Path to Solidity contract
            verbose: Enable verbose output

        Returns:
            Scan results dictionary
        """
        start_time = datetime.now()
        contract_path = str(Path(contract_path).resolve())

        if not os.path.exists(contract_path):
            raise FileNotFoundError(f"Contract not found: {contract_path}")

        results = {
            "contract": contract_path,
            "timestamp": start_time.isoformat(),
            "miesc_version": "4.0.0",
            "scan_type": "quick",
            "tools_run": [],
            "findings": [],
            "summary": {},
        }

        # Run available tools
        for tool in self.TOOLS:
            if not self.available_tools.get(tool, False):
                if verbose:
                    logger.info(f"Skipping {tool} (not available)")
                continue

            if verbose:
                logger.info(f"Running {tool}...")

            try:
                tool_findings = self._run_tool(tool, contract_path)
                results["tools_run"].append(tool)
                results["findings"].extend(tool_findings)
                if verbose:
                    logger.info(f"{tool}: {len(tool_findings)} findings")
            except Exception as e:
                logger.error(f"{tool} failed: {e}")

        # Calculate summary
        results["execution_time"] = (datetime.now() - start_time).total_seconds()
        results["summary"] = self._calculate_summary(results["findings"])

        return results

    def _run_tool(self, tool: str, contract_path: str) -> List[Dict]:
        """Run a specific tool and return findings."""
        if tool == "slither":
            return self._run_slither(contract_path)
        elif tool == "aderyn":
            return self._run_aderyn(contract_path)
        elif tool == "solhint":
            return self._run_solhint(contract_path)
        return []

    def _run_slither(self, contract_path: str) -> List[Dict]:
        """Run Slither static analyzer."""
        findings = []
        try:
            result = subprocess.run(
                ["slither", contract_path, "--json", "-"],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    for detector in data.get("results", {}).get("detectors", []):
                        findings.append({
                            "tool": "slither",
                            "type": detector.get("check"),
                            "severity": self._normalize_severity(detector.get("impact")),
                            "confidence": detector.get("confidence", "").lower(),
                            "description": detector.get("description", ""),
                            "first_markdown_element": detector.get("first_markdown_element"),
                        })
                except json.JSONDecodeError:
                    pass
        except subprocess.TimeoutExpired:
            logger.warning("Slither timed out")
        except FileNotFoundError:
            logger.warning("Slither not installed")

        return findings

    def _run_aderyn(self, contract_path: str) -> List[Dict]:
        """Run Aderyn static analyzer."""
        findings = []
        try:
            result = subprocess.run(
                ["aderyn", contract_path, "--output", "json"],
                capture_output=True,
                text=True,
                timeout=60
            )

            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    for issue in data.get("issues", []):
                        findings.append({
                            "tool": "aderyn",
                            "type": issue.get("title"),
                            "severity": self._normalize_severity(issue.get("severity")),
                            "description": issue.get("description", ""),
                        })
                except json.JSONDecodeError:
                    pass
        except subprocess.TimeoutExpired:
            logger.warning("Aderyn timed out")
        except FileNotFoundError:
            logger.warning("Aderyn not installed")

        return findings

    def _run_solhint(self, contract_path: str) -> List[Dict]:
        """Run Solhint linter."""
        findings = []
        try:
            result = subprocess.run(
                ["solhint", contract_path, "-f", "json"],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.stdout:
                try:
                    data = json.loads(result.stdout)
                    for file_results in data:
                        for msg in file_results.get("messages", []):
                            findings.append({
                                "tool": "solhint",
                                "type": msg.get("ruleId"),
                                "severity": self._normalize_severity(
                                    "error" if msg.get("severity") == 2 else "warning"
                                ),
                                "description": msg.get("message", ""),
                                "line": msg.get("line"),
                                "column": msg.get("column"),
                            })
                except json.JSONDecodeError:
                    pass
        except subprocess.TimeoutExpired:
            logger.warning("Solhint timed out")
        except FileNotFoundError:
            logger.warning("Solhint not installed")

        return findings

    def _normalize_severity(self, severity: str) -> str:
        """Normalize severity levels."""
        if not severity:
            return "info"

        severity = severity.lower()
        mapping = {
            "high": "high",
            "critical": "critical",
            "medium": "medium",
            "low": "low",
            "informational": "info",
            "info": "info",
            "warning": "medium",
            "error": "high",
            "optimization": "info",
        }
        return mapping.get(severity, "info")

    def _calculate_summary(self, findings: List[Dict]) -> Dict:
        """Calculate summary statistics."""
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        tools_used = set()
        types_found = set()

        for f in findings:
            sev = f.get("severity", "info")
            if sev in severity_counts:
                severity_counts[sev] += 1
            tools_used.add(f.get("tool", "unknown"))
            if f.get("type"):
                types_found.add(f["type"])

        return {
            "total_findings": len(findings),
            "by_severity": severity_counts,
            "tools_used": list(tools_used),
            "issue_types": len(types_found),
        }
