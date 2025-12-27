"""
Aderyn Agent - Ultra-Fast Rust-Based Static Analyzer

Aderyn is a Rust-based Solidity static analyzer developed by Cyfrin.
It provides ultra-fast AST-based analysis with 87+ detectors.

Features:
- 10-50x faster than Python-based analyzers
- Direct Solidity AST traversal
- Markdown report generation
- 87+ built-in detectors
- Custom detector framework

Integration: Part of MIESC Framework v2.1
"""

import os
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from src.agents.base_agent import BaseAgent
from src.mcp.context_bus import MCPMessage


class AderynAgent(BaseAgent):
    """Ultra-fast static analyzer using Aderyn (Rust-based)"""

    def __init__(self):
        super().__init__(
            agent_name="AderynAgent",
            capabilities=[
                "ultra_fast_static_analysis",
                "ast_traversal",
                "vulnerability_detection",
                "markdown_reporting",
                "87_detectors"
            ],
            agent_type="static"
        )
        self.aderyn_path = self._find_aderyn()

        # Subscribe to relevant channels
        self.bus.subscribe("audit_request", self.handle_message)

    def _find_aderyn(self) -> Optional[str]:
        """Find Aderyn binary in system"""
        # Check common locations
        locations = [
            os.path.expanduser("~/.cargo/bin/aderyn"),
            "/usr/local/bin/aderyn",
            "aderyn"  # PATH
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
        """Check if Aderyn is available"""
        return self.aderyn_path is not None

    def get_context_types(self) -> List[str]:
        """Return list of context types this agent publishes"""
        return ["static_findings", "aderyn_results"]

    def analyze(self, contract_path: str, output_dir: Optional[str] = None) -> Dict:
        """
        Run Aderyn analysis on contracts

        Args:
            contract_path: Path to contract file or directory
            output_dir: Optional output directory for report

        Returns:
            Dictionary with findings and stats
        """
        if not self.is_available():
            return {
                "error": "Aderyn not installed",
                "suggestion": "Install with: curl --proto '=https' --tlsv1.2 -LsSf https://github.com/cyfrin/aderyn/releases/latest/download/aderyn-installer.sh | sh"
            }

        try:
            # Prepare path - Aderyn needs directory
            contract_path = Path(contract_path)
            if contract_path.is_file():
                analysis_dir = contract_path.parent
            else:
                analysis_dir = contract_path

            # Run Aderyn
            cmd = [self.aderyn_path, str(analysis_dir)]

            if output_dir:
                cmd.extend(["--output", output_dir])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                cwd=str(analysis_dir)
            )

            if result.returncode != 0:
                return {
                    "error": "Aderyn analysis failed",
                    "stderr": result.stderr,
                    "stdout": result.stdout
                }

            # Parse report.md
            report_path = analysis_dir / "report.md"
            if report_path.exists():
                findings = self._parse_markdown_report(report_path)
            else:
                findings = {"warning": "No report generated"}

            # Publish to MCP bus
            self._publish_findings(str(contract_path), findings)

            return {
                "tool": "Aderyn",
                "version": self._get_version(),
                "status": "success",
                "findings": findings,
                "report_path": str(report_path) if report_path.exists() else None
            }

        except subprocess.TimeoutExpired:
            return {"error": "Aderyn analysis timed out (>60s)"}
        except Exception as e:
            return {"error": f"Unexpected error: {str(e)}"}

    def _get_version(self) -> str:
        """Get Aderyn version"""
        try:
            result = subprocess.run(
                [self.aderyn_path, "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return "unknown"

    def _parse_markdown_report(self, report_path: Path) -> Dict:
        """Parse Aderyn markdown report"""
        try:
            content = report_path.read_text()

            findings = {
                "high": [],
                "medium": [],
                "low": [],
                "stats": {}
            }

            # Extract issue counts
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if "| High |" in line:
                    count = line.split('|')[2].strip()
                    findings["stats"]["high"] = int(count) if count.isdigit() else 0
                elif "| Medium |" in line:
                    count = line.split('|')[2].strip()
                    findings["stats"]["medium"] = int(count) if count.isdigit() else 0
                elif "| Low |" in line:
                    count = line.split('|')[2].strip()
                    findings["stats"]["low"] = int(count) if count.isdigit() else 0

                # Extract high issues
                if line.startswith("## H-"):
                    title = line.replace("## H-", "").strip()
                    description = ""
                    if i + 2 < len(lines):
                        description = lines[i + 2].strip()
                    findings["high"].append({
                        "title": title,
                        "description": description
                    })

                # Extract low issues
                if line.startswith("## L-"):
                    title = line.replace("## L-", "").strip()
                    description = ""
                    if i + 2 < len(lines):
                        description = lines[i + 2].strip()
                    findings["low"].append({
                        "title": title,
                        "description": description
                    })

            return findings

        except Exception as e:
            return {"error": f"Failed to parse report: {str(e)}"}

    def _publish_findings(self, contract: str, findings: Dict):
        """Publish findings to MCP context bus"""
        try:
            self.contract_path = contract
            self.publish_findings(
                context_type="static_findings",
                findings={
                    "tool": "Aderyn",
                    "findings": findings,
                    "timestamp": str(Path(contract).stat().st_mtime)
                },
                metadata={"tool_version": self._get_version()}
            )
        except Exception as e:
            # Non-critical, just log
            print(f"Warning: Failed to publish to MCP bus: {e}")

    def quick_scan(self, contract_path: str) -> Dict:
        """
        Quick scan mode - just check for critical issues

        Args:
            contract_path: Path to contract

        Returns:
            Summary of critical findings
        """
        result = self.analyze(contract_path)

        if "error" in result:
            return result

        # Extract critical info
        findings = result.get("findings", {})
        stats = findings.get("stats", {})

        return {
            "tool": "Aderyn (Quick Scan)",
            "critical_count": stats.get("high", 0),
            "warning_count": stats.get("medium", 0) + stats.get("low", 0),
            "status": "pass" if stats.get("high", 0) == 0 else "fail",
            "high_issues": findings.get("high", [])[:3]  # Top 3
        }

    def get_capabilities(self) -> List[str]:
        """Return list of detection capabilities"""
        return [
            "Reentrancy detection",
            "Access control issues",
            "Arithmetic vulnerabilities",
            "Unchecked calls",
            "Gas optimization",
            "Best practices",
            "87+ total detectors"
        ]

    def handle_message(self, message: MCPMessage):
        """Handle MCP messages"""
        if message.context_type == "audit_request":
            contract = message.data.get("contract")
            if contract:
                result = self.quick_scan(contract)
                # Publish result
                self.contract_path = contract
                self.publish_findings(
                    context_type="audit_response",
                    findings=result,
                    metadata={"request_source": message.agent}
                )
