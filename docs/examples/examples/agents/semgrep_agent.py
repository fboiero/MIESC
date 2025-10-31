"""
Semgrep Agent - Example External Agent
=======================================

Example implementation of a MIESC security agent.
This shows how external developers can create their own agents.

Author: External Contributor (Example)
License: MIT
"""

import subprocess
import json
import logging
from typing import List
from datetime import datetime
import time
from pathlib import Path

# Import MIESC Protocol (install miesc package or add to PYTHONPATH)
from src.core.agent_protocol import (
    SecurityAgent,
    AgentCapability,
    AgentSpeed,
    AnalysisResult,
    AnalysisStatus,
    Finding,
    FindingSeverity
)

logger = logging.getLogger(__name__)


class SemgrepAgent(SecurityAgent):
    """
    Semgrep static analysis agent.

    Semgrep is a fast, open-source, static analysis tool for finding bugs
    and enforcing code standards.

    Homepage: https://semgrep.dev
    """

    @property
    def name(self) -> str:
        return "semgrep"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def description(self) -> str:
        return "Fast static analysis with custom pattern matching"

    @property
    def author(self) -> str:
        return "External Contributor"

    @property
    def license(self) -> str:
        return "MIT"

    @property
    def capabilities(self) -> List[AgentCapability]:
        return [
            AgentCapability.STATIC_ANALYSIS,
            AgentCapability.PATTERN_MATCHING,
            AgentCapability.CUSTOM_RULES
        ]

    @property
    def supported_languages(self) -> List[str]:
        return [
            "solidity",
            "python",
            "javascript",
            "typescript",
            "go",
            "java",
            "rust"
        ]

    @property
    def cost(self) -> float:
        return 0.0  # Free

    @property
    def speed(self) -> AgentSpeed:
        return AgentSpeed.FAST

    @property
    def homepage(self) -> str:
        return "https://semgrep.dev"

    @property
    def repository(self) -> str:
        return "https://github.com/returntocorp/semgrep"

    @property
    def documentation(self) -> str:
        return "https://semgrep.dev/docs"

    @property
    def installation(self) -> str:
        return "pip install semgrep"

    def is_available(self) -> bool:
        """Check if Semgrep is installed"""
        try:
            result = subprocess.run(
                ['semgrep', '--version'],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def can_analyze(self, file_path: str) -> bool:
        """Check if file can be analyzed"""
        path = Path(file_path)

        if not path.exists():
            return False

        # Check file extension
        supported_extensions = ['.sol', '.py', '.js', '.ts', '.go', '.java', '.rs']
        return path.suffix in supported_extensions

    def analyze(self, contract: str, **kwargs) -> AnalysisResult:
        """
        Run Semgrep analysis.

        Args:
            contract: Path to file to analyze
            **kwargs: Additional options
                - config: Semgrep config (default: "auto")
                - rules: Path to custom rules

        Returns:
            AnalysisResult with findings
        """
        start_time = time.time()

        try:
            logger.info(f"Running Semgrep analysis on {contract}")

            # Get configuration
            config = kwargs.get('config', 'auto')
            rules = kwargs.get('rules')

            # Build command
            cmd = ['semgrep', '--json']

            if rules:
                cmd.extend(['--config', rules])
            else:
                cmd.extend(['--config', config])

            cmd.append(contract)

            # Run Semgrep
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            if result.returncode not in [0, 1]:  # 1 = findings found
                raise RuntimeError(f"Semgrep failed: {result.stderr}")

            # Parse JSON output
            semgrep_data = json.loads(result.stdout)
            findings = self._parse_semgrep_results(semgrep_data)

            # Calculate summary
            summary = self._calculate_summary(findings)

            execution_time = time.time() - start_time

            return AnalysisResult(
                agent=self.name,
                version=self.version,
                status=AnalysisStatus.SUCCESS,
                timestamp=datetime.now(),
                execution_time=execution_time,
                findings=findings,
                summary=summary,
                metadata={
                    'config': config,
                    'rules_count': len(semgrep_data.get('results', []))
                }
            )

        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            return AnalysisResult(
                agent=self.name,
                version=self.version,
                status=AnalysisStatus.TIMEOUT,
                timestamp=datetime.now(),
                execution_time=execution_time,
                findings=[],
                summary={},
                error="Analysis timeout after 5 minutes"
            )

        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"Semgrep analysis failed: {e}", exc_info=True)

            return AnalysisResult(
                agent=self.name,
                version=self.version,
                status=AnalysisStatus.ERROR,
                timestamp=datetime.now(),
                execution_time=execution_time,
                findings=[],
                summary={},
                error=str(e)
            )

    def _parse_semgrep_results(self, data: dict) -> List[Finding]:
        """Parse Semgrep JSON output into Finding objects"""
        findings = []

        for result in data.get('results', []):
            # Map Semgrep severity to MIESC severity
            semgrep_severity = result.get('extra', {}).get('severity', 'INFO')
            severity = self._map_severity(semgrep_severity)

            # Extract location
            start_line = result.get('start', {}).get('line', 0)
            end_line = result.get('end', {}).get('line', 0)
            file_path = result.get('path', 'unknown')
            location = f"{file_path}:{start_line}"
            if end_line != start_line:
                location += f"-{end_line}"

            # Extract metadata
            metadata = result.get('extra', {}).get('metadata', {})

            finding = Finding(
                type=result.get('check_id', 'unknown'),
                severity=severity,
                location=location,
                message=result.get('extra', {}).get('message', ''),
                description=metadata.get('description'),
                recommendation=metadata.get('fix'),
                reference=metadata.get('references', [None])[0] if metadata.get('references') else None,
                confidence='high',
                code_snippet=result.get('extra', {}).get('lines')
            )

            findings.append(finding)

        return findings

    def _map_severity(self, semgrep_severity: str) -> FindingSeverity:
        """Map Semgrep severity to MIESC FindingSeverity"""
        severity_map = {
            'ERROR': FindingSeverity.HIGH,
            'WARNING': FindingSeverity.MEDIUM,
            'INFO': FindingSeverity.INFO
        }
        return severity_map.get(semgrep_severity.upper(), FindingSeverity.INFO)

    def _calculate_summary(self, findings: List[Finding]) -> dict:
        """Calculate summary statistics"""
        summary = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }

        for finding in findings:
            severity = finding.severity.value
            summary[severity] = summary.get(severity, 0) + 1

        summary['total'] = len(findings)
        return summary

    def get_config_schema(self) -> dict:
        """Configuration schema for Semgrep agent"""
        return {
            "type": "object",
            "properties": {
                "config": {
                    "type": "string",
                    "description": "Semgrep configuration (auto, p/security, etc.)",
                    "default": "auto"
                },
                "rules": {
                    "type": "string",
                    "description": "Path to custom rules file"
                }
            }
        }


# Example: How to test this agent standalone
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Create agent instance
    agent = SemgrepAgent()

    # Check availability
    print(f"Agent: {agent.name} v{agent.version}")
    print(f"Available: {agent.is_available()}")

    if agent.is_available():
        # Test with a file
        test_file = "examples/reentrancy_simple.sol"
        if Path(test_file).exists():
            print(f"\nAnalyzing: {test_file}")
            result = agent.analyze(test_file)

            print(f"Status: {result.status.value}")
            print(f"Findings: {len(result.findings)}")
            print(f"Execution time: {result.execution_time:.2f}s")

            for finding in result.findings[:3]:  # Show first 3
                print(f"\n- {finding.type}")
                print(f"  Severity: {finding.severity.value}")
                print(f"  Location: {finding.location}")
                print(f"  Message: {finding.message}")
