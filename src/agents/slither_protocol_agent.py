"""
Slither Agent - MIESC Protocol Implementation
==============================================

Wrapper for Slither static analysis tool using MIESC Agent Protocol.
"""

import logging
from typing import List
from datetime import datetime
import time
from pathlib import Path

from src.core.agent_protocol import (
    SecurityAgent,
    AgentCapability,
    AgentSpeed,
    AnalysisResult,
    AnalysisStatus,
    Finding,
    FindingSeverity
)
from src.slither_tool import run_slither_analysis

logger = logging.getLogger(__name__)


class SlitherAgent(SecurityAgent):
    """
    Slither static analysis agent.

    Slither is a Solidity static analysis framework with 87+ detectors.
    Developed by Trail of Bits.
    """

    @property
    def name(self) -> str:
        return "slither"

    @property
    def version(self) -> str:
        return "0.10.3"

    @property
    def description(self) -> str:
        return "Static analysis framework with 87+ detectors for Solidity"

    @property
    def author(self) -> str:
        return "Trail of Bits"

    @property
    def license(self) -> str:
        return "AGPL-3.0"

    @property
    def capabilities(self) -> List[AgentCapability]:
        return [
            AgentCapability.STATIC_ANALYSIS,
            AgentCapability.PATTERN_MATCHING,
            AgentCapability.CODE_QUALITY
        ]

    @property
    def supported_languages(self) -> List[str]:
        return ["solidity"]

    @property
    def cost(self) -> float:
        return 0.0  # Free

    @property
    def speed(self) -> AgentSpeed:
        return AgentSpeed.FAST

    @property
    def homepage(self) -> str:
        return "https://github.com/crytic/slither"

    @property
    def repository(self) -> str:
        return "https://github.com/crytic/slither"

    @property
    def documentation(self) -> str:
        return "https://github.com/crytic/slither/wiki"

    @property
    def installation(self) -> str:
        return "pip install slither-analyzer"

    def is_available(self) -> bool:
        """Check if Slither is installed and available"""
        import shutil
        return shutil.which('slither') is not None

    def can_analyze(self, file_path: str) -> bool:
        """Check if file is a Solidity contract"""
        path = Path(file_path)
        return path.suffix == '.sol' and path.exists()

    def analyze(self, contract: str, **kwargs) -> AnalysisResult:
        """
        Run Slither analysis on contract.

        Args:
            contract: Path to Solidity contract
            **kwargs: Additional arguments (ignored)

        Returns:
            AnalysisResult with findings
        """
        start_time = time.time()

        try:
            logger.info(f"Running Slither analysis on {contract}")

            # Run Slither using existing tool
            slither_output = run_slither_analysis(contract)

            # Parse Slither output to extract findings
            findings = self._parse_slither_output(slither_output)

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
                summary=summary
            )

        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"Slither analysis failed: {e}", exc_info=True)

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

    def _parse_slither_output(self, output: str) -> List[Finding]:
        """Parse Slither output text into Finding objects"""
        findings = []

        # Simple parser for Slither output
        # Format: "Contract.function (file.sol#line): Description"
        lines = output.split('\n')

        current_finding = {}
        for line in lines:
            line = line.strip()

            # Skip empty lines
            if not line:
                if current_finding:
                    findings.append(self._create_finding(current_finding))
                    current_finding = {}
                continue

            # Detect severity markers
            if 'Impact:' in line:
                impact = line.split('Impact:')[1].strip()
                current_finding['severity'] = self._map_severity(impact)
                current_finding['impact'] = impact

            elif 'Confidence:' in line:
                confidence = line.split('Confidence:')[1].strip()
                current_finding['confidence'] = confidence

            elif 'Reference:' in line:
                reference = line.split('Reference:')[1].strip()
                current_finding['reference'] = reference

            elif '.sol' in line and '(' in line:
                # Location line
                current_finding['location'] = line
                current_finding['message'] = line

            elif line and not current_finding.get('type'):
                # First non-empty line is usually the vulnerability type
                current_finding['type'] = line

        # Add last finding
        if current_finding:
            findings.append(self._create_finding(current_finding))

        return findings

    def _create_finding(self, finding_data: dict) -> Finding:
        """Create a Finding object from parsed data"""
        return Finding(
            type=finding_data.get('type', 'Unknown'),
            severity=finding_data.get('severity', FindingSeverity.INFO),
            location=finding_data.get('location', 'Unknown'),
            message=finding_data.get('message', ''),
            description=finding_data.get('description'),
            recommendation=finding_data.get('recommendation'),
            reference=finding_data.get('reference'),
            confidence=finding_data.get('confidence'),
            impact=finding_data.get('impact')
        )

    def _map_severity(self, impact: str) -> FindingSeverity:
        """Map Slither impact levels to FindingSeverity"""
        impact_lower = impact.lower()

        if 'high' in impact_lower or 'critical' in impact_lower:
            return FindingSeverity.HIGH
        elif 'medium' in impact_lower:
            return FindingSeverity.MEDIUM
        elif 'low' in impact_lower:
            return FindingSeverity.LOW
        else:
            return FindingSeverity.INFO

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
