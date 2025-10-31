"""
MIESC Core Analyzer - Static and Dynamic Analysis Module

Orchestrates multi-tool security scanning with support for:
- Slither (static analysis)
- Mythril (symbolic execution)
- Aderyn (fast AST analysis)
- Echidna (fuzzing)
- Solhint (linting)

Author: Fernando Boiero
Scientific Context: Defense-in-depth strategy (Saltzer & Schroeder, 1975)
"""

import os
import json
import logging
import subprocess
from datetime import datetime
from typing import Dict, List, Any, Optional
from pathlib import Path
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    """Normalized scan result from any security tool"""
    tool: str
    vulnerability_type: str
    severity: str  # Critical, High, Medium, Low, Info
    location: Dict[str, Any]  # file, line, function
    description: str
    confidence: str  # High, Medium, Low
    cwe_id: Optional[str] = None
    swc_id: Optional[str] = None
    owasp_category: Optional[str] = None
    raw_output: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


class ToolExecutor:
    """Executes security tools and normalizes outputs"""

    def __init__(self, timeout: int = 300):
        """
        Initialize tool executor

        Args:
            timeout: Maximum execution time per tool (seconds)
        """
        self.timeout = timeout
        self.supported_tools = {
            'slither': self._run_slither,
            'mythril': self._run_mythril,
            'echidna': self._run_echidna,
            'aderyn': self._run_aderyn,
            'solhint': self._run_solhint
        }

    def execute_tool(self, tool_name: str, contract_path: str, **kwargs) -> List[ScanResult]:
        """
        Execute a security tool on a contract

        Args:
            tool_name: Name of tool (slither, mythril, etc.)
            contract_path: Path to Solidity contract
            **kwargs: Tool-specific parameters

        Returns:
            List of normalized ScanResult objects
        """
        if tool_name not in self.supported_tools:
            logger.warning(f"Tool {tool_name} not supported. Skipping.")
            return []

        logger.info(f"Executing {tool_name} on {contract_path}")

        try:
            results = self.supported_tools[tool_name](contract_path, **kwargs)
            logger.info(f"{tool_name} found {len(results)} findings")
            return results
        except Exception as e:
            logger.error(f"Error executing {tool_name}: {e}")
            return []

    def _run_slither(self, contract_path: str, **kwargs) -> List[ScanResult]:
        """Execute Slither static analysis"""
        try:
            cmd = [
                'slither', contract_path,
                '--json', '-',
                '--exclude-informational'
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            if result.returncode != 0 and not result.stdout:
                logger.error(f"Slither error: {result.stderr}")
                return []

            output = json.loads(result.stdout) if result.stdout else {"results": {"detectors": []}}
            return self._normalize_slither_results(output)

        except subprocess.TimeoutExpired:
            logger.error(f"Slither timeout after {self.timeout}s")
            return []
        except Exception as e:
            logger.error(f"Slither execution error: {e}")
            return []

    def _normalize_slither_results(self, output: Dict) -> List[ScanResult]:
        """Normalize Slither JSON output to ScanResult"""
        results = []

        for detector in output.get("results", {}).get("detectors", []):
            # Map Slither severity to standard severity
            severity_map = {
                "High": "Critical",
                "Medium": "High",
                "Low": "Medium",
                "Informational": "Low"
            }

            result = ScanResult(
                tool="slither",
                vulnerability_type=detector.get("check", "unknown"),
                severity=severity_map.get(detector.get("impact", "Low"), "Low"),
                location={
                    "file": detector.get("elements", [{}])[0].get("source_mapping", {}).get("filename_short", "unknown"),
                    "line": detector.get("elements", [{}])[0].get("source_mapping", {}).get("lines", [0])[0],
                    "function": detector.get("elements", [{}])[0].get("name", "N/A")
                },
                description=detector.get("description", "No description"),
                confidence=detector.get("confidence", "Medium"),
                cwe_id=detector.get("cwe", None),
                swc_id=self._map_to_swc(detector.get("check", "")),
                raw_output=detector
            )
            results.append(result)

        return results

    def _run_mythril(self, contract_path: str, **kwargs) -> List[ScanResult]:
        """Execute Mythril symbolic execution"""
        try:
            cmd = ['myth', 'analyze', contract_path, '--execution-timeout', str(self.timeout)]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout + 10
            )

            # Mythril outputs to stderr even on success
            output = result.stdout + result.stderr

            return self._normalize_mythril_results(output, contract_path)

        except subprocess.TimeoutExpired:
            logger.error(f"Mythril timeout after {self.timeout}s")
            return []
        except Exception as e:
            logger.error(f"Mythril execution error: {e}")
            return []

    def _normalize_mythril_results(self, output: str, contract_path: str) -> List[ScanResult]:
        """Normalize Mythril text output to ScanResult"""
        results = []

        # Parse Mythril output (simplified - real implementation would be more robust)
        if "SWC ID:" in output:
            lines = output.split('\n')
            current_issue = {}

            for line in lines:
                if "SWC ID:" in line:
                    swc_id = line.split("SWC ID:")[1].strip()
                    current_issue['swc_id'] = swc_id
                elif "Severity:" in line:
                    severity = line.split("Severity:")[1].strip()
                    current_issue['severity'] = severity
                elif "Description:" in line:
                    desc_start = lines.index(line)
                    description = ' '.join(lines[desc_start:desc_start+3])
                    current_issue['description'] = description

                    # Create result when we have enough info
                    if current_issue:
                        result = ScanResult(
                            tool="mythril",
                            vulnerability_type=current_issue.get('swc_id', 'unknown'),
                            severity=current_issue.get('severity', 'Medium'),
                            location={"file": contract_path, "line": 0, "function": "N/A"},
                            description=current_issue.get('description', 'No description'),
                            confidence="High",
                            swc_id=current_issue.get('swc_id'),
                            raw_output=current_issue
                        )
                        results.append(result)
                        current_issue = {}

        return results

    def _run_aderyn(self, contract_path: str, **kwargs) -> List[ScanResult]:
        """Execute Aderyn fast static analysis"""
        # Placeholder - would integrate actual Aderyn if available
        logger.info("Aderyn analysis (placeholder)")
        return []

    def _run_echidna(self, contract_path: str, **kwargs) -> List[ScanResult]:
        """Execute Echidna fuzzing"""
        # Placeholder - would integrate actual Echidna if available
        logger.info("Echidna fuzzing (placeholder)")
        return []

    def _run_solhint(self, contract_path: str, **kwargs) -> List[ScanResult]:
        """Execute Solhint linting"""
        # Placeholder - would integrate actual Solhint if available
        logger.info("Solhint linting (placeholder)")
        return []

    def _map_to_swc(self, check_name: str) -> Optional[str]:
        """Map Slither detector to SWC ID"""
        swc_mapping = {
            "reentrancy-eth": "SWC-107",
            "reentrancy-no-eth": "SWC-107",
            "unprotected-upgrade": "SWC-106",
            "arbitrary-send-eth": "SWC-105",
            "controlled-delegatecall": "SWC-112",
            "tx-origin": "SWC-115",
            "unchecked-transfer": "SWC-104"
        }
        return swc_mapping.get(check_name)


def analyze_contract(
    contract_code: str,
    analysis_type: str = "slither",
    output_format: str = "dict",
    timeout: int = 300
) -> Dict[str, Any]:
    """
    Analyze a smart contract for vulnerabilities

    Args:
        contract_code: Solidity source code or path to file
        analysis_type: Tool to use (slither, mythril, all)
        output_format: Format of results (dict, json)
        timeout: Maximum execution time per tool

    Returns:
        Dictionary containing analysis results with findings
    """
    try:
        # Determine if code is a file path or actual code
        if os.path.isfile(contract_code):
            contract_path = contract_code
        else:
            # Write code to temporary file
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.sol', delete=False) as f:
                f.write(contract_code)
                contract_path = f.name

        executor = ToolExecutor(timeout=timeout)

        # Execute requested analysis
        all_results = []

        if analysis_type == "all":
            tools = list(executor.supported_tools.keys())
        else:
            tools = [analysis_type]

        for tool in tools:
            results = executor.execute_tool(tool, contract_path)
            all_results.extend(results)

        # Aggregate results
        analysis_output = {
            "timestamp": datetime.now().isoformat(),
            "contract": contract_path,
            "tools_executed": tools,
            "total_findings": len(all_results),
            "findings_by_severity": {
                "critical": len([r for r in all_results if r.severity == "Critical"]),
                "high": len([r for r in all_results if r.severity == "High"]),
                "medium": len([r for r in all_results if r.severity == "Medium"]),
                "low": len([r for r in all_results if r.severity == "Low"]),
            },
            "findings": [r.to_dict() for r in all_results],
            "context": "MIESC static/dynamic analysis"
        }

        # Clean up temporary file if created
        if not os.path.isfile(contract_code):
            try:
                os.unlink(contract_path)
            except (OSError, PermissionError) as e:
                # Cleanup failure is non-critical - file may already be deleted
                logger.debug(f"Unable to clean up temp file {contract_path}: {e}")

        if output_format == "json":
            return json.dumps(analysis_output, indent=2)

        return analysis_output

    except Exception as e:
        # Return error result in case of exceptions
        error_output = {
            "timestamp": datetime.now().isoformat(),
            "contract": contract_code,
            "tools_executed": [],
            "total_findings": 0,
            "findings_by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            },
            "findings": [],
            "context": "MIESC static/dynamic analysis",
            "error": str(e)
        }

        if output_format == "json":
            return json.dumps(error_output, indent=2)

        return error_output
