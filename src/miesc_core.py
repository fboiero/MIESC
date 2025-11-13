"""
MIESC Core - Multi-layer Intelligent Evaluation for Smart Contracts

This module orchestrates multi-tool security scanning, result normalization,
and integration with the MCP architecture for collaborative cyberdefense.

Scientific Context:
- Implements defense-in-depth strategy (Saltzer & Schroeder, 1975)
- Follows NIST CSF Detect function
- Integrates with MCP for multi-agent interoperability

Author: Fernando Boiero
Institution: Universidad de la Defensa Nacional (UNDEF) - IUA Córdoba
Thesis: Master's in Cyberdefense
"""

import os
import json
import logging
import subprocess
import hashlib
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
                logger.warning(f"Slither exited with code {result.returncode}")
                return []

            # Parse JSON output
            output = json.loads(result.stdout) if result.stdout else {}
            results = output.get('results', {}).get('detectors', [])

            return [self._normalize_slither(r) for r in results]

        except subprocess.TimeoutExpired:
            logger.error(f"Slither timed out after {self.timeout}s")
            return []
        except Exception as e:
            logger.error(f"Slither execution error: {e}")
            return []

    def _normalize_slither(self, raw: Dict[str, Any]) -> ScanResult:
        """Normalize Slither output to ScanResult"""
        # Map Slither impact to MIESC severity
        impact_map = {
            'Critical': 'Critical',
            'High': 'High',
            'Medium': 'Medium',
            'Low': 'Low',
            'Informational': 'Info'
        }

        location = {}
        if raw.get('elements'):
            elem = raw['elements'][0]
            location = {
                'file': elem.get('source_mapping', {}).get('filename_short', ''),
                'line': elem.get('source_mapping', {}).get('lines', [0])[0] if elem.get('source_mapping', {}).get('lines') else 0,
                'function': elem.get('name', '')
            }

        return ScanResult(
            tool='slither',
            vulnerability_type=raw.get('check', 'unknown'),
            severity=impact_map.get(raw.get('impact', 'Low'), 'Low'),
            location=location,
            description=raw.get('description', ''),
            confidence=raw.get('confidence', 'Medium'),
            swc_id=self._map_to_swc(raw.get('check')),
            owasp_category=self._map_to_owasp(raw.get('check')),
            raw_output=raw
        )

    def _run_mythril(self, contract_path: str, **kwargs) -> List[ScanResult]:
        """Execute Mythril symbolic analysis"""
        try:
            cmd = [
                'myth', 'analyze', contract_path,
                '--json-output', '-',
                '--execution-timeout', str(self.timeout)
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout + 10
            )

            if not result.stdout:
                return []

            output = json.loads(result.stdout)
            issues = output.get('issues', [])

            return [self._normalize_mythril(issue) for issue in issues]

        except Exception as e:
            logger.error(f"Mythril execution error: {e}")
            return []

    def _normalize_mythril(self, raw: Dict[str, Any]) -> ScanResult:
        """Normalize Mythril output to ScanResult"""
        severity_map = {
            'High': 'Critical',
            'Medium': 'High',
            'Low': 'Medium'
        }

        return ScanResult(
            tool='mythril',
            vulnerability_type=raw.get('title', 'unknown'),
            severity=severity_map.get(raw.get('severity', 'Low'), 'Medium'),
            location={
                'file': raw.get('filename', ''),
                'line': raw.get('lineno', 0),
                'function': raw.get('function', '')
            },
            description=raw.get('description', ''),
            confidence='High',  # Mythril has high confidence
            swc_id=raw.get('swc-id', ''),
            cwe_id=raw.get('cwe-id', ''),
            raw_output=raw
        )

    def _run_echidna(self, contract_path: str, **kwargs) -> List[ScanResult]:
        """Execute Echidna fuzzing (requires config file)"""
        # Echidna requires specific setup - placeholder for now
        logger.info("Echidna execution not yet implemented")
        return []

    def _run_aderyn(self, contract_path: str, **kwargs) -> List[ScanResult]:
        """Execute Aderyn static analysis"""
        try:
            cmd = ['aderyn', contract_path, '--json']

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            if not result.stdout:
                return []

            output = json.loads(result.stdout)
            findings = output.get('findings', [])

            return [self._normalize_aderyn(f) for f in findings]

        except Exception as e:
            logger.error(f"Aderyn execution error: {e}")
            return []

    def _normalize_aderyn(self, raw: Dict[str, Any]) -> ScanResult:
        """Normalize Aderyn output to ScanResult"""
        return ScanResult(
            tool='aderyn',
            vulnerability_type=raw.get('type', 'unknown'),
            severity=raw.get('severity', 'Medium'),
            location={
                'file': raw.get('file', ''),
                'line': raw.get('line', 0),
                'function': ''
            },
            description=raw.get('message', ''),
            confidence='High',
            raw_output=raw
        )

    def _run_solhint(self, contract_path: str, **kwargs) -> List[ScanResult]:
        """Execute Solhint linter"""
        try:
            cmd = ['solhint', contract_path, '--formatter', 'json']

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            if not result.stdout:
                return []

            output = json.loads(result.stdout)

            return [self._normalize_solhint(item) for item in output]

        except Exception as e:
            logger.error(f"Solhint execution error: {e}")
            return []

    def _normalize_solhint(self, raw: Dict[str, Any]) -> ScanResult:
        """Normalize Solhint output to ScanResult"""
        severity_map = {
            'error': 'High',
            'warning': 'Medium',
            'info': 'Low'
        }

        return ScanResult(
            tool='solhint',
            vulnerability_type=raw.get('ruleId', 'unknown'),
            severity=severity_map.get(raw.get('severity', 'info'), 'Low'),
            location={
                'file': raw.get('filePath', ''),
                'line': raw.get('line', 0),
                'function': ''
            },
            description=raw.get('message', ''),
            confidence='Medium',
            raw_output=raw
        )

    @staticmethod
    def _map_to_swc(check_name: Optional[str]) -> Optional[str]:
        """Map vulnerability to SWC ID"""
        swc_mapping = {
            'reentrancy-eth': 'SWC-107',
            'reentrancy-no-eth': 'SWC-107',
            'unchecked-send': 'SWC-104',
            'tx-origin': 'SWC-115',
            'timestamp': 'SWC-116',
            'uninitialized-state': 'SWC-109',
            'locked-ether': 'SWC-132',
            'arbitrary-send': 'SWC-105',
            'suicidal': 'SWC-106',
            'delegatecall': 'SWC-112',
            'controlled-delegatecall': 'SWC-112'
        }
        return swc_mapping.get(check_name, None)

    @staticmethod
    def _map_to_owasp(check_name: Optional[str]) -> Optional[str]:
        """Map vulnerability to OWASP SC Top 10"""
        owasp_mapping = {
            'reentrancy-eth': 'SC01-Reentrancy',
            'reentrancy-no-eth': 'SC01-Reentrancy',
            'unchecked-send': 'SC04-Unchecked-Call',
            'tx-origin': 'SC02-Access-Control',
            'timestamp': 'SC07-Bad-Randomness',
            'uninitialized-state': 'SC06-Uninitialized-Storage',
            'arbitrary-send': 'SC02-Access-Control',
            'suicidal': 'SC02-Access-Control',
            'delegatecall': 'SC05-Delegatecall',
            'controlled-delegatecall': 'SC05-Delegatecall'
        }
        return owasp_mapping.get(check_name, None)


class MIESCCore:
    """
    Main MIESC orchestration engine

    Coordinates multi-tool scanning, result aggregation, and MCP integration
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize MIESC Core

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.executor = ToolExecutor(timeout=self.config.get('timeout', 300))
        self.results_cache: Dict[str, List[ScanResult]] = {}

    def scan_contract(
        self,
        contract_path: str,
        tools: Optional[List[str]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Scan contract with multiple security tools

        Args:
            contract_path: Path to Solidity contract
            tools: List of tools to use (default: all available)
            **kwargs: Additional parameters

        Returns:
            Dictionary with aggregated scan results
        """
        if not os.path.exists(contract_path):
            raise FileNotFoundError(f"Contract not found: {contract_path}")

        # Default to all tools if not specified
        if tools is None:
            tools = ['slither', 'mythril', 'aderyn', 'solhint']

        logger.info(f"Starting MIESC scan of {contract_path} with tools: {tools}")

        # Calculate contract hash for caching
        contract_hash = self._hash_file(contract_path)

        # Execute all tools
        all_results: List[ScanResult] = []
        tool_results: Dict[str, List[ScanResult]] = {}
        execution_times: Dict[str, float] = {}

        for tool in tools:
            start_time = datetime.utcnow()
            results = self.executor.execute_tool(tool, contract_path, **kwargs)
            end_time = datetime.utcnow()

            execution_times[tool] = (end_time - start_time).total_seconds()
            tool_results[tool] = results
            all_results.extend(results)

        # Aggregate results
        aggregated = {
            'contract_path': contract_path,
            'contract_hash': contract_hash,
            'scan_timestamp': datetime.utcnow().isoformat() + 'Z',
            'tools_executed': tools,
            'execution_times': execution_times,
            'total_findings': len(all_results),
            'findings_by_tool': {t: len(r) for t, r in tool_results.items()},
            'findings_by_severity': self._count_by_severity(all_results),
            'raw_findings': [r.to_dict() for r in all_results],
            'metadata': {
                'miesc_version': '3.0.0',
                'protocol': 'mcp/1.0'
            }
        }

        # Cache results
        self.results_cache[contract_hash] = all_results

        logger.info(
            f"MIESC scan complete: {len(all_results)} findings "
            f"({aggregated['findings_by_severity']})"
        )

        return aggregated

    def scan_directory(
        self,
        directory: str,
        tools: Optional[List[str]] = None,
        **kwargs
    ) -> List[Dict[str, Any]]:
        """
        Scan all Solidity files in a directory

        Args:
            directory: Path to directory
            tools: List of tools to use
            **kwargs: Additional parameters

        Returns:
            List of scan results for each contract
        """
        solidity_files = list(Path(directory).rglob('*.sol'))
        logger.info(f"Found {len(solidity_files)} Solidity files in {directory}")

        results = []
        for contract_path in solidity_files:
            try:
                result = self.scan_contract(str(contract_path), tools, **kwargs)
                results.append(result)
            except Exception as e:
                logger.error(f"Error scanning {contract_path}: {e}")

        return results

    @staticmethod
    def _hash_file(filepath: str) -> str:
        """Calculate SHA256 hash of file"""
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        return sha256.hexdigest()

    @staticmethod
    def _count_by_severity(results: List[ScanResult]) -> Dict[str, int]:
        """Count findings by severity"""
        counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        for result in results:
            if result.severity in counts:
                counts[result.severity] += 1
        return counts

    def export_results(self, results: Dict[str, Any], output_path: str) -> None:
        """
        Export scan results to JSON file

        Args:
            results: Scan results dictionary
            output_path: Path to output JSON file
        """
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)
        logger.info(f"Results exported to {output_path}")


# Example usage
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Initialize MIESC
    miesc = MIESCCore()

    # Example scan
    # results = miesc.scan_contract('examples/reentrancy_simple.sol')
    # print(json.dumps(results, indent=2))
