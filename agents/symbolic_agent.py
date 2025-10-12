"""
Symbolic Execution Agent for MCP Architecture

Wraps Layer 4 tools: Mythril, Manticore
Publishes symbolic analysis results and execution paths to Context Bus
"""
import json
import logging
import subprocess
from typing import Dict, Any, List
from pathlib import Path
from agents.base_agent import BaseAgent

logger = logging.getLogger(__name__)


class SymbolicAgent(BaseAgent):
    """
    Agent for symbolic execution (Layer 4 - MIESC)

    Capabilities:
    - Path exploration (Mythril)
    - Automated exploit generation (Manticore)
    - Constraint solving
    - Deep vulnerability discovery

    Published Context Types:
    - "symbolic_findings": Unified findings from symbolic tools
    - "mythril_results": Mythril analysis results
    - "manticore_results": Manticore execution traces
    """

    def __init__(self):
        super().__init__(
            agent_name="SymbolicAgent",
            capabilities=[
                "symbolic_execution",
                "path_exploration",
                "constraint_solving",
                "exploit_generation"
            ],
            agent_type="symbolic"
        )

    def get_context_types(self) -> List[str]:
        return [
            "symbolic_findings",
            "mythril_results",
            "manticore_results"
        ]

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Run symbolic execution tools on contract

        Args:
            contract_path: Path to Solidity contract
            **kwargs: Optional parameters
                - max_depth: Maximum symbolic execution depth
                - timeout: Timeout per tool in seconds (default: 900)
                - solc_version: Solidity compiler version

        Returns:
            Dictionary with results from symbolic tools
        """
        results = {
            "symbolic_findings": [],
            "mythril_results": {},
            "manticore_results": {}
        }

        max_depth = kwargs.get("max_depth", 128)
        timeout = kwargs.get("timeout", 900)  # 15 minutes default
        solc_version = kwargs.get("solc_version", "0.8.0")

        # Run Mythril
        logger.info(f"SymbolicAgent: Running Mythril on {contract_path}")
        mythril_data = self._run_mythril(contract_path, timeout, solc_version)
        results["mythril_results"] = mythril_data

        # Run Manticore
        logger.info(f"SymbolicAgent: Running Manticore on {contract_path}")
        manticore_data = self._run_manticore(contract_path, max_depth, timeout)
        results["manticore_results"] = manticore_data

        # Aggregate findings
        results["symbolic_findings"] = self._aggregate_findings(
            mythril_data, manticore_data
        )

        return results

    def _run_mythril(self, contract_path: str, timeout: int,
                     solc_version: str) -> Dict[str, Any]:
        """
        Execute Mythril symbolic analysis

        Returns:
            Dictionary with vulnerabilities found
        """
        try:
            cmd = [
                "myth",
                "analyze",
                contract_path,
                "--solv", solc_version,
                "-o", "json"
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            # Parse JSON output
            vulnerabilities = []
            try:
                data = json.loads(result.stdout) if result.stdout else {}

                if "issues" in data:
                    for issue in data["issues"]:
                        vulnerabilities.append({
                            "swc_id": issue.get("swc-id", "UNKNOWN"),
                            "title": issue.get("title", ""),
                            "severity": issue.get("severity", "Unknown"),
                            "description": issue.get("description", ""),
                            "location": {
                                "file": issue.get("filename", "unknown"),
                                "line": issue.get("lineno", 0),
                                "function": issue.get("function", "unknown")
                            },
                            "transaction_sequence": issue.get("debug", "")
                        })

            except json.JSONDecodeError:
                logger.warning("Failed to parse Mythril JSON output")

            return {
                "tool": "Mythril",
                "vulnerabilities": vulnerabilities,
                "total_issues": len(vulnerabilities),
                "metadata": {
                    "exit_code": result.returncode,
                    "solc_version": solc_version,
                    "analysis_type": "symbolic_execution"
                }
            }

        except subprocess.TimeoutExpired:
            logger.error(f"Mythril timeout after {timeout} seconds")
            return {"error": "timeout", "vulnerabilities": []}
        except FileNotFoundError:
            logger.warning("Mythril not installed, skipping")
            return {"error": "not_installed", "vulnerabilities": []}
        except Exception as e:
            logger.error(f"Mythril execution error: {e}")
            return {"error": str(e), "vulnerabilities": []}

    def _run_manticore(self, contract_path: str, max_depth: int,
                       timeout: int) -> Dict[str, Any]:
        """
        Execute Manticore symbolic execution with exploit generation

        Returns:
            Dictionary with execution paths and exploits
        """
        try:
            # Manticore is typically used via Python API, but can be called from CLI
            cmd = [
                "manticore",
                contract_path,
                "--max-depth", str(max_depth),
                "--quick-mode"
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            # Parse output
            output = result.stdout
            exploits = []
            paths_explored = 0

            # Extract key information from output
            for line in output.split('\n'):
                if 'explored' in line.lower():
                    try:
                        paths_explored = int(''.join(filter(str.isdigit, line)))
                    except ValueError:
                        pass

                if 'exploit' in line.lower() or 'vulnerable' in line.lower():
                    exploits.append({
                        "type": "potential_exploit",
                        "description": line.strip()
                    })

            return {
                "tool": "Manticore",
                "exploits": exploits,
                "paths_explored": paths_explored,
                "metadata": {
                    "exit_code": result.returncode,
                    "max_depth": max_depth,
                    "analysis_type": "symbolic_execution"
                }
            }

        except subprocess.TimeoutExpired:
            logger.error(f"Manticore timeout after {timeout} seconds")
            return {"error": "timeout", "exploits": []}
        except FileNotFoundError:
            logger.warning("Manticore not installed, skipping")
            return {"error": "not_installed", "exploits": []}
        except Exception as e:
            logger.error(f"Manticore execution error: {e}")
            return {"error": str(e), "exploits": []}

    def _aggregate_findings(self, mythril_data: Dict,
                           manticore_data: Dict) -> List[Dict[str, Any]]:
        """
        Aggregate findings from symbolic tools into unified format

        Returns:
            List of unified findings with OWASP/SWC mapping
        """
        unified = []

        # Add Mythril vulnerabilities
        for vuln in mythril_data.get("vulnerabilities", []):
            unified.append({
                "source": "Mythril",
                "type": "symbolic_vulnerability",
                "id": vuln.get("swc_id", "UNKNOWN"),
                "title": vuln.get("title"),
                "severity": vuln.get("severity"),
                "description": vuln.get("description"),
                "location": vuln.get("location"),
                "transaction_sequence": vuln.get("transaction_sequence"),
                "layer": "symbolic",
                "swc_id": vuln.get("swc_id"),
                "owasp_category": self._map_swc_to_owasp(vuln.get("swc_id")),
                "confidence": "High"  # Mythril has high confidence
            })

        # Add Manticore exploits
        for exploit in manticore_data.get("exploits", []):
            unified.append({
                "source": "Manticore",
                "type": "exploit_path",
                "severity": "Critical",
                "description": exploit.get("description"),
                "layer": "symbolic",
                "confidence": "High",
                "exploitable": True
            })

        return unified

    def _map_swc_to_owasp(self, swc_id: str) -> str:
        """
        Map SWC ID to OWASP Smart Contract Top 10 category

        Args:
            swc_id: SWC identifier (e.g., "SWC-107")

        Returns:
            OWASP category string
        """
        mapping = {
            "SWC-107": "SC01-Reentrancy",
            "SWC-101": "SC03-Arithmetic",
            "SWC-104": "SC04-Unchecked-Calls",
            "SWC-105": "SC02-Access-Control",
            "SWC-106": "SC02-Access-Control",
            "SWC-110": "SC05-DoS",
            "SWC-113": "SC05-DoS",
            "SWC-114": "SC07-Front-Running",
            "SWC-115": "SC02-Access-Control",
            "SWC-116": "SC08-Time-Manipulation",
            "SWC-120": "SC06-Bad-Randomness",
            "SWC-128": "SC05-DoS"
        }
        return mapping.get(swc_id, "SC10-Unknown-Unknowns")
