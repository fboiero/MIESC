"""
Mythril Symbolic Execution Adapter - MIESC Phase 3
==================================================

Mythril is a security analysis tool for Ethereum smart contracts using symbolic execution,
taint analysis, and control flow checking to detect security vulnerabilities.

Tool: Mythril by ConsenSys (https://github.com/ConsenSys/mythril)
Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: November 11, 2025
Version: 1.0.0
"""

from src.core.tool_protocol import (
    ToolAdapter, ToolMetadata, ToolStatus, ToolCategory, ToolCapability
)
from typing import Dict, Any, List, Optional
import subprocess
import json
import logging
import time
from pathlib import Path

# OpenLLaMA integration for intelligent post-processing
from src.llm import enhance_findings_with_llm

logger = logging.getLogger(__name__)


class MythrilAdapter(ToolAdapter):
    """
    Mythril Symbolic Execution Adapter for MIESC Layer 3.

    Mythril is one of the most powerful symbolic execution tools for Ethereum:
    - 88+ vulnerability detection patterns
    - Symbolic execution engine
    - Taint analysis
    - Control flow analysis
    - SMT solver integration (Z3)
    - SWC compliance

    Expected Impact (2025 Roadmap):
    - +35% vulnerability detection for complex logic bugs
    - Detects reentrancy, integer overflow, access control issues
    - High precision on state-dependent vulnerabilities
    - Execution time: ~30-120s (symbolic analysis intensive)
    """

    # Severity mapping from Mythril to MIESC standard
    SEVERITY_MAP = {
        "High": "High",
        "Medium": "Medium",
        "Low": "Low"
    }

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="mythril",
            version="1.0.0",
            category=ToolCategory.SYMBOLIC_EXECUTION,
            author="ConsenSys (Adapter by Fernando Boiero)",
            license="MIT",
            homepage="https://github.com/ConsenSys/mythril",
            repository="https://github.com/ConsenSys/mythril",
            documentation="https://mythril-classic.readthedocs.io/",
            installation_cmd="pip install mythril",
            capabilities=[
                ToolCapability(
                    name="symbolic_execution",
                    description="Symbolic execution and taint analysis for Solidity (88+ detectors)",
                    supported_languages=["solidity"],
                    detection_types=[
                        "reentrancy",
                        "integer_overflow_underflow",
                        "unprotected_ether_withdrawal",
                        "unprotected_selfdestruct",
                        "delegatecall_to_untrusted_contract",
                        "state_access_after_external_call",
                        "assert_violation",
                        "unchecked_return_value",
                        "arbitrary_storage_write",
                        "arbitrary_jump",
                        "external_call_to_fixed_address",
                        "dos_via_gas_limit",
                        "transaction_order_dependence",
                        "timestamp_dependence",
                        "weak_randomness",
                        "multiple_sends",
                        "tx_origin_usage",
                        "uninitialized_storage_pointer",
                        "shadowing_state_variables",
                        "requirements_violation"
                    ]
                )
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True  # DPGA compliance - graceful degradation
        )

    def is_available(self) -> ToolStatus:
        """
        Check if Mythril CLI is available and working.

        Returns:
            ToolStatus.AVAILABLE if mythril is installed and working
            ToolStatus.NOT_INSTALLED otherwise
        """
        try:
            result = subprocess.run(
                ["myth", "version"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                version = result.stdout.strip()
                logger.info(f"Mythril available: {version}")
                return ToolStatus.AVAILABLE
            else:
                logger.warning("Mythril command found but returned error")
                return ToolStatus.CONFIGURATION_ERROR

        except FileNotFoundError:
            logger.info("Mythril not installed (optional tool)")
            return ToolStatus.NOT_INSTALLED
        except subprocess.TimeoutExpired:
            logger.warning("Mythril version check timed out")
            return ToolStatus.CONFIGURATION_ERROR
        except Exception as e:
            logger.error(f"Error checking Mythril availability: {e}")
            return ToolStatus.CONFIGURATION_ERROR

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Execute Mythril symbolic execution analysis on the contract.

        Args:
            contract_path: Path to Solidity file
            **kwargs:
                - output_path: Path for JSON output (default: temp file)
                - timeout: Analysis timeout in seconds (default: 600)
                - execution_timeout: Symbolic execution timeout (default: 300)
                - max_depth: Maximum recursion depth (default: 22)
                - solver_timeout: SMT solver timeout (default: 100000)

        Returns:
            Normalized results dictionary with:
            {
                "tool": "mythril",
                "version": "1.0.0",
                "status": "success" | "error",
                "findings": List[Dict],
                "metadata": Dict,
                "execution_time": float,
                "error": Optional[str]
            }
        """
        start_time = time.time()

        # Check availability first
        status = self.is_available()
        if status != ToolStatus.AVAILABLE:
            return {
                "tool": "mythril",
                "version": "1.0.0",
                "status": "error",
                "findings": [],
                "metadata": {"tool_status": status.value},
                "execution_time": time.time() - start_time,
                "error": f"Mythril not available: {status.value}"
            }

        try:
            # Prepare parameters
            output_path = kwargs.get("output_path", "/tmp/mythril_output.json")
            timeout = kwargs.get("timeout", 600)
            execution_timeout = kwargs.get("execution_timeout", 300)
            max_depth = kwargs.get("max_depth", 22)
            solver_timeout = kwargs.get("solver_timeout", 100000)

            # Build command
            cmd = [
                "myth", "analyze",
                contract_path,
                "-o", "json",
                "--execution-timeout", str(execution_timeout),
                "--max-depth", str(max_depth),
                "--solver-timeout", str(solver_timeout)
            ]

            logger.info(f"Running Mythril analysis: {' '.join(cmd)}")

            # Execute Mythril
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            execution_time = time.time() - start_time

            # Parse JSON output
            try:
                if result.stdout:
                    raw_output = json.loads(result.stdout)
                else:
                    # Mythril may output to stderr on error
                    logger.warning(f"Mythril stderr: {result.stderr}")
                    raw_output = {"issues": []}
            except json.JSONDecodeError:
                logger.error(f"Failed to parse Mythril JSON output: {result.stdout}")
                return {
                    "tool": "mythril",
                    "version": "1.0.0",
                    "status": "error",
                    "findings": [],
                    "metadata": {"parse_error": "Invalid JSON"},
                    "execution_time": execution_time,
                    "error": "Failed to parse Mythril output"
                }

            # Normalize findings
            findings = self.normalize_findings(raw_output)

            # Read contract code for LLM context
            try:
                with open(contract_path, 'r', encoding='utf-8') as f:
                    contract_code = f.read()
            except Exception as e:
                logger.warning(f"Could not read contract for LLM enhancement: {e}")
                contract_code = ""

            # Enhance findings with OpenLLaMA insights (if available)
            if contract_code and findings:
                try:
                    findings = enhance_findings_with_llm(
                        findings=findings,
                        contract_code=contract_code,
                        adapter_name="mythril"
                    )
                    logger.info(f"OpenLLaMA: Enhanced Mythril findings with AI insights")
                except Exception as e:
                    logger.debug(f"OpenLLaMA enhancement skipped: {e}")

            metadata = {
                "contract_analyzed": contract_path,
                "raw_findings_count": len(raw_output.get("issues", [])),
                "normalized_findings_count": len(findings),
                "execution_timeout": execution_timeout,
                "max_depth": max_depth,
                "solver_timeout": solver_timeout
            }

            logger.info(
                f"Mythril analysis completed: {len(findings)} findings in {execution_time:.2f}s"
            )

            return {
                "tool": "mythril",
                "version": "1.0.0",
                "status": "success",
                "findings": findings,
                "metadata": metadata,
                "execution_time": execution_time
            }

        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            logger.error(f"Mythril analysis timed out after {timeout}s")
            return {
                "tool": "mythril",
                "version": "1.0.0",
                "status": "error",
                "findings": [],
                "metadata": {"timeout": timeout},
                "execution_time": execution_time,
                "error": f"Analysis timed out after {timeout} seconds"
            }

        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"Unexpected error during Mythril analysis: {e}", exc_info=True)
            return {
                "tool": "mythril",
                "version": "1.0.0",
                "status": "error",
                "findings": [],
                "metadata": {"exception": str(e)},
                "execution_time": execution_time,
                "error": f"Unexpected error: {e}"
            }

    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        """
        Normalize Mythril findings to MIESC standard format.

        Args:
            raw_output: Parsed JSON from Mythril

        Returns:
            List of normalized findings
        """
        normalized = []

        try:
            raw_issues = raw_output.get("issues", [])

            for idx, issue in enumerate(raw_issues):
                # Extract core information
                swc_id = issue.get("swc-id", "")
                severity = issue.get("severity", "Medium")
                title = issue.get("title", "Unknown Issue")
                description = issue.get("description", "")

                # Extract location info
                locations = issue.get("locations", [])
                location_info = {}

                if locations and len(locations) > 0:
                    first_location = locations[0]
                    source_map = first_location.get("sourceMap", "")
                    location_info = {
                        "file": contract_path if 'contract_path' in locals() else "unknown",
                        "line": self._extract_line_from_sourcemap(source_map),
                        "function": issue.get("function", "unknown")
                    }
                else:
                    location_info = {
                        "file": "unknown",
                        "line": 0,
                        "function": "unknown"
                    }

                # Map severity
                mapped_severity = self.SEVERITY_MAP.get(severity, "Medium")

                # Build normalized finding
                normalized_finding = {
                    "id": f"mythril-{swc_id}-{idx}",
                    "type": title,
                    "severity": mapped_severity,
                    "confidence": 0.85,  # Mythril has high confidence
                    "location": location_info,
                    "message": title,
                    "description": description,
                    "recommendation": self._get_recommendation(swc_id),
                    "swc_id": f"SWC-{swc_id}" if swc_id else None,
                    "cwe_id": None,
                    "owasp_category": self._map_to_owasp(swc_id)
                }

                normalized.append(normalized_finding)

        except Exception as e:
            logger.error(f"Error normalizing Mythril findings: {e}", exc_info=True)

        return normalized

    def _extract_line_from_sourcemap(self, source_map: str) -> int:
        """Extract line number from Mythril source map."""
        try:
            # Source map format: "start:length:file"
            parts = source_map.split(":")
            if len(parts) >= 1:
                return int(parts[0])
        except:
            pass
        return 0

    def _get_recommendation(self, swc_id: str) -> str:
        """Get recommendation based on SWC ID."""
        recommendations = {
            "107": "Use the checks-effects-interactions pattern or ReentrancyGuard",
            "101": "Use SafeMath library or Solidity 0.8+ with built-in overflow checks",
            "105": "Implement proper access control for Ether withdrawal functions",
            "106": "Protect selfdestruct with multi-sig or DAO governance",
            "112": "Avoid delegatecall to untrusted contracts or use a whitelist",
            "115": "Use msg.sender instead of tx.origin for authentication",
            "116": "Do not rely on block.timestamp for critical logic",
            "120": "Use Chainlink VRF for random number generation",
            "104": "Check return values of external calls"
        }
        return recommendations.get(swc_id, "Review and fix the vulnerability")

    def _map_to_owasp(self, swc_id: str) -> Optional[str]:
        """Map SWC ID to OWASP Smart Contract Top 10 (2025)."""
        owasp_mapping = {
            "107": "SC01: Reentrancy",
            "101": "SC03: Arithmetic Issues",
            "105": "SC02: Access Control",
            "106": "SC02: Access Control",
            "112": "SC07: Unprotected Delegatecall",
            "115": "SC08: Bad Randomness / Front-Running",
            "116": "SC08: Bad Randomness / Front-Running",
            "120": "SC08: Bad Randomness / Front-Running",
            "104": "SC04: Unchecked Return Values"
        }
        return owasp_mapping.get(swc_id, None)

    def can_analyze(self, contract_path: str) -> bool:
        """Check if Mythril can analyze the given contract."""
        path = Path(contract_path)

        # Mythril analyzes .sol files
        if path.is_file():
            return path.suffix == '.sol'

        return False

    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration for Mythril."""
        return {
            "timeout": 600,
            "execution_timeout": 300,
            "max_depth": 22,
            "solver_timeout": 100000,
            "output_format": "json"
        }


# Export for registry
__all__ = ["MythrilAdapter"]
