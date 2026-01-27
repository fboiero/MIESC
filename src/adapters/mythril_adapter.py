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

            # Show progress message
            verbose = kwargs.get("verbose", True)
            if verbose:
                print(f"  [Mythril] Starting symbolic execution analysis...")
                print(f"  [Mythril] This may take 2-5 minutes for complex contracts")
                print(f"  [Mythril] Parameters: max_depth={max_depth}, solver_timeout={solver_timeout}")

            # Execute Mythril with streaming output
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )

            stdout_data = []
            stderr_data = []
            last_progress = time.time()
            progress_interval = 15  # Show progress every 15 seconds

            # Read output while process runs
            import select
            while process.poll() is None:
                # Check if we should show progress
                if verbose and (time.time() - last_progress) >= progress_interval:
                    elapsed = int(time.time() - start_time)
                    print(f"  [Mythril] Analysis in progress... ({elapsed}s elapsed)")
                    last_progress = time.time()

                # Non-blocking read of stderr for progress info
                if process.stderr:
                    try:
                        # Use select for non-blocking read on Unix
                        readable, _, _ = select.select([process.stderr], [], [], 0.5)
                        if readable:
                            line = process.stderr.readline()
                            if line:
                                stderr_data.append(line)
                                if verbose and any(kw in line.lower() for kw in ['analyzing', 'solving', 'checking', 'creating']):
                                    print(f"  [Mythril] {line.strip()}")
                    except:
                        time.sleep(0.5)

                # Check timeout
                if (time.time() - start_time) > timeout:
                    process.kill()
                    raise subprocess.TimeoutExpired(cmd, timeout)

            # Get remaining output
            remaining_stdout, remaining_stderr = process.communicate()
            if remaining_stdout:
                stdout_data.append(remaining_stdout)
            if remaining_stderr:
                stderr_data.append(remaining_stderr)

            # Combine output
            class Result:
                def __init__(self, stdout, stderr, returncode):
                    self.stdout = stdout
                    self.stderr = stderr
                    self.returncode = returncode

            result = Result(
                stdout=''.join(stdout_data),
                stderr=''.join(stderr_data),
                returncode=process.returncode
            )

            execution_time = time.time() - start_time

            if verbose:
                print(f"  [Mythril] Analysis completed in {execution_time:.1f}s")

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


# v4.7.0: Cross-validation support for precision improvement
    def validate_finding(
        self,
        source_code: str,
        finding_type: str,
        finding_line: int,
        timeout: int = 60,
    ) -> tuple:
        """
        Validate a pattern-based finding using Mythril symbolic execution.

        Args:
            source_code: Solidity source code
            finding_type: Type of vulnerability from pattern detector
            finding_line: Line number of the finding
            timeout: Timeout for Mythril

        Returns:
            Tuple of (is_confirmed, matching_mythril_finding_or_None)
        """
        import tempfile
        import os

        # Create temp file for analysis
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.sol', delete=False
        ) as f:
            f.write(source_code)
            temp_path = f.name

        try:
            result = self.analyze(temp_path, timeout=timeout, verbose=False)

            if result.get("status") != "success" or not result.get("findings"):
                return False, None

            # Map pattern type to SWC IDs
            type_to_swc = {
                "reentrancy": ["107"],
                "reentrancy_eth": ["107"],
                "integer_overflow": ["101"],
                "integer_underflow": ["101"],
                "arithmetic": ["101"],
                "access_control": ["105", "106", "112"],
                "unprotected_function": ["105", "106"],
                "timestamp_dependence": ["116"],
                "tx_origin": ["115"],
                "unchecked_low_level_calls": ["104"],
                "front_running": ["114"],
                "bad_randomness": ["120"],
            }

            expected_swcs = type_to_swc.get(
                finding_type.lower().replace("-", "_"), []
            )

            # Find matching Mythril finding
            for mythril_finding in result.get("findings", []):
                swc = mythril_finding.get("swc_id", "").replace("SWC-", "")
                if swc in expected_swcs:
                    return True, mythril_finding

            return False, None

        finally:
            try:
                os.unlink(temp_path)
            except Exception:
                pass


def validate_findings_with_mythril(
    source_code: str,
    findings: List[Dict[str, Any]],
    timeout: int = 60,
) -> List[Dict[str, Any]]:
    """
    Validate pattern-based findings using Mythril symbolic execution.

    This function helps improve precision by confirming if vulnerabilities
    detected by pattern matching are actually exploitable.

    Args:
        source_code: Solidity source code
        findings: List of findings to validate
        timeout: Timeout per finding

    Returns:
        Findings with Mythril validation results and adjusted confidence
    """
    adapter = MythrilAdapter()

    status = adapter.is_available()
    if status != ToolStatus.AVAILABLE:
        return findings

    validated_findings = []

    for finding in findings:
        finding_type = finding.get("type", "")
        finding_line = finding.get("location", {}).get("line", 0)

        is_confirmed, mythril_finding = adapter.validate_finding(
            source_code, finding_type, finding_line, timeout
        )

        updated = finding.copy()
        updated["_mythril_validated"] = is_confirmed

        if is_confirmed and mythril_finding:
            updated["_mythril_swc"] = mythril_finding.get("swc_id")
            updated["_mythril_description"] = mythril_finding.get("description")
            # Boost confidence for confirmed findings
            current_conf = finding.get("confidence", 0.5)
            updated["confidence"] = min(0.95, current_conf + 0.25)
        else:
            # Slightly reduce confidence for unconfirmed findings
            current_conf = finding.get("confidence", 0.5)
            updated["confidence"] = max(0.2, current_conf - 0.1)

        validated_findings.append(updated)

    return validated_findings


# Export for registry
__all__ = ["MythrilAdapter", "validate_findings_with_mythril"]
