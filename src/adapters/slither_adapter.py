"""
Slither adapter for MIESC Layer 1 (static analysis).

Wraps Trail of Bits' Slither analyzer (github.com/crytic/slither).
Implements ToolAdapter protocol for standardized integration.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
"""

import json
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.core.tool_protocol import (
    ToolAdapter,
    ToolCapability,
    ToolCategory,
    ToolMetadata,
    ToolStatus,
)
from src.llm import enhance_findings_with_llm

logger = logging.getLogger(__name__)


def _find_slither_binary() -> str:
    """
    Find the correct slither binary, preferring user installations.

    This handles cases where multiple slither versions are installed
    (e.g., an old version in /usr/local/bin and a new one in user site-packages).
    """
    # Priority list of paths to check
    priority_paths = [
        # User site-packages (pip install --user)
        os.path.expanduser("~/.local/bin/slither"),
        os.path.expanduser("~/Library/Python/3.9/bin/slither"),
        os.path.expanduser("~/Library/Python/3.10/bin/slither"),
        os.path.expanduser("~/Library/Python/3.11/bin/slither"),
        os.path.expanduser("~/Library/Python/3.12/bin/slither"),
        # Virtual environment
        os.path.join(os.environ.get("VIRTUAL_ENV", ""), "bin", "slither"),
    ]

    # Check priority paths first
    for path in priority_paths:
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            # Verify it's a working slither by checking version
            try:
                result = subprocess.run(
                    [path, "--version"], capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    logger.debug(f"Found slither at priority path: {path}")
                    return path
            except Exception:
                continue

    # Fall back to shutil.which (PATH-based lookup)
    slither_path = shutil.which("slither")
    if slither_path:
        return slither_path

    # Default to 'slither' and let the caller handle if not found
    return "slither"


class SlitherAdapter(ToolAdapter):
    """
    Slither Static Analyzer Adapter for MIESC.

    Slither is the most widely-used Solidity static analyzer with:
    - 88+ built-in vulnerability detectors
    - High detection rate (28% improvement expected)
    - Python-based, easy integration
    - JSON output format
    - Industry-standard tool by Trail of Bits

    Expected Impact (2025 Roadmap):
    - +28% vulnerability detection rate (per MIESC docs)
    - High coverage of OWASP Top 10 vulnerabilities
    - <10s execution time (Python performance)
    - Cross-validation with Aderyn for false positive reduction
    """

    # Severity mapping from Slither to MIESC standard
    SEVERITY_MAP = {
        "High": "High",
        "Medium": "Medium",
        "Low": "Low",
        "Informational": "Info",
        "Optimization": "Info",
    }

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="slither",
            version="1.0.0",
            category=ToolCategory.STATIC_ANALYSIS,
            author="Trail of Bits (Adapter by Fernando Boiero)",
            license="AGPL-3.0",
            homepage="https://github.com/crytic/slither",
            repository="https://github.com/crytic/slither",
            documentation="https://github.com/crytic/slither/wiki",
            installation_cmd="pip install slither-analyzer",
            capabilities=[
                ToolCapability(
                    name="static_analysis",
                    description="Python-based static analysis for Solidity (88+ detectors)",
                    supported_languages=["solidity"],
                    detection_types=[
                        "reentrancy",
                        "access_control",
                        "arithmetic_issues",
                        "unchecked_return_values",
                        "state_variable_shadowing",
                        "dangerous_strict_equality",
                        "uninitialized_variables",
                        "tx_origin_usage",
                        "delegatecall_injection",
                        "missing_zero_address_check",
                        "timestamp_dependence",
                        "block_number_dependence",
                        "weak_randomness",
                        "integer_overflow_underflow",
                        "locked_ether",
                        "arbitrary_send",
                        "controlled_delegatecall",
                        "unused_return_values",
                        "assembly_usage",
                        "low_level_calls",
                        "naming_convention",
                        "constant_functions_asm",
                        "external_function_not_checked",
                    ],
                )
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True,  # DPGA compliance - graceful degradation
        )

    def __init__(self):
        """Initialize SlitherAdapter with the correct binary path."""
        self._slither_binary = _find_slither_binary()
        logger.debug(f"SlitherAdapter using binary: {self._slither_binary}")

    def is_available(self) -> ToolStatus:
        """
        Check if Slither CLI is available and working.

        Returns:
            ToolStatus.AVAILABLE if slither is installed and working
            ToolStatus.NOT_INSTALLED otherwise
        """
        try:
            result = subprocess.run(
                [self._slither_binary, "--version"], capture_output=True, text=True, timeout=5
            )

            if result.returncode == 0:
                version = result.stdout.strip()
                logger.info(f"Slither available: {version}")
                return ToolStatus.AVAILABLE
            else:
                logger.warning("Slither command found but returned error")
                return ToolStatus.CONFIGURATION_ERROR

        except FileNotFoundError:
            logger.info("Slither not installed (optional tool)")
            return ToolStatus.NOT_INSTALLED
        except subprocess.TimeoutExpired:
            logger.warning("Slither version check timed out")
            return ToolStatus.CONFIGURATION_ERROR
        except Exception as e:
            logger.error(f"Error checking Slither availability: {e}")
            return ToolStatus.CONFIGURATION_ERROR

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Execute Slither analysis on the contract.

        Args:
            contract_path: Path to Solidity file or directory
            **kwargs:
                - output_path: Path for JSON output (default: temp file)
                - timeout: Analysis timeout in seconds (default: 300)
                - exclude_detectors: List of detectors to exclude
                - filter_paths: Paths to exclude from analysis

        Returns:
            Normalized results dictionary with:
            {
                "tool": "slither",
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
                "tool": "slither",
                "version": "1.0.0",
                "status": "error",
                "findings": [],
                "metadata": {"tool_status": status.value},
                "execution_time": time.time() - start_time,
                "error": f"Slither not available: {status.value}",
            }

        try:
            # Prepare output path
            output_path = kwargs.get("output_path", "/tmp/slither_output.json")
            timeout = kwargs.get("timeout", 300)
            exclude_detectors = kwargs.get("exclude_detectors", [])
            filter_paths = kwargs.get("filter_paths", [])

            # Build command
            cmd = [self._slither_binary, contract_path, "--json", output_path]

            # Support for legacy Solidity versions (0.4.x, 0.5.x)
            # Forces direct solc compilation instead of Foundry/Hardhat detection
            legacy_solc = kwargs.get("legacy_solc", False)
            solc_version = kwargs.get("solc_version")

            if legacy_solc or solc_version:
                cmd.extend(["--compile-force-framework", "solc"])
                if solc_version:
                    cmd.extend(["--solc-solcs-select", solc_version])

            if exclude_detectors:
                cmd.extend(["--exclude", ",".join(exclude_detectors)])

            if filter_paths:
                cmd.extend(["--filter-paths", "|".join(filter_paths)])

            logger.info(f"Running Slither analysis: {' '.join(cmd)}")

            # Execute Slither
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

            execution_time = time.time() - start_time

            # Slither returns non-zero even on success if vulnerabilities found
            # So we check if JSON was created instead of exit code
            if not Path(output_path).exists():
                error_msg = result.stderr or result.stdout
                logger.error(f"Slither execution failed: {error_msg}")
                return {
                    "tool": "slither",
                    "version": "1.0.0",
                    "status": "error",
                    "findings": [],
                    "metadata": {"exit_code": result.returncode, "stderr": error_msg},
                    "execution_time": execution_time,
                    "error": f"Slither analysis failed (exit code {result.returncode})",
                }

            # Parse JSON output
            with open(output_path, "r") as f:
                raw_output = json.load(f)

            # Normalize findings
            findings = self.normalize_findings(raw_output)

            # Enhance findings with OpenLLaMA (optional)
            try:
                with open(contract_path, "r") as f:
                    contract_code = f.read()

                # Enhance top findings with LLM insights
                if findings:
                    findings = enhance_findings_with_llm(
                        findings[:5], contract_code, "slither"  # Top 5 findings
                    )
            except Exception as e:
                logger.debug(f"LLM enhancement failed: {e}")

            metadata = {
                "contract_analyzed": contract_path,
                "output_file": output_path,
                "raw_findings_count": len(raw_output.get("results", {}).get("detectors", [])),
                "normalized_findings_count": len(findings),
                "slither_version": raw_output.get("success", False),
                "excluded_detectors": exclude_detectors,
            }

            logger.info(
                f"Slither analysis completed: {len(findings)} findings in {execution_time:.2f}s"
            )

            return {
                "tool": "slither",
                "version": "1.0.0",
                "status": "success",
                "findings": findings,
                "metadata": metadata,
                "execution_time": execution_time,
            }

        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            logger.error(f"Slither analysis timed out after {timeout}s")
            return {
                "tool": "slither",
                "version": "1.0.0",
                "status": "error",
                "findings": [],
                "metadata": {"timeout": timeout},
                "execution_time": execution_time,
                "error": f"Analysis timed out after {timeout} seconds",
            }

        except FileNotFoundError as e:
            execution_time = time.time() - start_time
            logger.error(f"Slither output file not found: {e}")
            return {
                "tool": "slither",
                "version": "1.0.0",
                "status": "error",
                "findings": [],
                "metadata": {"expected_output": output_path},
                "execution_time": execution_time,
                "error": f"Output file not found: {output_path}",
            }

        except json.JSONDecodeError as e:
            execution_time = time.time() - start_time
            logger.error(f"Failed to parse Slither JSON output: {e}")
            return {
                "tool": "slither",
                "version": "1.0.0",
                "status": "error",
                "findings": [],
                "metadata": {"json_error": str(e)},
                "execution_time": execution_time,
                "error": f"Invalid JSON output: {e}",
            }

        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"Unexpected error during Slither analysis: {e}", exc_info=True)
            return {
                "tool": "slither",
                "version": "1.0.0",
                "status": "error",
                "findings": [],
                "metadata": {"exception": str(e)},
                "execution_time": execution_time,
                "error": f"Unexpected error: {e}",
            }

    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        """
        Normalize Slither findings to MIESC standard format.

        Args:
            raw_output: Parsed JSON from Slither

        Returns:
            List of normalized findings
        """
        normalized = []

        try:
            raw_detectors = raw_output.get("results", {}).get("detectors", [])

            for idx, detector in enumerate(raw_detectors):
                # Extract core information
                check = detector.get("check", "unknown")
                impact = detector.get("impact", "Low")
                confidence = detector.get("confidence", "Medium")
                description = detector.get("description", "")
                markdown = detector.get("markdown", "")

                # Extract location info (first element if available)
                elements = detector.get("elements", [])
                location_info = {}

                if elements and len(elements) > 0:
                    first_element = elements[0]
                    source_mapping = first_element.get("source_mapping", {})
                    location_info = {
                        "file": source_mapping.get("filename_short", "unknown"),
                        "line": (
                            source_mapping.get("lines", [0])[0]
                            if source_mapping.get("lines")
                            else 0
                        ),
                        "function": first_element.get("name", "unknown"),
                    }
                else:
                    location_info = {"file": "unknown", "line": 0, "function": "unknown"}

                # Map severity (use impact as severity)
                mapped_severity = self.SEVERITY_MAP.get(impact, "Low")

                # Build normalized finding
                normalized_finding = {
                    "id": f"slither-{check}-{idx}",
                    "type": check,
                    "severity": mapped_severity,
                    "confidence": self._map_confidence(confidence),
                    "location": location_info,
                    "message": description.split("\n")[0] if description else check,
                    "description": markdown or description,
                    "recommendation": self._get_recommendation(check),
                    "swc_id": self._map_to_swc(check),
                    "cwe_id": None,  # Slither doesn't provide CWE directly
                    "owasp_category": self._map_to_owasp(check),
                }

                normalized.append(normalized_finding)

        except Exception as e:
            logger.error(f"Error normalizing Slither findings: {e}", exc_info=True)

        return normalized

    def _map_confidence(self, confidence: str) -> float:
        """Map Slither confidence to numeric value."""
        confidence_map = {"High": 0.90, "Medium": 0.75, "Low": 0.60}
        return confidence_map.get(confidence, 0.75)

    def _get_recommendation(self, check: str) -> str:
        """Get recommendation based on detector type."""
        recommendations = {
            "reentrancy": "Use the checks-effects-interactions pattern or ReentrancyGuard",
            "arbitrary-send": "Ensure only authorized addresses can trigger transfers",
            "suicidal": "Protect selfdestruct with proper access control",
            "uninitialized-state": "Initialize all state variables in constructor",
            "uninitialized-storage": "Initialize storage pointers explicitly",
            "tx-origin": "Use msg.sender instead of tx.origin for authentication",
            "locked-ether": "Provide a withdrawal function or ensure contract is payable",
        }
        return recommendations.get(check, "Review and fix the vulnerability")

    def _map_to_swc(self, check: str) -> Optional[str]:
        """Map Slither detector to SWC ID."""
        swc_mapping = {
            "reentrancy": "SWC-107",
            "arbitrary-send": "SWC-105",
            "suicidal": "SWC-106",
            "uninitialized-state": "SWC-109",
            "uninitialized-storage": "SWC-109",
            "tx-origin": "SWC-115",
            "timestamp": "SWC-116",
            "locked-ether": "SWC-132",
            "controlled-delegatecall": "SWC-112",
            "unchecked-send": "SWC-104",
        }

        for key, value in swc_mapping.items():
            if key in check.lower():
                return value

        return None

    def _map_to_owasp(self, check: str) -> Optional[str]:
        """Map Slither detector to OWASP Smart Contract Top 10 (2025)."""
        owasp_mapping = {
            "reentrancy": "SC01: Reentrancy",
            "access-control": "SC02: Access Control",
            "arithmetic": "SC03: Arithmetic Issues",
            "unchecked": "SC04: Unchecked Return Values",
            "tx-origin": "SC08: Bad Randomness / Front-Running",
            "delegatecall": "SC07: Unprotected Delegatecall",
            "timestamp": "SC08: Bad Randomness / Front-Running",
            "block-number": "SC08: Bad Randomness / Front-Running",
        }

        for key, value in owasp_mapping.items():
            if key in check.lower():
                return value

        return None

    def can_analyze(self, contract_path: str) -> bool:
        """Check if Slither can analyze the given contract."""
        path = Path(contract_path)

        # Slither can analyze .sol files and directories
        if path.is_file():
            return path.suffix == ".sol"
        elif path.is_dir():
            # Check if directory contains .sol files
            return any(path.glob("**/*.sol"))

        return False

    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration for Slither."""
        return {
            "timeout": 300,
            "exclude_detectors": [],
            "filter_paths": [],
            "output_format": "json",
        }


# Export for registry
__all__ = ["SlitherAdapter"]
