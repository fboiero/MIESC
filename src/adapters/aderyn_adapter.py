"""
Aderyn Static Analyzer Adapter - 2025 Security Enhancement
============================================================

Integrates Aderyn (Cyfrin's Rust-based Solidity analyzer) to MIESC Layer 1.
Fast execution, low false positive rate, complementary to Slither 3.0.

Tool: Aderyn by Cyfrin (https://github.com/Cyfrin/aderyn)
Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: November 10, 2025
Version: 1.0.0
"""

import json
import logging
import os
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


def _get_solc_env() -> dict:
    """
    Get environment with correct solc PATH for ARM64 Macs.

    solc-select may have multiple entry points with version conflicts.
    This ensures Aderyn uses the correct solc binary.
    """
    env = os.environ.copy()

    # Priority paths for solc (user site-packages first)
    priority_paths = [
        os.path.expanduser("~/Library/Python/3.9/bin"),
        os.path.expanduser("~/Library/Python/3.10/bin"),
        os.path.expanduser("~/Library/Python/3.11/bin"),
        os.path.expanduser("~/Library/Python/3.12/bin"),
        os.path.expanduser("~/.local/bin"),
        "/opt/homebrew/bin",
    ]

    # Build new PATH with priority paths first
    existing_path = env.get("PATH", "")
    new_paths = [p for p in priority_paths if os.path.isdir(p)]
    env["PATH"] = ":".join(new_paths) + ":" + existing_path

    return env


class AderynAdapter(ToolAdapter):
    """
    Aderyn Static Analyzer Adapter for MIESC.

    Aderyn is a Rust-based Solidity static analyzer from Cyfrin with:
    - Fast execution (Rust performance)
    - Low false positive rate
    - 50+ vulnerability detectors
    - JSON output format
    - Complementary detection to Slither

    Expected Impact (2025 Roadmap):
    - +10-15% vulnerability coverage (cross-validation with Slither)
    - -30% false positives (different detection algorithms)
    - <5s execution time (Rust performance)
    """

    # Severity mapping from Aderyn to MIESC standard
    SEVERITY_MAP = {
        "Critical": "Critical",
        "High": "High",
        "Medium": "Medium",
        "Low": "Low",
        "NC": "Info",  # Non-Critical
        "Gas": "Info",  # Gas optimization
    }

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="aderyn",
            version="1.0.0",
            category=ToolCategory.STATIC_ANALYSIS,
            author="Cyfrin (Adapter by Fernando Boiero)",
            license="MIT",
            homepage="https://github.com/Cyfrin/aderyn",
            repository="https://github.com/Cyfrin/aderyn",
            documentation="https://github.com/Cyfrin/aderyn#readme",
            installation_cmd="cargo install aderyn",
            capabilities=[
                ToolCapability(
                    name="static_analysis",
                    description="Rust-based static analysis for Solidity",
                    supported_languages=["solidity"],
                    detection_types=[
                        "reentrancy",
                        "access_control",
                        "arithmetic_issues",
                        "unchecked_return_values",
                        "state_variable_shadowing",
                        "dangerous_strict_equality",
                        "uninitialized_state_variables",
                        "tx_origin_usage",
                        "delegatecall_in_loop",
                        "missing_zero_address_check",
                        "centralization_risk",
                        "unused_imports",
                        "function_selector_collision",
                        "multiple_constructor_schemes",
                        "push_0_opcode_not_supported",
                    ],
                )
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True,  # DPGA compliance - graceful degradation
        )

    def is_available(self) -> ToolStatus:
        """
        Check if Aderyn CLI is available and working.

        Returns:
            ToolStatus.AVAILABLE if aderyn is installed and working
            ToolStatus.NOT_INSTALLED otherwise
        """
        try:
            result = subprocess.run(
                ["aderyn", "--version"], capture_output=True, text=True, timeout=5
            )

            if result.returncode == 0:
                version = result.stdout.strip()
                logger.info(f"Aderyn available: {version}")
                return ToolStatus.AVAILABLE
            else:
                logger.warning("Aderyn command found but returned error")
                return ToolStatus.CONFIGURATION_ERROR

        except FileNotFoundError:
            logger.info("Aderyn not installed (optional tool)")
            return ToolStatus.NOT_INSTALLED
        except subprocess.TimeoutExpired:
            logger.warning("Aderyn version check timed out")
            return ToolStatus.CONFIGURATION_ERROR
        except Exception as e:
            logger.error(f"Error checking Aderyn availability: {e}")
            return ToolStatus.CONFIGURATION_ERROR

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Execute Aderyn analysis on the contract.

        Args:
            contract_path: Path to Solidity file or directory
            **kwargs:
                - output_path: Path for JSON output (default: temp file)
                - timeout: Analysis timeout in seconds (default: 300)
                - no_snippets: Disable code snippets in output

        Returns:
            Normalized results dictionary with:
            {
                "tool": "aderyn",
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
                "tool": "aderyn",
                "version": "1.0.0",
                "status": "error",
                "findings": [],
                "metadata": {"tool_status": status.value},
                "execution_time": time.time() - start_time,
                "error": f"Aderyn not available: {status.value}",
            }

        try:
            # Prepare output path
            output_path = kwargs.get("output_path", "/tmp/aderyn_output.json")
            timeout = kwargs.get("timeout", 300)
            no_snippets = kwargs.get("no_snippets", False)

            # Build command
            # Aderyn works better on directories than single files
            contract_file = Path(contract_path)
            if contract_file.is_file():
                # Run Aderyn on parent directory with include filter
                contract_dir = str(contract_file.parent)
                contract_name = contract_file.name
                cmd = ["aderyn", contract_dir, "-i", contract_name, "-o", output_path]
            else:
                cmd = ["aderyn", contract_path, "-o", output_path]

            if no_snippets:
                cmd.append("--no-snippets")

            logger.info(f"Running Aderyn analysis: {' '.join(cmd)}")

            # Execute Aderyn with corrected PATH for solc
            env = _get_solc_env()
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)

            execution_time = time.time() - start_time

            # Check for errors - but first check if output file was created
            # Aderyn 0.1.9 has a version parsing bug that causes exit code 101
            # even when analysis completes successfully
            output_exists = Path(output_path).exists()

            if result.returncode != 0 and not output_exists:
                error_msg = result.stderr or result.stdout
                logger.error(f"Aderyn execution failed: {error_msg}")
                return {
                    "tool": "aderyn",
                    "version": "1.0.0",
                    "status": "error",
                    "findings": [],
                    "metadata": {"exit_code": result.returncode, "stderr": error_msg},
                    "execution_time": execution_time,
                    "error": f"Aderyn analysis failed (exit code {result.returncode})",
                }

            # If output exists but there was an error, log warning but continue
            if result.returncode != 0 and output_exists:
                logger.warning(
                    f"Aderyn exited with code {result.returncode} but output file exists - "
                    "possibly a version parsing bug in aderyn 0.1.9"
                )

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
                        findings[:5], contract_code, "aderyn"  # Top 5 findings
                    )
            except Exception as e:
                logger.debug(f"LLM enhancement failed: {e}")

            metadata = {
                "contract_analyzed": contract_path,
                "output_file": output_path,
                "raw_findings_count": len(raw_output.get("findings", [])),
                "normalized_findings_count": len(findings),
                "aderyn_version": raw_output.get("version", "unknown"),
                "analysis_timestamp": raw_output.get("timestamp", "unknown"),
            }

            logger.info(
                f"Aderyn analysis completed: {len(findings)} findings in {execution_time:.2f}s"
            )

            return {
                "tool": "aderyn",
                "version": "1.0.0",
                "status": "success",
                "findings": findings,
                "metadata": metadata,
                "execution_time": execution_time,
            }

        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            logger.error(f"Aderyn analysis timed out after {timeout}s")
            return {
                "tool": "aderyn",
                "version": "1.0.0",
                "status": "error",
                "findings": [],
                "metadata": {"timeout": timeout},
                "execution_time": execution_time,
                "error": f"Analysis timed out after {timeout} seconds",
            }

        except FileNotFoundError as e:
            execution_time = time.time() - start_time
            logger.error(f"Aderyn output file not found: {e}")
            return {
                "tool": "aderyn",
                "version": "1.0.0",
                "status": "error",
                "findings": [],
                "metadata": {"expected_output": output_path},
                "execution_time": execution_time,
                "error": f"Output file not found: {output_path}",
            }

        except json.JSONDecodeError as e:
            execution_time = time.time() - start_time
            logger.error(f"Failed to parse Aderyn JSON output: {e}")
            return {
                "tool": "aderyn",
                "version": "1.0.0",
                "status": "error",
                "findings": [],
                "metadata": {"json_error": str(e)},
                "execution_time": execution_time,
                "error": f"Invalid JSON output: {e}",
            }

        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"Unexpected error during Aderyn analysis: {e}", exc_info=True)
            return {
                "tool": "aderyn",
                "version": "1.0.0",
                "status": "error",
                "findings": [],
                "metadata": {"exception": str(e)},
                "execution_time": execution_time,
                "error": f"Unexpected error: {e}",
            }

    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        """
        Normalize Aderyn findings to MIESC standard format.

        Aderyn 0.1.9 output format:
        {
            "high_issues": {"issues": [...]},
            "low_issues": {"issues": [...]},
            ...
        }

        Args:
            raw_output: Parsed JSON from Aderyn

        Returns:
            List of normalized findings
        """
        normalized = []
        idx = 0

        try:
            # Process high severity issues
            high_issues = raw_output.get("high_issues", {}).get("issues", [])
            for finding in high_issues:
                normalized.extend(self._normalize_issue(finding, "High", idx))
                idx += 1

            # Process low severity issues (includes Medium, Low, Info)
            low_issues = raw_output.get("low_issues", {}).get("issues", [])
            for finding in low_issues:
                normalized.extend(self._normalize_issue(finding, "Low", idx))
                idx += 1

        except Exception as e:
            logger.error(f"Error normalizing Aderyn findings: {e}", exc_info=True)

        return normalized

    def _normalize_issue(self, finding: Dict, severity: str, idx: int) -> List[Dict[str, Any]]:
        """Normalize a single Aderyn issue with multiple instances."""
        normalized = []

        try:
            detector_name = finding.get("detector_name", "unknown")
            title = finding.get("title", "Unknown issue")
            description = finding.get("description", "")
            instances = finding.get("instances", [])

            # Create one finding per instance
            for inst_idx, instance in enumerate(instances):
                location_info = {
                    "file": instance.get("contract_path", "unknown"),
                    "line": instance.get("line_no", 0),
                    "function": "unknown",
                }

                mapped_severity = self.SEVERITY_MAP.get(severity, "Low")

                normalized_finding = {
                    "id": f"aderyn-{detector_name}-{idx}-{inst_idx}",
                    "type": detector_name,
                    "severity": mapped_severity,
                    "confidence": self._estimate_confidence(severity, detector_name),
                    "location": location_info,
                    "message": title,
                    "description": description or title,
                    "recommendation": "Review and fix the issue",
                    "swc_id": self._map_to_swc(detector_name),
                    "cwe_id": None,
                    "owasp_category": self._map_to_owasp(detector_name),
                }

                normalized.append(normalized_finding)

        except Exception as e:
            logger.error(f"Error normalizing Aderyn issue: {e}", exc_info=True)

        return normalized

    def _map_to_swc(self, detector_name: str) -> Optional[str]:
        """Map Aderyn detector to SWC ID."""
        swc_mapping = {
            "reentrancy": "SWC-107",
            "unchecked-send": "SWC-104",
            "tx-origin": "SWC-115",
            "send-ether": "SWC-105",
            "delegatecall": "SWC-112",
        }
        for key, value in swc_mapping.items():
            if key in detector_name.lower():
                return value
        return None

    def _estimate_confidence(self, severity: str, detector: str) -> float:
        """
        Estimate confidence based on severity and detector type.

        Aderyn has low false positive rate, so confidence is generally high.
        """
        if severity == "Critical":
            return 0.95
        elif severity == "High":
            return 0.90
        elif severity == "Medium":
            return 0.85
        elif severity == "Low":
            return 0.75
        else:
            return 0.60

    def _map_to_owasp(self, detector_name: str) -> Optional[str]:
        """
        Map Aderyn detector to OWASP Smart Contract Top 10 (2025).

        Returns:
            OWASP category or None
        """
        owasp_mapping = {
            "reentrancy": "SC01: Reentrancy",
            "access_control": "SC02: Access Control",
            "arithmetic": "SC03: Arithmetic Issues",
            "unchecked_call": "SC04: Unchecked Return Values",
            "tx_origin": "SC08: Bad Randomness / Front-Running",
            "delegatecall": "SC07: Unprotected Delegatecall",
            "centralization": "SC09: Centralization Risk",
            "uninitialized": "SC05: Uninitialized Storage",
        }

        for key, value in owasp_mapping.items():
            if key in detector_name.lower():
                return value

        return None

    def can_analyze(self, contract_path: str) -> bool:
        """Check if Aderyn can analyze the given contract."""
        path = Path(contract_path)

        # Aderyn can analyze .sol files and directories
        if path.is_file():
            return path.suffix == ".sol"
        elif path.is_dir():
            # Check if directory contains .sol files
            return any(path.glob("**/*.sol"))

        return False

    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration for Aderyn."""
        return {"timeout": 300, "no_snippets": False, "output_format": "json"}


# Export for registry
__all__ = ["AderynAdapter"]
