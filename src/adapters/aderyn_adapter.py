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
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

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
        temp_workspace = None
        actual_contract_path = contract_path

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

            contract_file = Path(contract_path)

            # Always copy contract to a clean temp directory for Aderyn
            # This avoids issues with solc discovery and complex project structures
            if contract_file.is_file():
                temp_workspace = tempfile.mkdtemp(prefix="miesc_aderyn_")
                temp_contract = Path(temp_workspace) / contract_file.name
                shutil.copy2(contract_path, temp_contract)
                analysis_dir = temp_workspace
                logger.debug(f"Copied contract to temp workspace: {temp_workspace}")
            else:
                temp_workspace = None
                analysis_dir = str(contract_file)

            # Check for external imports and set up dependencies if needed
            if contract_file.is_file():
                external_imports = self._detect_imports(contract_path)
                if external_imports:
                    logger.info(f"Detected external imports: {external_imports}")
                    # Set up workspace with dependencies (reuse temp_workspace)
                    self._install_deps_in_workspace(temp_workspace, contract_path, external_imports)

            # Build command - always analyze the directory, not a single file
            # Aderyn 0.1.9 has issues finding solc when targeting single files
            cmd = ["aderyn", analysis_dir, "-o", output_path]

            if no_snippets:
                cmd.append("--no-snippets")

            logger.info(f"Running Aderyn analysis: {' '.join(cmd)}")

            # Show progress message
            verbose = kwargs.get("verbose", True)
            if verbose:
                print(f"  [Aderyn] Running Rust-based static analysis...")

            # Execute Aderyn with corrected PATH for solc
            env = _get_solc_env()
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)

            execution_time = time.time() - start_time

            if verbose:
                print(f"  [Aderyn] Analysis completed in {execution_time:.1f}s")

            # Check for errors - but first check if output file was created with valid JSON
            # Aderyn 0.1.9 has a version parsing bug that causes exit code 101
            # even when analysis completes successfully and output is written
            output_exists = Path(output_path).exists()
            output_valid = False

            if output_exists:
                try:
                    with open(output_path, "r") as f:
                        test_json = json.load(f)
                        # Check if it has the expected structure
                        output_valid = "high_issues" in test_json or "low_issues" in test_json
                except (json.JSONDecodeError, Exception):
                    output_valid = False

            if result.returncode != 0 and not output_valid:
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

            # If output is valid but there was an error exit code, log warning but continue
            # This handles Aderyn 0.1.9 version parsing bug (exit 101 after successful analysis)
            if result.returncode != 0 and output_valid:
                logger.debug(
                    f"Aderyn exited with code {result.returncode} but output is valid - "
                    "ignoring exit code (known bug in aderyn 0.1.9)"
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

        finally:
            # Always cleanup temporary workspace
            if temp_workspace:
                self._cleanup_workspace(temp_workspace)

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

                # v4.6.0: Enhanced normalization with CWE and better recommendations
                normalized_finding = {
                    "id": f"aderyn-{detector_name}-{idx}-{inst_idx}",
                    "type": detector_name,
                    "severity": mapped_severity,
                    "confidence": self._estimate_confidence(severity, detector_name),
                    "location": location_info,
                    "message": title,
                    "description": description or title,
                    "recommendation": self._get_recommendation(detector_name),
                    "swc_id": self._map_to_swc(detector_name),
                    "cwe_id": self._map_to_cwe(detector_name),
                    "owasp_category": self._map_to_owasp(detector_name),
                    "_aderyn_detector": detector_name,  # For cross-validation
                }

                normalized.append(normalized_finding)

        except Exception as e:
            logger.error(f"Error normalizing Aderyn issue: {e}", exc_info=True)

        return normalized

    # v4.6.0: Comprehensive SWC mapping for Aderyn detectors
    SWC_MAPPING = {
        # Reentrancy
        "reentrancy": "SWC-107",
        "cross-function-reentrancy": "SWC-107",
        "read-only-reentrancy": "SWC-107",

        # Access Control
        "unprotected": "SWC-105",
        "arbitrary-send": "SWC-105",
        "send-ether": "SWC-105",
        "suicidal": "SWC-106",
        "selfdestruct": "SWC-106",
        "tx-origin": "SWC-115",

        # Unchecked Returns
        "unchecked": "SWC-104",
        "unchecked-send": "SWC-104",
        "unchecked-transfer": "SWC-104",
        "unchecked-call": "SWC-104",

        # Integer Issues
        "overflow": "SWC-101",
        "underflow": "SWC-101",
        "integer": "SWC-101",

        # Delegatecall
        "delegatecall": "SWC-112",
        "controlled-delegatecall": "SWC-112",

        # Timestamp
        "timestamp": "SWC-116",
        "block-timestamp": "SWC-116",

        # DoS
        "dos": "SWC-128",
        "gas-limit": "SWC-128",
        "unbounded": "SWC-128",

        # Randomness
        "random": "SWC-120",
        "weak-prng": "SWC-120",
        "blockhash": "SWC-120",

        # Storage
        "uninitialized-storage": "SWC-109",
        "uninitialized-state": "SWC-109",
        "shadowing": "SWC-119",

        # Signature
        "signature": "SWC-117",
        "ecrecover": "SWC-117",

        # Default Visibility
        "visibility": "SWC-100",
        "missing-visibility": "SWC-100",

        # Code Quality
        "unused": "SWC-131",
        "deprecated": "SWC-111",
        "assembly": "SWC-127",
    }

    # v4.6.0: CWE mapping for Aderyn detectors
    CWE_MAPPING = {
        "reentrancy": "CWE-841",
        "access-control": "CWE-284",
        "unprotected": "CWE-284",
        "tx-origin": "CWE-477",
        "overflow": "CWE-190",
        "underflow": "CWE-191",
        "unchecked": "CWE-252",
        "delegatecall": "CWE-829",
        "timestamp": "CWE-330",
        "random": "CWE-330",
        "dos": "CWE-400",
        "signature": "CWE-347",
        "uninitialized": "CWE-457",
    }

    def _map_to_swc(self, detector_name: str) -> Optional[str]:
        """Map Aderyn detector to SWC ID."""
        detector_lower = detector_name.lower()
        for key, value in self.SWC_MAPPING.items():
            if key in detector_lower:
                return value
        return None

    def _map_to_cwe(self, detector_name: str) -> Optional[str]:
        """Map Aderyn detector to CWE ID."""
        detector_lower = detector_name.lower()
        for key, value in self.CWE_MAPPING.items():
            if key in detector_lower:
                return value
        return None

    # v4.6.0: Recommendations for common Aderyn detectors
    RECOMMENDATIONS = {
        "reentrancy": "Use ReentrancyGuard or checks-effects-interactions pattern",
        "unprotected": "Add access control modifier (onlyOwner) or require(msg.sender == owner)",
        "tx-origin": "Use msg.sender instead of tx.origin for authorization",
        "unchecked": "Always check return value of low-level calls or use SafeERC20",
        "delegatecall": "Validate target address and use access control for delegatecall",
        "selfdestruct": "Add access control and consider removing selfdestruct",
        "timestamp": "Avoid using block.timestamp for critical decisions or randomness",
        "overflow": "Use Solidity 0.8+ or SafeMath for arithmetic operations",
        "random": "Use Chainlink VRF or commit-reveal scheme for randomness",
        "dos": "Limit loop iterations or use pull payment pattern",
        "signature": "Include nonce and chain ID in signed messages to prevent replay",
        "uninitialized": "Initialize all state variables in constructor",
        "centralization": "Consider using multi-sig or timelocks for privileged operations",
        "unused": "Remove unused code to reduce attack surface and gas costs",
        "visibility": "Explicitly declare function visibility",
    }

    def _get_recommendation(self, detector_name: str) -> str:
        """Get recommendation for a detector type."""
        detector_lower = detector_name.lower()
        for key, value in self.RECOMMENDATIONS.items():
            if key in detector_lower:
                return value
        return "Review and fix the issue according to best practices"

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

    def _detect_imports(self, contract_path: str) -> Set[str]:
        """Detect external imports in a Solidity contract."""
        imports = set()
        try:
            with open(contract_path, "r") as f:
                content = f.read()

            import_pattern = r'import\s+(?:{[^}]+}\s+from\s+)?["\']([^"\']+)["\']'
            matches = re.findall(import_pattern, content)

            for match in matches:
                if match.startswith("forge-std/"):
                    imports.add("forge-std")
                elif match.startswith("@openzeppelin/"):
                    imports.add("@openzeppelin/contracts")
                elif match.startswith("@chainlink/"):
                    imports.add("@chainlink/contracts")
                elif match.startswith("solmate/"):
                    imports.add("solmate")
                elif match.startswith("solady/"):
                    imports.add("solady")
                elif not match.startswith("."):
                    root = match.split("/")[0]
                    if root and not root.endswith(".sol"):
                        imports.add(root)

        except Exception as e:
            logger.debug(f"Error detecting imports: {e}")
        return imports

    def _get_dependency_info(self, import_name: str) -> Tuple[Optional[str], Optional[str]]:
        """Get forge install command and remapping for a dependency."""
        KNOWN_DEPS = {
            "forge-std": ("foundry-rs/forge-std", "forge-std/=lib/forge-std/src/"),
            "@openzeppelin/contracts": (
                "OpenZeppelin/openzeppelin-contracts",
                "@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/",
            ),
            "solmate": ("transmissions11/solmate", "solmate/=lib/solmate/src/"),
            "solady": ("Vectorized/solady", "solady/=lib/solady/src/"),
        }
        return KNOWN_DEPS.get(import_name, (None, None))

    def _detect_solidity_version(self, contract_path: str) -> str:
        """Detect Solidity version from pragma statement."""
        try:
            with open(contract_path, "r") as f:
                content = f.read()
            match = re.search(r"pragma\s+solidity\s*[\^~>=<]*\s*([\d.]+)", content)
            if match:
                return match.group(1)
        except Exception:
            pass
        return "0.8.20"

    def _install_deps_in_workspace(
        self, workspace: str, contract_path: str, imports: Set[str]
    ) -> bool:
        """Install dependencies in an existing workspace."""
        if not shutil.which("forge"):
            logger.debug("forge not available, cannot install dependencies")
            return False

        try:
            solc_version = self._detect_solidity_version(contract_path)

            remappings = []
            deps_to_install = []

            for imp in imports:
                install_target, remapping = self._get_dependency_info(imp)
                if install_target:
                    deps_to_install.append(install_target)
                    if remapping:
                        remappings.append(remapping)
                else:
                    logger.warning(f"Unknown dependency: {imp}")

            if not deps_to_install:
                return True

            foundry_config = f'''[profile.default]
src = "."
out = "out"
libs = ["lib"]
solc = "{solc_version}"
auto_detect_solc = false
'''
            if remappings:
                foundry_config += "\nremappings = [\n"
                for r in remappings:
                    foundry_config += f'    "{r}",\n'
                foundry_config += "]\n"

            foundry_toml = Path(workspace) / "foundry.toml"
            foundry_toml.write_text(foundry_config)

            # Initialize git repo (required by forge install)
            subprocess.run(
                ["git", "init"],
                cwd=workspace,
                capture_output=True,
                timeout=10,
            )

            for dep in deps_to_install:
                logger.info(f"Installing dependency: {dep}")
                result = subprocess.run(
                    ["forge", "install", dep, "--no-git"],
                    cwd=workspace,
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                if result.returncode != 0:
                    logger.warning(f"Failed to install {dep}: {result.stderr}")

            return True

        except Exception as e:
            logger.error(f"Error installing dependencies: {e}")
            return False

    def _setup_workspace_with_deps(
        self, contract_path: str, imports: Set[str]
    ) -> Optional[Tuple[str, str]]:
        """Create a temporary workspace with dependencies installed."""
        try:
            workspace = tempfile.mkdtemp(prefix="miesc_aderyn_")
            logger.debug(f"Created temporary workspace: {workspace}")

            contract_name = Path(contract_path).name
            temp_contract = Path(workspace) / contract_name
            shutil.copy2(contract_path, temp_contract)

            if imports:
                self._install_deps_in_workspace(workspace, contract_path, imports)

            return workspace, str(temp_contract)

        except Exception as e:
            logger.error(f"Error setting up workspace: {e}")
            return None

    def _cleanup_workspace(self, workspace: Optional[str]) -> None:
        """Remove temporary workspace directory."""
        if workspace and Path(workspace).exists():
            try:
                shutil.rmtree(workspace, ignore_errors=True)
            except Exception as e:
                logger.warning(f"Failed to cleanup workspace: {e}")

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
