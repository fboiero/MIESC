"""
Slither adapter for MIESC Layer 1 (static analysis).

Wraps Trail of Bits' Slither analyzer (github.com/crytic/slither).
Implements ToolAdapter protocol for standardized integration.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
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
        temp_foundry_toml = None  # Track for cleanup in finally block
        temp_workspace = None  # Track for cleanup
        actual_contract_path = contract_path  # May change if workspace created

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

            # Detect external imports that need to be resolved
            external_imports = set()
            if Path(contract_path).is_file():
                external_imports = self._detect_imports(contract_path)
                if external_imports:
                    logger.info(f"Detected external imports: {external_imports}")

            # Support for legacy Solidity versions (0.4.x, 0.5.x)
            # Forces direct solc compilation instead of Foundry/Hardhat detection
            legacy_solc = kwargs.get("legacy_solc", False)
            solc_version = kwargs.get("solc_version")
            force_solc = kwargs.get("force_solc", None)

            # Auto-detect if we should force solc compilation
            # This prevents crytic-compile from incorrectly detecting Foundry
            # when forge is installed but the contract is a standalone file
            if force_solc is None:
                force_solc = self._should_force_solc(contract_path)

            # If contract has external imports, set up workspace with dependencies
            if external_imports and not force_solc:
                workspace_result = self._setup_workspace_with_deps(
                    contract_path, external_imports
                )
                if workspace_result:
                    temp_workspace, actual_contract_path = workspace_result
                    logger.info(f"Using workspace with dependencies: {temp_workspace}")

            # Build command with actual path (may be temp workspace)
            cmd = [self._slither_binary, actual_contract_path, "--json", output_path]

            if force_solc or legacy_solc or solc_version:
                cmd.extend(["--compile-force-framework", "solc"])
                if solc_version:
                    cmd.extend(["--solc-solcs-select", solc_version])
            elif not temp_workspace:
                # If not forcing solc, no workspace, and no project exists, create minimal Foundry project
                # This handles ARM64 where solc-select binaries don't work
                temp_foundry_toml = self._setup_foundry_project(actual_contract_path)

            if exclude_detectors:
                cmd.extend(["--exclude", ",".join(exclude_detectors)])

            if filter_paths:
                cmd.extend(["--filter-paths", "|".join(filter_paths)])

            logger.info(f"Running Slither analysis: {' '.join(cmd)}")

            # Show progress message
            verbose = kwargs.get("verbose", True)
            if verbose:
                print(f"  [Slither] Running static analysis...")

            # Execute Slither
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

            execution_time = time.time() - start_time

            if verbose:
                print(f"  [Slither] Analysis completed in {execution_time:.1f}s")

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

        finally:
            # Always cleanup temporary files
            if temp_foundry_toml:
                self._cleanup_foundry_project(temp_foundry_toml)
            if temp_workspace:
                self._cleanup_workspace(temp_workspace)

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

                # v4.6.0: Build normalized finding with detector name for FP filtering
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
                    "cwe_id": self._map_to_cwe(check),
                    "owasp_category": self._map_to_owasp(check),
                    # v4.6.0: Add detector name for FP rate adjustment
                    "_slither_detector": check,
                    "_slither_impact": impact,
                    "_slither_confidence": confidence,
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
            "weak-prng": "SWC-120",
            "divide-before-multiply": "SWC-101",
            "shadowing": "SWC-119",
            "assembly": "SWC-127",
            "deprecated": "SWC-111",
        }

        for key, value in swc_mapping.items():
            if key in check.lower():
                return value

        return None

    def _map_to_cwe(self, check: str) -> Optional[str]:
        """Map Slither detector to CWE ID (v4.6.0)."""
        cwe_mapping = {
            "reentrancy": "CWE-841",
            "access-control": "CWE-284",
            "arbitrary-send": "CWE-284",
            "tx-origin": "CWE-477",
            "overflow": "CWE-190",
            "underflow": "CWE-191",
            "divide": "CWE-369",
            "unchecked": "CWE-252",
            "delegatecall": "CWE-829",
            "timestamp": "CWE-330",
            "weak-prng": "CWE-330",
            "dos": "CWE-400",
            "locked-ether": "CWE-400",
            "uninitialized": "CWE-457",
            "shadowing": "CWE-710",
        }

        for key, value in cwe_mapping.items():
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

    def _should_force_solc(self, contract_path: str) -> bool:
        """
        Determine if we should force solc compilation instead of auto-detection.

        This prevents crytic-compile from incorrectly detecting Foundry/Hardhat
        when forge/npx is installed but the contract is a standalone file.

        Returns True if:
        - Contract is a single .sol file
        - No foundry.toml or hardhat.config.js in parent directories
        - AND solc is working (not ARM64 with x86_64 binaries)

        Returns False if:
        - Contract is in a Foundry project (foundry.toml exists)
        - Contract is in a Hardhat project (hardhat.config.js/ts exists)
        - Contract is a directory (let crytic-compile detect)
        - solc is not working (ARM64) - will use _setup_foundry_project instead
        """
        path = Path(contract_path).resolve()

        # If it's a directory, let crytic-compile auto-detect
        if path.is_dir():
            return False

        # Check parent directories for project files (up to 5 levels)
        check_dir = path.parent
        for _ in range(5):
            # Foundry project markers
            if (check_dir / "foundry.toml").exists():
                logger.debug(f"Found foundry.toml in {check_dir}, using Foundry")
                return False

            # Hardhat project markers
            if (check_dir / "hardhat.config.js").exists() or (
                check_dir / "hardhat.config.ts"
            ).exists():
                logger.debug(f"Found hardhat config in {check_dir}, using Hardhat")
                return False

            # Truffle project marker
            if (check_dir / "truffle-config.js").exists():
                logger.debug(f"Found truffle config in {check_dir}, using Truffle")
                return False

            # Move up one directory
            parent = check_dir.parent
            if parent == check_dir:  # Reached root
                break
            check_dir = parent

        # No project detected - check if solc works before forcing it
        if not self._is_solc_working():
            logger.debug(f"solc not working, will use Foundry for {contract_path}")
            return False

        # solc works, force it for standalone files
        logger.debug(f"No project detected for {contract_path}, forcing solc")
        return True

    def _is_solc_working(self) -> bool:
        """Check if solc is working (may fail on ARM64 with x86_64 binaries)."""
        try:
            result = subprocess.run(
                ["solc", "--version"], capture_output=True, text=True, timeout=5
            )
            # Check for QEMU errors (ARM64 running x86_64 binaries)
            if "qemu" in result.stderr.lower() or result.returncode != 0:
                return False
            return True
        except Exception:
            return False

    def _setup_foundry_project(self, contract_path: str) -> Optional[str]:
        """
        Create a minimal Foundry project for standalone .sol files.

        This is needed when:
        - forge is installed but no foundry.toml exists
        - solc is not working (ARM64)

        Returns the path to the created foundry.toml, or None if not needed/failed.
        """
        path = Path(contract_path).resolve()
        contract_dir = path.parent

        # Check if foundry.toml already exists
        foundry_toml = contract_dir / "foundry.toml"
        if foundry_toml.exists():
            return None

        # Check if forge is available
        if not shutil.which("forge"):
            logger.debug("forge not available, cannot create Foundry project")
            return None

        # Detect Solidity version from contract
        solc_version = self._detect_solidity_version(contract_path)

        # Create minimal foundry.toml
        try:
            config = f'''[profile.default]
src = "."
out = "out"
libs = []
solc = "{solc_version}"
auto_detect_solc = false
'''
            foundry_toml.write_text(config)
            logger.info(f"Created minimal foundry.toml at {foundry_toml}")
            return str(foundry_toml)
        except Exception as e:
            logger.warning(f"Failed to create foundry.toml: {e}")
            return None

    def _detect_solidity_version(self, contract_path: str) -> str:
        """Detect Solidity version from pragma statement."""
        try:
            with open(contract_path, "r") as f:
                content = f.read()

            # Match pragma solidity ^0.8.19; or similar
            match = re.search(r"pragma\s+solidity\s*[\^~>=<]*\s*([\d.]+)", content)
            if match:
                return match.group(1)
        except Exception:
            pass

        # Default to 0.8.20 if not detected
        return "0.8.20"

    def _detect_imports(self, contract_path: str) -> Set[str]:
        """
        Detect external imports in a Solidity contract.

        Returns a set of import prefixes like:
        - 'forge-std'
        - '@openzeppelin/contracts'
        - '@chainlink/contracts'
        """
        imports = set()
        try:
            with open(contract_path, "r") as f:
                content = f.read()

            # Match import statements
            # import "forge-std/Test.sol";
            # import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
            # import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
            import_pattern = r'import\s+(?:{[^}]+}\s+from\s+)?["\']([^"\']+)["\']'
            matches = re.findall(import_pattern, content)

            for match in matches:
                # Extract the root package
                if match.startswith("forge-std/"):
                    imports.add("forge-std")
                elif match.startswith("@openzeppelin/"):
                    imports.add("@openzeppelin/contracts")
                elif match.startswith("@chainlink/"):
                    imports.add("@chainlink/contracts")
                elif match.startswith("@uniswap/"):
                    imports.add("@uniswap")
                elif match.startswith("solmate/"):
                    imports.add("solmate")
                elif match.startswith("solady/"):
                    imports.add("solady")
                # Relative imports (./foo.sol, ../bar.sol) are OK
                elif not match.startswith("."):
                    # Unknown external import
                    root = match.split("/")[0]
                    if root and not root.endswith(".sol"):
                        imports.add(root)

        except Exception as e:
            logger.debug(f"Error detecting imports: {e}")

        return imports

    def _get_dependency_info(self, import_name: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Get forge install command and remapping for a dependency.

        Returns (install_target, remapping) or (None, None) if unknown.
        """
        # Known dependencies mapping: import_name -> (forge_install_target, remapping)
        KNOWN_DEPS = {
            "forge-std": (
                "foundry-rs/forge-std",
                "forge-std/=lib/forge-std/src/"
            ),
            "@openzeppelin/contracts": (
                "OpenZeppelin/openzeppelin-contracts",
                "@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/"
            ),
            "@openzeppelin/contracts-upgradeable": (
                "OpenZeppelin/openzeppelin-contracts-upgradeable",
                "@openzeppelin/contracts-upgradeable/=lib/openzeppelin-contracts-upgradeable/contracts/"
            ),
            "@chainlink/contracts": (
                "smartcontractkit/chainlink",
                "@chainlink/contracts/=lib/chainlink/contracts/"
            ),
            "solmate": (
                "transmissions11/solmate",
                "solmate/=lib/solmate/src/"
            ),
            "solady": (
                "Vectorized/solady",
                "solady/=lib/solady/src/"
            ),
        }

        return KNOWN_DEPS.get(import_name, (None, None))

    def _setup_workspace_with_deps(
        self, contract_path: str, imports: Set[str]
    ) -> Optional[Tuple[str, str]]:
        """
        Create a temporary workspace with dependencies installed.

        This handles the case where:
        - Contract has external imports (forge-std, openzeppelin, etc.)
        - Original directory might be read-only (Docker volume)

        Returns (temp_workspace_path, temp_contract_path) or None if failed.
        """
        if not shutil.which("forge"):
            logger.debug("forge not available, cannot install dependencies")
            return None

        try:
            # Create temporary workspace
            workspace = tempfile.mkdtemp(prefix="miesc_slither_")
            logger.debug(f"Created temporary workspace: {workspace}")

            # Copy contract to workspace
            contract_name = Path(contract_path).name
            temp_contract = Path(workspace) / contract_name
            shutil.copy2(contract_path, temp_contract)

            # Detect solidity version
            solc_version = self._detect_solidity_version(contract_path)

            # Build remappings
            remappings = []
            deps_to_install = []

            for imp in imports:
                install_target, remapping = self._get_dependency_info(imp)
                if install_target:
                    deps_to_install.append(install_target)
                    if remapping:
                        remappings.append(remapping)
                else:
                    logger.warning(f"Unknown dependency: {imp} - may fail to compile")

            # Create foundry.toml
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
            logger.debug(f"Created foundry.toml with remappings: {remappings}")

            # Initialize git repo (required by forge install)
            subprocess.run(
                ["git", "init"],
                cwd=workspace,
                capture_output=True,
                timeout=10,
            )

            # Install dependencies
            for dep in deps_to_install:
                logger.info(f"Installing dependency: {dep}")
                # Use --no-git to avoid submodule issues
                result = subprocess.run(
                    ["forge", "install", dep, "--no-git"],
                    cwd=workspace,
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                if result.returncode != 0:
                    logger.warning(f"Failed to install {dep}: {result.stderr}")
                else:
                    logger.debug(f"Installed {dep} successfully")

            return workspace, str(temp_contract)

        except Exception as e:
            logger.error(f"Error setting up workspace: {e}")
            return None

    def _cleanup_workspace(self, workspace: Optional[str]) -> None:
        """Remove temporary workspace directory."""
        if workspace and Path(workspace).exists():
            try:
                shutil.rmtree(workspace, ignore_errors=True)
                logger.debug(f"Cleaned up workspace: {workspace}")
            except Exception as e:
                logger.warning(f"Failed to cleanup workspace: {e}")

    def _cleanup_foundry_project(self, foundry_toml_path: Optional[str]) -> None:
        """Remove the temporary foundry.toml created for analysis."""
        if foundry_toml_path:
            try:
                Path(foundry_toml_path).unlink(missing_ok=True)
                # Also clean up the out directory if created
                out_dir = Path(foundry_toml_path).parent / "out"
                if out_dir.exists():
                    shutil.rmtree(out_dir, ignore_errors=True)
                logger.debug(f"Cleaned up temporary Foundry files")
            except Exception as e:
                logger.warning(f"Failed to cleanup Foundry files: {e}")

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
