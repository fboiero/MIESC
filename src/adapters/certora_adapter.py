"""
Certora Formal Verification Adapter - MIESC Phase 4 (Matured Implementation)
==============================================================================

Certora's commercial-grade formal verification tool for smart contracts.
Provides rigorous mathematical proofs using CVL (Certora Verification Language).

Note: Requires commercial license and Certora Prover installation.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: November 11, 2025
Version: 2.0.0 (Matured)
"""

from src.core.tool_protocol import (
    ToolAdapter, ToolMetadata, ToolStatus, ToolCategory, ToolCapability
)
from typing import Dict, Any, List, Optional
import subprocess
import logging
import json
import time
import re
import os
from pathlib import Path

logger = logging.getLogger(__name__)


class CertoraAdapter(ToolAdapter):
    """
    Certora Formal Verification Adapter for MIESC Layer 4.

    Key Features:
    - Commercial-grade formal verification
    - CVL (Certora Verification Language) spec support
    - Mathematical proofs for invariants and properties
    - Counterexample generation
    - Requires API key and license
    """

    def __init__(self):
        super().__init__()
        self._default_timeout = 900  # 15 minutes (Certora can be slow)

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="certora",
            version="2.0.0",
            category=ToolCategory.FORMAL_VERIFICATION,
            author="Certora (Adapter by Fernando Boiero)",
            license="Proprietary",
            homepage="https://www.certora.com",
            repository="https://github.com/Certora",
            documentation="https://docs.certora.com",
            installation_cmd="Requires commercial license - contact Certora at https://www.certora.com",
            capabilities=[
                ToolCapability(
                    name="formal_verification",
                    description="Commercial formal verification with mathematical proofs (Certora)",
                    supported_languages=["solidity"],
                    detection_types=[
                        "invariant_violations",
                        "property_failures",
                        "specification_mismatches",
                        "state_reachability_issues",
                        "counterexamples"
                    ]
                )
            ],
            cost=0.0,  # Commercial - pricing varies
            requires_api_key=True,
            is_optional=True
        )

    def is_available(self) -> ToolStatus:
        """Check if Certora Prover is installed and licensed."""
        try:
            # Check if certoraRun command exists
            result = subprocess.run(
                ["certoraRun", "--version"],
                capture_output=True,
                timeout=10,
                text=True
            )

            if result.returncode == 0:
                # Check for API key
                api_key = os.getenv("CERTORAKEY") or os.getenv("CERTORA_KEY")
                if not api_key:
                    logger.warning("CERTORAKEY environment variable not set")
                    return ToolStatus.CONFIGURATION_ERROR

                return ToolStatus.AVAILABLE
            else:
                logger.warning(f"Certora version check failed: {result.stderr}")
                return ToolStatus.CONFIGURATION_ERROR

        except FileNotFoundError:
            logger.info("Certora not installed. Requires commercial license from https://www.certora.com")
            return ToolStatus.NOT_INSTALLED
        except subprocess.TimeoutExpired:
            logger.warning("Certora version check timeout")
            return ToolStatus.CONFIGURATION_ERROR
        except Exception as e:
            logger.error(f"Error checking Certora: {e}")
            return ToolStatus.CONFIGURATION_ERROR

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Analyze contract using Certora formal verification.

        Args:
            contract_path: Path to Solidity contract
            **kwargs: Optional configuration (timeout, spec_file)

        Returns:
            Analysis results with findings
        """
        start_time = time.time()

        # Check availability
        if self.is_available() != ToolStatus.AVAILABLE:
            return {
                "tool": "certora",
                "version": "2.0.0",
                "status": "error",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": "Certora not available. Requires commercial license and CERTORAKEY environment variable."
            }

        try:
            # Get configuration
            timeout = kwargs.get("timeout", self._default_timeout)
            spec_file = kwargs.get("spec_file", None)

            # Find spec file if not provided
            if not spec_file:
                spec_file = self._find_spec_file(contract_path)
                if not spec_file:
                    logger.warning(f"No CVL spec file found for {contract_path}")
                    return {
                        "tool": "certora",
                        "version": "2.0.0",
                        "status": "success",
                        "findings": [],
                        "execution_time": time.time() - start_time,
                        "metadata": {"note": "No CVL spec file found - skipping Certora"}
                    }

            # Run Certora verification
            raw_output = self._run_certora_prover(
                contract_path,
                spec_file,
                timeout=timeout
            )

            # Parse findings
            findings = self._parse_certora_output(raw_output, contract_path, spec_file)

            return {
                "tool": "certora",
                "version": "2.0.0",
                "status": "success",
                "findings": findings,
                "metadata": {
                    "timeout": timeout,
                    "spec_file": spec_file
                },
                "execution_time": time.time() - start_time
            }

        except subprocess.TimeoutExpired:
            return {
                "tool": "certora",
                "version": "2.0.0",
                "status": "timeout",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": f"Certora verification exceeded {timeout}s timeout"
            }
        except Exception as e:
            logger.error(f"Certora verification error: {e}", exc_info=True)
            return {
                "tool": "certora",
                "version": "2.0.0",
                "status": "error",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": str(e)
            }

    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        """Normalize findings - already normalized in analyze()."""
        return raw_output.get("findings", []) if isinstance(raw_output, dict) else []

    def can_analyze(self, contract_path: str) -> bool:
        """Check if adapter can analyze the contract."""
        return Path(contract_path).suffix == '.sol'

    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration."""
        return {
            "timeout": 900,
            "optimistic_loop": True,
            "loop_iter": 3,
            "smt_timeout": 600
        }

    # ============================================================================
    # PRIVATE HELPER METHODS
    # ============================================================================

    def _find_spec_file(self, contract_path: str) -> Optional[str]:
        """Find CVL specification file for contract."""
        contract_path_obj = Path(contract_path)
        contract_name = contract_path_obj.stem

        # Common spec file patterns
        spec_patterns = [
            f"{contract_name}.spec",
            f"{contract_name}.cvl",
            f"spec/{contract_name}.spec",
            f"certora/specs/{contract_name}.spec"
        ]

        # Search in common spec directories
        spec_dirs = [
            contract_path_obj.parent,
            contract_path_obj.parent / "certora" / "specs",
            contract_path_obj.parent / "spec",
            contract_path_obj.parent.parent / "certora" / "specs"
        ]

        for spec_dir in spec_dirs:
            if not spec_dir.exists():
                continue

            for pattern in spec_patterns:
                spec_file = spec_dir / pattern
                if spec_file.exists():
                    return str(spec_file)

        return None

    def _run_certora_prover(
        self,
        contract_path: str,
        spec_file: str,
        timeout: int = 900
    ) -> str:
        """Execute Certora Prover verification."""

        cmd = [
            "certoraRun",
            contract_path,
            "--verify",
            f"{Path(contract_path).stem}:{spec_file}",
            "--optimistic_loop",
            "--loop_iter", "3",
            "--msg", "MIESC automated verification"
        ]

        logger.info(f"Certora: Running formal verification (timeout={timeout}s)")

        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            text=True,
            cwd=Path(contract_path).parent
        )

        # Certora returns non-zero for violations (expected)
        if result.returncode not in [0, 1]:
            logger.warning(f"Certora completed with code {result.returncode}")

        return result.stdout + "\n" + result.stderr

    def _parse_certora_output(
        self,
        output: str,
        contract_path: str,
        spec_file: str
    ) -> List[Dict[str, Any]]:
        """Parse Certora output and extract findings."""
        findings = []

        lines = output.split('\n')

        for i, line in enumerate(lines):
            # Detect rule violations
            if "violated" in line.lower() or "violation" in line.lower():
                # Extract rule name
                rule_match = re.search(r'rule\s+(\w+)', line, re.IGNORECASE)
                rule_name = rule_match.group(1) if rule_match else "unknown_rule"

                # Look for counterexample details
                counterexample = ""
                for j in range(i+1, min(i+20, len(lines))):
                    if "counterexample" in lines[j].lower() or "trace" in lines[j].lower():
                        counterexample += lines[j].strip() + " "
                        for k in range(j+1, min(j+10, len(lines))):
                            if lines[k].strip():
                                counterexample += lines[k].strip() + " "

                findings.append({
                    "id": f"certora-{len(findings)+1}",
                    "title": f"Rule Violation: {rule_name}",
                    "description": f"Certora detected violation of rule {rule_name}. {counterexample[:300]}",
                    "severity": "CRITICAL",
                    "confidence": 0.98,  # Very high - formal proof
                    "category": "rule_violation",
                    "location": {
                        "file": contract_path,
                        "spec_file": spec_file,
                        "rule": rule_name
                    },
                    "recommendation": f"Fix violation of rule {rule_name}. Review counterexample trace.",
                    "references": [
                        "https://docs.certora.com",
                        f"Spec file: {spec_file}"
                    ]
                })

            # Detect invariant violations
            if "invariant" in line.lower() and ("failed" in line.lower() or "violation" in line.lower()):
                invariant_match = re.search(r'invariant\s+(\w+)', line, re.IGNORECASE)
                invariant_name = invariant_match.group(1) if invariant_match else "unknown_invariant"

                findings.append({
                    "id": f"certora-inv-{len(findings)+1}",
                    "title": f"Invariant Violation: {invariant_name}",
                    "description": line.strip(),
                    "severity": "CRITICAL",
                    "confidence": 0.98,
                    "category": "invariant_violation",
                    "location": {
                        "file": contract_path,
                        "spec_file": spec_file,
                        "invariant": invariant_name
                    },
                    "recommendation": f"Fix invariant {invariant_name} - it does not hold for all states",
                    "references": [
                        "https://docs.certora.com/en/latest/docs/cvl/invariants.html",
                        f"Spec file: {spec_file}"
                    ]
                })

            # Detect timeout or incomplete verification
            if "timeout" in line.lower() or "incomplete" in line.lower():
                findings.append({
                    "id": f"certora-timeout",
                    "title": "Verification Timeout",
                    "description": line.strip(),
                    "severity": "LOW",
                    "confidence": 0.70,
                    "category": "verification_incomplete",
                    "location": {
                        "file": contract_path,
                        "spec_file": spec_file
                    },
                    "recommendation": "Increase timeout or simplify specifications to complete verification",
                    "references": ["https://docs.certora.com/en/latest/docs/prover/approx/"]
                })

        # Check for successful verification
        if "verified" in output.lower() and not findings:
            # Extract verified rules count
            verified_count_match = re.search(r'(\d+)\s+rules?\s+verified', output, re.IGNORECASE)
            verified_count = int(verified_count_match.group(1)) if verified_count_match else 0

            findings.append({
                "id": "certora-verified",
                "title": f"Formal Verification Passed ({verified_count} rules)",
                "description": f"Certora successfully verified {verified_count} rules with no violations",
                "severity": "INFO",
                "confidence": 1.0,
                "category": "verification_success",
                "location": {
                    "file": contract_path,
                    "spec_file": spec_file
                },
                "recommendation": "Contract formally verified - proceed with confidence",
                "references": [f"Spec file: {spec_file}"]
            })

        logger.info(f"Certora: Extracted {len(findings)} findings")
        return findings


__all__ = ["CertoraAdapter"]
