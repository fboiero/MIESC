"""
Echidna Property-Based Fuzzer Adapter - Layer 2: Dynamic Testing
=================================================================

Echidna is a property-based fuzzer from Trail of Bits for Solidity contracts.
Uses random testing to find property violations and assertion failures.

Features:
- Property-based fuzzing (invariant testing)
- Assertion violation detection
- Coverage-guided fuzzing
- Corpus management
- Custom test campaigns

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: November 11, 2025
Version: 1.0.0
"""

from src.core.tool_protocol import (
    ToolAdapter, ToolMetadata, ToolStatus, ToolCategory, ToolCapability
)
from src.llm import enhance_findings_with_llm
from typing import Dict, Any, List, Optional
import subprocess
import json
import tempfile
import os
import time
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class EchidnaAdapter(ToolAdapter):
    """
    Echidna Property-Based Fuzzer for MIESC Layer 2

    Echidna performs property-based fuzzing to find invariant violations
    and assertion failures in Solidity contracts through intelligent
    random testing.

    DPGA Compliance: 100% PASS
    - Optional tool (graceful degradation if not installed)
    - No external API calls
    - Open source (can be self-hosted)
    """

    METADATA = {
        "name": "echidna",
        "version": "1.0.0",
        "category": "dynamic-testing",
        "description": "Property-based fuzzer for Solidity contracts",
        "is_optional": True,
        "requires": ["echidna"],
        "supported_languages": ["solidity"],
        "detection_types": [
            "invariant_violations",
            "assertion_failures",
            "property_violations",
            "state_inconsistencies"
        ]
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize Echidna adapter

        Args:
            config: Configuration dict with optional:
                - test_limit: Number of tests to run (default: 50000)
                - timeout: Timeout in seconds (default: 600)
                - corpus_dir: Directory for corpus files
                - config_file: Path to echidna.config.yaml
        """
        self.config = config or {}
        self.test_limit = self.config.get("test_limit", 50000)
        self.timeout = self.config.get("timeout", 600)
        self.corpus_dir = self.config.get("corpus_dir", None)
        self.config_file = self.config.get("config_file", None)

        logger.debug(f"Echidna adapter initialized (test_limit={self.test_limit})")

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="echidna",
            version="1.0.0",
            category=ToolCategory.DYNAMIC_TESTING,
            author="Trail of Bits (Adapter by Fernando Boiero)",
            license="AGPL-3.0",
            homepage="https://github.com/crytic/echidna",
            repository="https://github.com/crytic/echidna",
            documentation="https://github.com/crytic/echidna/wiki",
            installation_cmd="brew install echidna",
            capabilities=[
                ToolCapability(
                    name="property_based_fuzzing",
                    description="Property-based fuzzing for invariant testing",
                    supported_languages=["solidity"],
                    detection_types=["invariant_violations", "assertion_failures",
                                   "property_violations"]
                )
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True
        )

    def is_available(self) -> ToolStatus:
        """Check if Echidna is installed and available"""
        try:
            result = subprocess.run(
                ["echidna", "--version"],
                capture_output=True,
                timeout=5,
                text=True
            )
            if result.returncode == 0:
                logger.debug(f"Echidna available: {result.stdout.strip()}")
                return ToolStatus.AVAILABLE
            else:
                return ToolStatus.CONFIGURATION_ERROR
        except FileNotFoundError:
            logger.debug("Echidna not installed")
            return ToolStatus.NOT_INSTALLED
        except subprocess.TimeoutExpired:
            return ToolStatus.CONFIGURATION_ERROR
        except Exception as e:
            logger.error(f"Error checking Echidna availability: {e}")
            return ToolStatus.CONFIGURATION_ERROR

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Run Echidna property-based fuzzing on contract

        Args:
            contract_path: Path to Solidity contract file
            **kwargs: Additional arguments:
                - contract_name: Specific contract to test
                - test_mode: "property" or "assertion" (default: "property")
                - sender: Address to use as sender

        Returns:
            Dict containing:
                - tool: "echidna"
                - version: Version string
                - status: "success" or "error"
                - findings: List of property violations found
                - execution_time: Analysis duration
                - tests_run: Number of tests executed
                - coverage: Coverage information
        """
        start_time = time.time()

        # Check availability
        if self.is_available() != ToolStatus.AVAILABLE:
            return {
                "tool": "echidna",
                "status": "error",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": "Echidna not available"
            }

        try:
            # Build echidna command
            cmd = ["echidna", contract_path]

            # Add test limit
            cmd.extend(["--test-limit", str(self.test_limit)])

            # Add config file if specified
            if self.config_file and os.path.exists(self.config_file):
                cmd.extend(["--config", self.config_file])

            # Add corpus directory if specified
            if self.corpus_dir:
                os.makedirs(self.corpus_dir, exist_ok=True)
                cmd.extend(["--corpus-dir", self.corpus_dir])

            # Add contract name if specified
            contract_name = kwargs.get("contract_name")
            if contract_name:
                cmd.extend(["--contract", contract_name])

            # Add test mode if specified
            test_mode = kwargs.get("test_mode", "property")
            if test_mode == "assertion":
                cmd.append("--test-mode=assertion")

            logger.info(f"Running Echidna: {' '.join(cmd)}")

            # Run echidna
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=self.timeout,
                text=True,
                cwd=os.path.dirname(contract_path) or "."
            )

            duration = time.time() - start_time

            # Parse output
            findings = self._parse_output(result.stdout, result.stderr)

            # Enhance findings with OpenLLaMA (optional)
            try:
                with open(contract_path, 'r') as f:
                    contract_code = f.read()

                # Enhance top findings with LLM insights
                if findings:
                    findings = enhance_findings_with_llm(
                        findings[:5],  # Top 5 findings
                        contract_code,
                        "echidna"
                    )
            except Exception as e:
                logger.debug(f"LLM enhancement failed: {e}")

            # Extract metrics
            tests_run = self._extract_tests_run(result.stdout)
            coverage_info = self._extract_coverage(result.stdout)

            return {
                "tool": "echidna",
                "version": "1.0.0",
                "status": "success",
                "findings": findings,
                "execution_time": round(duration, 2),
                "tests_run": tests_run,
                "coverage": coverage_info,
                "test_limit": self.test_limit,
                "dpga_compliant": True
            }

        except subprocess.TimeoutExpired:
            logger.error(f"Echidna timeout after {self.timeout}s")
            return {
                "tool": "echidna",
                "status": "error",
                "findings": [],
                "execution_time": self.timeout,
                "error": f"Analysis timeout after {self.timeout}s"
            }
        except FileNotFoundError:
            return {
                "tool": "echidna",
                "status": "error",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": f"Contract file not found: {contract_path}"
            }
        except Exception as e:
            logger.error(f"Echidna analysis failed: {str(e)}")
            return {
                "tool": "echidna",
                "status": "error",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": str(e)
            }

    def _parse_output(self, stdout: str, stderr: str) -> List[Dict[str, Any]]:
        """
        Parse Echidna output to extract findings

        Echidna output format:
        echidna_property_name: failed!💥
          Call sequence:
            1. transfer(0x123, 100)
            2. withdraw(50)
        """
        findings = []

        lines = stdout.split('\n')
        current_finding = None
        call_sequence = []

        for line in lines:
            line = line.strip()

            # Detect failed property
            if 'failed' in line.lower() and ':' in line:
                if current_finding:
                    # Save previous finding
                    current_finding["call_sequence"] = call_sequence
                    findings.append(current_finding)
                    call_sequence = []

                # Start new finding
                property_name = line.split(':')[0].strip()
                current_finding = {
                    "type": "property_violation",
                    "severity": "high",
                    "property": property_name,
                    "description": f"Property {property_name} violated during fuzzing",
                    "recommendation": "Review the property definition and fix the contract logic"
                }

            # Detect assertion failures
            elif 'assertion' in line.lower() and 'failed' in line.lower():
                findings.append({
                    "type": "assertion_failure",
                    "severity": "critical",
                    "description": line,
                    "recommendation": "Fix the assertion failure in the contract"
                })

            # Extract call sequence
            elif line.startswith(tuple('0123456789')) and '.' in line:
                # Extract function call from numbered line
                parts = line.split('.', 1)
                if len(parts) == 2:
                    call_sequence.append(parts[1].strip())

        # Save last finding
        if current_finding:
            current_finding["call_sequence"] = call_sequence
            findings.append(current_finding)

        return findings

    def _extract_tests_run(self, output: str) -> int:
        """Extract number of tests run from output"""
        # Look for patterns like "Ran 50000 tests"
        import re
        match = re.search(r'(\d+)\s+tests?', output, re.IGNORECASE)
        if match:
            return int(match.group(1))
        return 0

    def _extract_coverage(self, output: str) -> Dict[str, Any]:
        """Extract coverage information from output"""
        # Echidna doesn't always provide detailed coverage
        # Return basic coverage info if available
        return {
            "available": False,
            "note": "Enable coverage with --coverage in config"
        }

    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        """
        Normalize findings to MIESC standard format

        Args:
            raw_output: Raw Echidna output or parsed findings

        Returns:
            List of normalized findings
        """
        if isinstance(raw_output, dict) and "findings" in raw_output:
            return raw_output["findings"]
        elif isinstance(raw_output, list):
            return raw_output
        else:
            return []

    def can_analyze(self, contract_path: str) -> bool:
        """Check if file can be analyzed"""
        path = Path(contract_path)
        return path.suffix == '.sol' and path.exists()

    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration for Echidna"""
        return {
            "test_limit": 50000,
            "timeout": 600,
            "test_mode": "property",
            "format": "text",
            "coverage": False
        }


# Adapter registration
def register_adapter():
    """Register Echidna adapter with MIESC"""
    return {
        "adapter_class": EchidnaAdapter,
        "metadata": EchidnaAdapter.METADATA
    }


__all__ = ["EchidnaAdapter", "register_adapter"]
