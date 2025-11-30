"""
Medusa Coverage-Guided Fuzzer Adapter - 2025 Security Enhancement
===================================================================

Integrates Medusa (Trail of Bits' coverage-guided fuzzer) to MIESC Layer 2.
Smarter fuzzing than random testing - follows code paths for deeper coverage.

Tool: Medusa by Trail of Bits (https://github.com/crytic/medusa)
Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: November 10, 2025
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

logger = logging.getLogger(__name__)


class MedusaAdapter(ToolAdapter):
    """
    Medusa Coverage-Guided Fuzzer Adapter for MIESC Layer 2.

    Medusa is a coverage-guided fuzzer from Trail of Bits that:
    - Uses coverage feedback to guide test generation
    - Explores deeper code paths than random fuzzing
    - Detects complex vulnerabilities through path exploration
    - Supports property-based testing
    - Generates reproducible test cases

    Expected Impact (2025 Roadmap):
    - +30-40% path coverage improvement over Echidna
    - Discovers edge cases in complex contracts
    - <60s execution time for standard fuzzing campaigns
    - Complements random fuzzing with intelligent path selection
    """

    # Default fuzzing configuration
    DEFAULT_CONFIG = {
        "test_limit": 10000,        # Number of test sequences
        "timeout": 300,              # Total timeout in seconds
        "coverage_target": 90,       # Target coverage percentage
        "corpus_dir": ".medusa_corpus",  # Corpus directory
        "shrink_corpus": True,       # Minimize corpus after fuzzing
        "assertion_testing": True,   # Test for assertion violations
        "optimization_testing": False,  # Test for gas optimizations
        "workers": 4                 # Parallel workers
    }

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="medusa",
            version="0.3.0",
            category=ToolCategory.DYNAMIC_TESTING,
            author="Trail of Bits (Adapter by Fernando Boiero)",
            license="MIT",
            homepage="https://github.com/crytic/medusa",
            repository="https://github.com/crytic/medusa",
            documentation="https://github.com/crytic/medusa/wiki",
            installation_cmd="cargo install medusa",
            capabilities=[
                ToolCapability(
                    name="coverage_guided_fuzzing",
                    description="Coverage-guided fuzzing with intelligent path exploration",
                    supported_languages=["solidity"],
                    detection_types=[
                        "assertion_violations",
                        "property_violations",
                        "integer_overflow",
                        "reentrancy",
                        "access_control_bypass",
                        "state_inconsistencies",
                        "race_conditions",
                        "edge_case_vulnerabilities"
                    ]
                )
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True  # DPGA compliance - graceful degradation
        )

    def is_available(self) -> ToolStatus:
        """
        Check if Medusa CLI is available and working.

        Returns:
            ToolStatus.AVAILABLE if medusa is installed and working
            ToolStatus.NOT_INSTALLED otherwise
        """
        try:
            result = subprocess.run(
                ["medusa", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )

            if result.returncode == 0:
                version = result.stdout.strip()
                logger.info(f"Medusa available: {version}")
                return ToolStatus.AVAILABLE
            else:
                logger.warning("Medusa command found but returned error")
                return ToolStatus.CONFIGURATION_ERROR

        except FileNotFoundError:
            logger.info("Medusa not installed (optional tool)")
            return ToolStatus.NOT_INSTALLED
        except subprocess.TimeoutExpired:
            logger.warning("Medusa version check timed out")
            return ToolStatus.CONFIGURATION_ERROR
        except Exception as e:
            logger.error(f"Error checking Medusa availability: {e}")
            return ToolStatus.CONFIGURATION_ERROR

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        """
        Execute Medusa fuzzing campaign on the contract.

        Args:
            contract_path: Path to Solidity project directory or file
            **kwargs:
                - test_limit: Number of test sequences (default: 10000)
                - timeout: Campaign timeout in seconds (default: 300)
                - coverage_target: Target coverage % (default: 90)
                - corpus_dir: Corpus directory path
                - workers: Number of parallel workers (default: 4)
                - config_file: Path to medusa.json config file

        Returns:
            Normalized results dictionary with:
            {
                "tool": "medusa",
                "version": "0.3.0",
                "status": "success" | "error",
                "findings": List[Dict],
                "metadata": Dict with coverage metrics,
                "execution_time": float,
                "error": Optional[str]
            }
        """
        start_time = time.time()

        # Check availability first
        status = self.is_available()
        if status != ToolStatus.AVAILABLE:
            return {
                "tool": "medusa",
                "version": "0.3.0",
                "status": "error",
                "findings": [],
                "metadata": {"tool_status": status.value},
                "execution_time": time.time() - start_time,
                "error": f"Medusa not available: {status.value}"
            }

        try:
            # Get configuration
            config = self.DEFAULT_CONFIG.copy()
            config.update(kwargs)

            test_limit = config.get("test_limit", 10000)
            timeout = config.get("timeout", 300)
            coverage_target = config.get("coverage_target", 90)
            workers = config.get("workers", 4)
            corpus_dir = config.get("corpus_dir", ".medusa_corpus")
            config_file = config.get("config_file", None)

            # Build command
            cmd = [
                "medusa",
                "fuzz",
                f"--test-limit={test_limit}",
                f"--timeout={timeout}",
                f"--workers={workers}",
                f"--corpus-dir={corpus_dir}",
                "--compilation-target", contract_path
            ]

            if config_file and Path(config_file).exists():
                cmd.extend(["--config", config_file])

            if config.get("shrink_corpus", True):
                cmd.append("--shrink-corpus")

            if config.get("assertion_testing", True):
                cmd.append("--assertion-mode")

            logger.info(f"Running Medusa fuzzing campaign: {' '.join(cmd)}")

            # Execute Medusa
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 30,  # Add buffer to subprocess timeout
                cwd=Path(contract_path).parent if Path(contract_path).is_file() else contract_path
            )

            execution_time = time.time() - start_time

            # Parse output
            findings = self.normalize_findings(result.stdout + result.stderr)

            # Extract coverage metrics from output
            coverage_info = self._extract_coverage_metrics(result.stdout)

            metadata = {
                "contract_analyzed": contract_path,
                "test_sequences": test_limit,
                "actual_tests_run": coverage_info.get("tests_run", 0),
                "coverage_achieved": coverage_info.get("coverage_percentage", 0),
                "coverage_target": coverage_target,
                "paths_explored": coverage_info.get("paths_explored", 0),
                "corpus_size": coverage_info.get("corpus_size", 0),
                "workers_used": workers,
                "exit_code": result.returncode,
                "campaign_completed": result.returncode == 0
            }

            if result.returncode != 0 and len(findings) == 0:
                # No findings but non-zero exit code might indicate error
                logger.warning(f"Medusa completed with exit code {result.returncode}")

            logger.info(
                f"Medusa campaign completed: {len(findings)} findings, "
                f"{coverage_info.get('coverage_percentage', 0)}% coverage in {execution_time:.2f}s"
            )

            return {
                "tool": "medusa",
                "version": "0.3.0",
                "status": "success" if result.returncode in [0, 1] else "error",
                "findings": findings,
                "metadata": metadata,
                "execution_time": execution_time
            }

        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            logger.error(f"Medusa fuzzing timed out after {timeout}s")
            return {
                "tool": "medusa",
                "version": "0.3.0",
                "status": "error",
                "findings": [],
                "metadata": {"timeout": timeout},
                "execution_time": execution_time,
                "error": f"Fuzzing campaign timed out after {timeout} seconds"
            }

        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"Unexpected error during Medusa fuzzing: {e}", exc_info=True)
            return {
                "tool": "medusa",
                "version": "0.3.0",
                "status": "error",
                "findings": [],
                "metadata": {"exception": str(e)},
                "execution_time": execution_time,
                "error": f"Unexpected error: {e}"
            }

    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        """
        Normalize Medusa findings to MIESC standard format.

        Args:
            raw_output: Raw text output from Medusa

        Returns:
            List of normalized findings
        """
        normalized = []

        try:
            lines = raw_output.split('\n') if isinstance(raw_output, str) else []

            # Medusa outputs findings in structured format
            # Look for patterns like:
            # [FAIL] assertion violated
            # [FAIL] property violated
            # [FAIL] integer overflow

            for idx, line in enumerate(lines):
                if '[FAIL]' in line or 'FAILURE' in line or 'violated' in line.lower():
                    # Extract finding details
                    finding_type = self._extract_finding_type(line)
                    location_info = self._extract_location(lines, idx)

                    normalized_finding = {
                        "id": f"medusa-{finding_type}-{idx}",
                        "type": finding_type,
                        "severity": self._determine_severity(finding_type),
                        "confidence": 0.85,  # Medusa has high confidence due to coverage-guided approach
                        "location": location_info,
                        "message": line.strip(),
                        "description": self._generate_description(finding_type, line),
                        "recommendation": self._get_recommendation(finding_type),
                        "swc_id": self._map_to_swc(finding_type),
                        "cwe_id": None,
                        "owasp_category": self._map_to_owasp(finding_type)
                    }

                    normalized.append(normalized_finding)

        except Exception as e:
            logger.error(f"Error normalizing Medusa findings: {e}", exc_info=True)

        return normalized

    def _extract_finding_type(self, line: str) -> str:
        """Extract vulnerability type from finding line."""
        line_lower = line.lower()

        if "assertion" in line_lower:
            return "assertion_violation"
        elif "property" in line_lower:
            return "property_violation"
        elif "overflow" in line_lower:
            return "integer_overflow"
        elif "underflow" in line_lower:
            return "integer_underflow"
        elif "reentrancy" in line_lower:
            return "reentrancy"
        elif "access" in line_lower:
            return "access_control"
        else:
            return "unknown_violation"

    def _extract_location(self, lines: List[str], idx: int) -> Dict[str, Any]:
        """Extract location information from context around finding."""
        # Look ahead for location info
        for i in range(idx, min(idx + 5, len(lines))):
            if "at" in lines[i] and ".sol:" in lines[i]:
                parts = lines[i].split(".sol:")
                if len(parts) >= 2:
                    file_path = parts[0].split()[-1] + ".sol"
                    line_num = int(parts[1].split(":")[0]) if ":" in parts[1] else 0
                    return {
                        "file": file_path,
                        "line": line_num,
                        "function": "unknown"
                    }

        return {"file": "unknown", "line": 0, "function": "unknown"}

    def _extract_coverage_metrics(self, output: str) -> Dict[str, Any]:
        """Extract coverage metrics from Medusa output."""
        metrics = {
            "tests_run": 0,
            "coverage_percentage": 0,
            "paths_explored": 0,
            "corpus_size": 0
        }

        try:
            lines = output.split('\n')
            for line in lines:
                if "coverage:" in line.lower():
                    # Extract percentage
                    parts = line.split()
                    for part in parts:
                        if '%' in part:
                            metrics["coverage_percentage"] = float(part.replace('%', ''))

                if "tests:" in line.lower() or "sequences:" in line.lower():
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part.isdigit():
                            metrics["tests_run"] = int(part)
                            break

        except Exception as e:
            logger.warning(f"Error extracting coverage metrics: {e}")

        return metrics

    def _determine_severity(self, finding_type: str) -> str:
        """Determine severity based on finding type."""
        severity_map = {
            "assertion_violation": "High",
            "property_violation": "High",
            "integer_overflow": "High",
            "integer_underflow": "High",
            "reentrancy": "Critical",
            "access_control": "High",
            "unknown_violation": "Medium"
        }
        return severity_map.get(finding_type, "Medium")

    def _generate_description(self, finding_type: str, line: str) -> str:
        """Generate detailed description for finding."""
        descriptions = {
            "assertion_violation": "An assertion was violated during fuzzing, indicating a contract invariant was broken",
            "property_violation": "A property test failed, suggesting unexpected behavior under certain conditions",
            "integer_overflow": "Integer overflow detected through coverage-guided fuzzing",
            "integer_underflow": "Integer underflow detected through coverage-guided fuzzing",
            "reentrancy": "Reentrancy vulnerability discovered through path exploration",
            "access_control": "Access control bypass detected during fuzzing campaign"
        }
        return descriptions.get(finding_type, line.strip())

    def _get_recommendation(self, finding_type: str) -> str:
        """Get remediation recommendation for finding type."""
        recommendations = {
            "assertion_violation": "Review the assertion condition and ensure contract invariants hold under all states",
            "property_violation": "Fix the property to handle edge cases discovered by the fuzzer",
            "integer_overflow": "Use SafeMath library or Solidity 0.8+ automatic overflow checks",
            "integer_underflow": "Use SafeMath library or Solidity 0.8+ automatic underflow checks",
            "reentrancy": "Apply checks-effects-interactions pattern and consider using ReentrancyGuard",
            "access_control": "Implement proper access control modifiers and validation"
        }
        return recommendations.get(finding_type, "Review and fix the discovered vulnerability")

    def _map_to_swc(self, finding_type: str) -> Optional[str]:
        """Map finding type to SWC ID."""
        swc_map = {
            "integer_overflow": "SWC-101",
            "integer_underflow": "SWC-101",
            "reentrancy": "SWC-107",
            "access_control": "SWC-105",
            "assertion_violation": "SWC-110"
        }
        return swc_map.get(finding_type)

    def _map_to_owasp(self, finding_type: str) -> Optional[str]:
        """Map finding type to OWASP Smart Contract Top 10 (2025)."""
        owasp_map = {
            "reentrancy": "SC01: Reentrancy",
            "access_control": "SC02: Access Control",
            "integer_overflow": "SC03: Arithmetic Issues",
            "integer_underflow": "SC03: Arithmetic Issues",
            "assertion_violation": "SC06: Unvalidated Inputs"
        }
        return owasp_map.get(finding_type)

    def can_analyze(self, contract_path: str) -> bool:
        """Check if Medusa can analyze the given contract/project."""
        path = Path(contract_path)

        # Medusa works best with project directories
        if path.is_dir():
            return any(path.glob('**/*.sol'))
        elif path.is_file():
            return path.suffix == '.sol'

        return False

    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration for Medusa."""
        return self.DEFAULT_CONFIG.copy()


# Export for registry
__all__ = ["MedusaAdapter"]
