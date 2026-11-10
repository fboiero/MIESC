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

import logging
import re
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from miesc.adapters._fuzz_result import apply_fuzz_verdict
from miesc.core.tool_protocol import (
    ToolAdapter,
    ToolCapability,
    ToolCategory,
    ToolMetadata,
    ToolStatus,
)

logger = logging.getLogger(__name__)

# medusa colorizes output even when piped; strip ANSI before parsing.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# Signatures of a real tool failure (crytic-compile crash, missing binary, a Go
# panic) — distinct from medusa's own "couldn't fuzz" aborts ("specify target
# contract(s)", "constructor arguments ... not provided"), which are an honest
# inconclusive, not an error. Matched case-insensitively on the ANSI-stripped output.
_TOOL_FAILURE_MARKERS = (
    "traceback (most recent call last)",
    "modulenotfounderror",
    "valueerror:",
    "command not found",
    "no such file or directory",
    "is not a file or directory",
    "panic:",
)


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
        "test_limit": 10000,  # Number of test sequences
        "timeout": 300,  # Total timeout in seconds
        "coverage_target": 90,  # Target coverage percentage
        "corpus_dir": ".medusa_corpus",  # Corpus directory
        "shrink_corpus": True,  # Minimize corpus after fuzzing
        "assertion_testing": True,  # Test for assertion violations
        "optimization_testing": False,  # Test for gas optimizations
        "workers": 4,  # Parallel workers
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
                        "edge_case_vulnerabilities",
                    ],
                )
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True,  # DPGA compliance - graceful degradation
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
                ["medusa", "--version"], capture_output=True, text=True, timeout=5
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

    def analyze(self, contract_path: str, **kwargs: Any) -> Dict[str, Any]:
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
                "error": f"Medusa not available: {status.value}",
            }

        try:
            # Get configuration
            config: Dict[str, Any] = self.DEFAULT_CONFIG.copy()
            config.update(kwargs)

            test_limit = config.get("test_limit", 10000)
            timeout = config.get("timeout", 300)
            coverage_target = config.get("coverage_target", 90)
            workers = config.get("workers", 4)

            from miesc.adapters._medusa_harness import select_targets, write_medusa_config

            # Medusa (1.3.x) needs explicit target contracts and a property-test
            # prefix config: run it via a generated medusa.json rather than the
            # old `--assertion-mode` flag (removed in 1.3.x) and a bare target,
            # which exited 1 before fuzzing anything. Prefer a real
            # property/invariant/echidna harness; fall back to first-party source.
            path = Path(contract_path)
            project_dir = (
                path if path.is_dir() else (path.parent if path.parent != Path("") else Path("."))
            )
            # Absolute: medusa resolves `compilation.target` relative to the
            # config file's directory, and the config lives in a temp dir.
            compilation_target = str(path.resolve())
            targets, target_source = select_targets(contract_path)

            if not targets:
                return {
                    "tool": "medusa",
                    "version": "0.3.0",
                    "status": "error",
                    "findings": [],
                    "metadata": {"reason": "no_target_contracts", "target_source": target_source},
                    "execution_time": time.time() - start_time,
                    "error": "Medusa: no first-party target contracts found to fuzz",
                }

            harness_reason = (
                None
                if target_source == "harness"
                else "no fuzzable property/invariant/echidna harness found in the project"
            )

            with tempfile.TemporaryDirectory(prefix="miesc-medusa-") as tmp:
                config_path = write_medusa_config(
                    Path(tmp),
                    targets=targets,
                    compilation_target=compilation_target,
                    test_limit=test_limit,
                    timeout=timeout,
                    workers=workers,
                )
                cmd = ["medusa", "fuzz", "--config", str(config_path)]
                logger.info(
                    f"Running Medusa: targets={targets} source={target_source} "
                    f"compilation_target={compilation_target}"
                )

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout + 30,  # buffer so medusa's own timeout fires first
                    cwd=str(project_dir),
                )

            execution_time = time.time() - start_time

            # Parse output
            findings = self.normalize_findings(result.stdout + result.stderr)

            # Extract coverage metrics from output
            coverage_info = self._extract_coverage_metrics(result.stdout)

            metadata = {
                "contract_analyzed": contract_path,
                "target_contracts": targets,
                "target_source": target_source,
                "test_sequences": test_limit,
                "calls_executed": coverage_info.get("calls", 0),
                "branches_hit": coverage_info.get("branches_hit", 0),
                "tests_passed": coverage_info.get("tests_passed", 0),
                "tests_failed": coverage_info.get("tests_failed", 0),
                "corpus_size": coverage_info.get("corpus_size", 0),
                "coverage_target": coverage_target,
                "workers_used": workers,
                "exit_code": result.returncode,
                "campaign_completed": result.returncode == 0,
            }
            if harness_reason:
                metadata["harness_note"] = harness_reason

            logger.info(
                f"Medusa campaign: {len(findings)} findings, "
                f"{coverage_info.get('calls', 0)} calls / "
                f"{coverage_info.get('branches_hit', 0)} branches in {execution_time:.2f}s"
            )

            # The campaign exercised the contract iff medusa executed fuzzing
            # transactions, grew a corpus, or evaluated tests. Branches-hit alone
            # (from deployment) is not enough — none of these on a successful exit
            # means it never actually fuzzed, and "0 findings" is inconclusive.
            exercised = (
                int(coverage_info.get("calls", 0) or 0) > 0
                or int(coverage_info.get("corpus_size", 0) or 0) > 0
                or (
                    int(coverage_info.get("tests_passed", 0) or 0)
                    + int(coverage_info.get("tests_failed", 0) or 0)
                )
                > 0
            )

            diagnostic_text = (result.stdout or "") + (result.stderr or "")

            # A run that never fuzzed is normally inconclusive — but a genuine
            # tool failure (crytic-compile crash, missing solc, a Go panic) is an
            # error the user must see, not a quiet "no coverage". Exit code alone
            # cannot tell them apart (exit 6 is also the no-harness case); the
            # output text can.
            if not exercised and any(
                marker in _ANSI_RE.sub("", diagnostic_text).lower()
                for marker in _TOOL_FAILURE_MARKERS
            ):
                return {
                    "tool": "medusa",
                    "version": "0.3.0",
                    "status": "error",
                    "findings": findings,
                    "metadata": metadata,
                    "execution_time": execution_time,
                    "error": _ANSI_RE.sub("", diagnostic_text).strip()[-400:],
                }

            result_dict = {
                "tool": "medusa",
                "version": "0.3.0",
                "status": "success",
                "findings": findings,
                "metadata": metadata,
                "execution_time": execution_time,
            }
            # The subprocess completed and did not hard-fail, so let the exercise
            # signal decide: a run that fuzzed is success (findings force it); one
            # that never fuzzed — no harness, a non-deployable target, a deploy
            # abort — is inconclusive, with WHY leading the diagnostic.
            diag_prefix = f"{harness_reason}. " if (harness_reason and not exercised) else ""
            apply_fuzz_verdict(
                result_dict,
                tool="medusa",
                exercised=exercised,
                diagnostic=diag_prefix + diagnostic_text,
            )
            return result_dict

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
                "error": f"Fuzzing campaign timed out after {timeout} seconds",
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
                "error": f"Unexpected error: {e}",
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
            text = _ANSI_RE.sub("", raw_output) if isinstance(raw_output, str) else ""
            lines = text.split("\n")

            # medusa 1.3.x reports a falsified test as, e.g.
            #   [FAILED] Property Test: C.property_x()
            #   [FAILED] Assertion Test: C.f(uint256)
            # (older phrasings: "[FAIL]", "FAILURE", "violated"). Never count a
            # "[PASSED]" line.

            for idx, line in enumerate(lines):
                is_failure = (
                    "[FAILED]" in line
                    or "[FAIL]" in line
                    or "FAILURE" in line
                    or "violated" in line.lower()
                )
                if is_failure and "[PASSED]" not in line:
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
                        "owasp_category": self._map_to_owasp(finding_type),
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
                    return {"file": file_path, "line": line_num, "function": "unknown"}

        return {"file": "unknown", "line": 0, "function": "unknown"}

    def _extract_coverage_metrics(self, output: str) -> Dict[str, Any]:
        """Extract coverage metrics from medusa 1.3.x output (ANSI-stripped).

        medusa reports progress as, e.g.
        ``fuzz: elapsed: 3s, calls: 140003 (46667/sec), seq/s: 466,
        branches hit: 81, corpus: 2, failures: 0/1399, gas/s: ...``
        and a final ``Test summary: N test(s) passed, M test(s) failed``.
        There is no "coverage: N%" line, so the exercised signal is calls /
        corpus / tests, not a percentage."""
        metrics: Dict[str, Any] = {
            "calls": 0,
            "branches_hit": 0,
            "corpus_size": 0,
            "tests_passed": 0,
            "tests_failed": 0,
        }

        try:
            text = _ANSI_RE.sub("", output or "")
            # Successive progress lines overwrite; the last match wins (final count).
            for m in re.finditer(r"calls:\s*(\d+)", text):
                metrics["calls"] = int(m.group(1))
            for m in re.finditer(r"branches hit:\s*(\d+)", text):
                metrics["branches_hit"] = int(m.group(1))
            for m in re.finditer(r"corpus:\s*(\d+)", text):
                metrics["corpus_size"] = int(m.group(1))
            summary = re.search(
                r"Test summary:\s*(\d+)\s*test\(s\)\s*passed,\s*(\d+)\s*test\(s\)\s*failed",
                text,
            )
            if summary:
                metrics["tests_passed"] = int(summary.group(1))
                metrics["tests_failed"] = int(summary.group(2))
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
            "unknown_violation": "Medium",
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
            "access_control": "Access control bypass detected during fuzzing campaign",
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
            "access_control": "Implement proper access control modifiers and validation",
        }
        return recommendations.get(finding_type, "Review and fix the discovered vulnerability")

    def _map_to_swc(self, finding_type: str) -> Optional[str]:
        """Map finding type to SWC ID."""
        swc_map = {
            "integer_overflow": "SWC-101",
            "integer_underflow": "SWC-101",
            "reentrancy": "SWC-107",
            "access_control": "SWC-105",
            "assertion_violation": "SWC-110",
        }
        return swc_map.get(finding_type)

    def _map_to_owasp(self, finding_type: str) -> Optional[str]:
        """Map finding type to OWASP Smart Contract Top 10 (2025)."""
        owasp_map = {
            "reentrancy": "SC01: Reentrancy",
            "access_control": "SC02: Access Control",
            "integer_overflow": "SC03: Arithmetic Issues",
            "integer_underflow": "SC03: Arithmetic Issues",
            "assertion_violation": "SC06: Unvalidated Inputs",
        }
        return owasp_map.get(finding_type)

    def can_analyze(self, contract_path: str) -> bool:
        """Check if Medusa can analyze the given contract/project."""
        path = Path(contract_path)

        # Medusa works best with project directories
        if path.is_dir():
            return any(path.glob("**/*.sol"))
        elif path.is_file():
            return path.suffix == ".sol"

        return False

    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration for Medusa."""
        return self.DEFAULT_CONFIG.copy()


# Export for registry
__all__ = ["MedusaAdapter"]
