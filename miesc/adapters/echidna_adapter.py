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

import logging
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, cast

from miesc.adapters._fuzz_result import apply_fuzz_verdict
from miesc.core.tool_protocol import (
    ToolAdapter,
    ToolCapability,
    ToolCategory,
    ToolMetadata,
    ToolStatus,
)
from miesc.llm import enhance_findings_with_llm

logger = logging.getLogger(__name__)

# CSI / charset escape sequences and carriage returns that Echidna emits under a tty.
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][AB012]|\r")


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def _run_capturing_pty(cmd: List[str], cwd: str, timeout: int) -> tuple[int, str]:
    """Run ``cmd`` under a pseudo-tty and return ``(returncode, combined_output)``.

    Echidna gates its full (non-TUI) output on a controlling terminal: a plain captured
    subprocess receives only the compile banner and drops every ``name: failed!`` verdict, so
    the run looks clean even when properties were falsified. A pty makes Echidna emit the
    complete text output, which we strip of ANSI control codes. Raises
    :class:`subprocess.TimeoutExpired` on timeout. Falls back to a plain pipe where ``pty`` is
    unavailable (e.g. Windows).
    """
    # Echidna shells out to its own Python toolchain (crytic-compile, slither). MIESC's
    # PYTHON* environment (a PYTHONPATH into the package, PYTHONNOUSERSITE isolating the venv)
    # leaks into that child and makes crytic-compile unimportable ("Couldn't compile given
    # file"), so strip those variables for the subprocess and let Echidna find its own install.
    child_env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}

    try:
        import pty
        import select
    except ImportError:  # pragma: no cover - non-POSIX
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd, env=child_env
        )
        return proc.returncode, _strip_ansi((proc.stdout or "") + (proc.stderr or ""))

    master, slave = pty.openpty()
    process = subprocess.Popen(
        cmd,
        stdin=slave,
        stdout=slave,
        stderr=slave,
        cwd=cwd,
        close_fds=True,
        start_new_session=True,
        env=child_env,
    )
    os.close(slave)
    chunks: List[bytes] = []
    deadline = time.time() + timeout
    timed_out = False
    try:
        # Read until EOF (the slave closes when the child and its children all exit, which
        # surfaces as an empty read or EIO) rather than on process exit: Echidna flushes its
        # final verdict lines as it is tearing down, so stopping at process.poll() truncates
        # exactly the output we need.
        while True:
            if time.time() > deadline:
                process.kill()
                timed_out = True
                break
            try:
                readable, _, _ = select.select([master], [], [], 1.0)
            except (OSError, ValueError):
                break
            if master in readable:
                try:
                    data = os.read(master, 65536)
                except OSError:  # slave fully closed (EIO on Linux)
                    break
                if not data:  # EOF
                    break
                chunks.append(data)
    finally:
        try:
            os.close(master)
        except OSError:
            pass
        try:
            process.wait(timeout=5)
        except Exception:
            process.kill()
    if timed_out:
        raise subprocess.TimeoutExpired(cmd, timeout)
    output = b"".join(chunks).decode("utf-8", errors="replace")
    return (process.returncode or 0), _strip_ansi(output)


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
            "state_inconsistencies",
        ],
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
                    detection_types=[
                        "invariant_violations",
                        "assertion_failures",
                        "property_violations",
                    ],
                )
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True,
        )

    def is_available(self) -> ToolStatus:
        """Check if Echidna is installed and available"""
        try:
            result = subprocess.run(
                ["echidna", "--version"], capture_output=True, timeout=5, text=True
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

    def analyze(self, contract_path: str, **kwargs: Any) -> Dict[str, Any]:
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
                "error": "Echidna not available",
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

            # Line-oriented text output. Echidna's default TUI renders via cursor control that
            # does not survive capture; --format text emits the `name: failed!/passing` verdict
            # lines that _parse_output reads.
            cmd.extend(["--format", "text"])

            logger.info(f"Running Echidna: {' '.join(cmd)}")

            # Run under a pseudo-tty. Echidna only emits its full results when it believes a
            # terminal is attached, so a plain captured subprocess loses every verdict line and
            # the run looks clean even when properties were falsified.
            returncode, output = _run_capturing_pty(
                cmd, cwd=os.path.dirname(contract_path) or ".", timeout=self.timeout
            )

            duration = time.time() - start_time

            # Parse output (combined stdout+stderr, ANSI stripped, from the pty)
            findings = self._parse_output(output, "")
            # Enhance findings with OpenLLaMA (opt-in via llm_enhance=True)
            # Default: SKIP — adds 8s per finding. Enable for client reports.
            if kwargs.get("llm_enhance", False):
                try:
                    with open(contract_path, "r") as fc:
                        contract_code = fc.read()
                    if findings:
                        findings = enhance_findings_with_llm(findings[:5], contract_code, "echidna")
                except Exception as e:
                    logger.debug(f"LLM enhancement failed: {e}")

            # Extract metrics
            tests_run = self._extract_tests_run(output)
            coverage_info = self._extract_coverage(output)

            # Did echidna actually drive the contract? A degenerate run (empty
            # ABI, no properties, compile failure) evaluates nothing — reporting
            # its "0 findings" as a clean pass would be a false negative.
            exercised = tests_run > 0 or self._campaign_exercised(output)

            result_dict = {
                "tool": "echidna",
                "version": "1.0.0",
                "status": "success",
                "findings": findings,
                "execution_time": round(duration, 2),
                "tests_run": tests_run,
                "coverage": coverage_info,
                "test_limit": self.test_limit,
                "dpga_compliant": True,
            }
            apply_fuzz_verdict(result_dict, tool="echidna", exercised=exercised, diagnostic=output)
            return result_dict

        except subprocess.TimeoutExpired:
            logger.error(f"Echidna timeout after {self.timeout}s")
            return {
                "tool": "echidna",
                "status": "error",
                "findings": [],
                "execution_time": self.timeout,
                "error": f"Analysis timeout after {self.timeout}s",
            }
        except FileNotFoundError:
            return {
                "tool": "echidna",
                "status": "error",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": f"Contract file not found: {contract_path}",
            }
        except Exception as e:
            logger.error(f"Echidna analysis failed: {str(e)}")
            return {
                "tool": "echidna",
                "status": "error",
                "findings": [],
                "execution_time": time.time() - start_time,
                "error": str(e),
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

        lines = stdout.split("\n")
        current_finding: Optional[Dict[str, Any]] = None
        call_sequence: List[str] = []

        for line in lines:
            line = line.strip()

            # Detect a falsified property: Echidna prints `name: failed!💥` for a violation.
            # Require the `!` so log noise such as "WARNING: Running slither failed." (a period,
            # not a verdict) does not read as a finding.
            verdict = re.match(r"(\w+):\s*failed!", line)
            if verdict:
                if current_finding:
                    # Save previous finding
                    current_finding["call_sequence"] = call_sequence
                    findings.append(current_finding)
                    call_sequence = []

                # Start new finding
                property_name = verdict.group(1)
                current_finding = {
                    "type": "property_violation",
                    "severity": "high",
                    "property": property_name,
                    "description": f"Property {property_name} violated during fuzzing",
                    "recommendation": "Review the property definition and fix the contract logic",
                }

            # Detect assertion failures
            elif "assertion" in line.lower() and "failed" in line.lower():
                findings.append(
                    {
                        "type": "assertion_failure",
                        "severity": "critical",
                        "description": line,
                        "recommendation": "Fix the assertion failure in the contract",
                    }
                )

            # Extract call sequence
            elif line.startswith(tuple("0123456789")) and "." in line:
                # Extract function call from numbered line
                parts = line.split(".", 1)
                if len(parts) == 2:
                    call_sequence.append(parts[1].strip())

        # Save last finding
        if current_finding:
            current_finding["call_sequence"] = call_sequence
            findings.append(current_finding)

        return findings

    # Markers that only appear once Echidna has actually driven the EVM or
    # resolved a property/assertion. A degenerate run (empty ABI, no
    # properties, compile failure) prints none of them.
    # Only markers that appear AFTER real execution — never count-bearing
    # status lines like "fuzzing: 0/50000" or "tests found: 0", which can show
    # up before a single call and would re-open the false-clean side door.
    _EXERCISED_MARKERS = (
        ": passing",
        ": passed",
        "passed!",
        ": failing",
        "failed!",
        "unique instructions:",
        "total calls:",
        "corpus size:",
    )

    def _campaign_exercised(self, output: str) -> bool:
        """True iff Echidna's output shows it evaluated at least one property or
        executed fuzzing transactions. Used to distinguish a genuine clean run
        from a campaign that never ran (which must not be reported as clean)."""
        lowered = output.lower()
        return any(marker in lowered for marker in self._EXERCISED_MARKERS)

    def _extract_tests_run(self, output: str) -> int:
        """Extract the number of properties Echidna evaluated from its output.

        Echidna's status line reads ``[status] tests: 2/2, fuzzing: ...``; the first number is
        the count of properties resolved and the second the total. Fall back to the older
        ``Ran N tests`` phrasing.
        """
        match = re.search(r"tests:\s*(\d+)\s*/\s*(\d+)", output, re.IGNORECASE)
        if match:
            return int(match.group(2))
        match = re.search(r"(\d+)\s+tests?", output, re.IGNORECASE)
        if match:
            return int(match.group(1))
        return 0

    def _extract_coverage(self, output: str) -> Dict[str, Any]:
        """Extract coverage information from output"""
        # Echidna doesn't always provide detailed coverage
        # Return basic coverage info if available
        return {"available": False, "note": "Enable coverage with --coverage in config"}

    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        """
        Normalize findings to MIESC standard format

        Args:
            raw_output: Raw Echidna output or parsed findings

        Returns:
            List of normalized findings
        """
        if isinstance(raw_output, dict) and "findings" in raw_output:
            return cast(list[dict[str, Any]], raw_output["findings"])
        elif isinstance(raw_output, list):
            return raw_output
        else:
            return []

    def can_analyze(self, contract_path: str) -> bool:
        """Check if file can be analyzed"""
        path = Path(contract_path)
        return path.suffix == ".sol" and path.exists()

    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration for Echidna"""
        return {
            "test_limit": 50000,
            "timeout": 600,
            "test_mode": "property",
            "format": "text",
            "coverage": False,
        }


# Adapter registration
def register_adapter() -> Dict[str, Any]:
    """Register Echidna adapter with MIESC"""
    return {"adapter_class": EchidnaAdapter, "metadata": EchidnaAdapter.METADATA}


__all__ = ["EchidnaAdapter", "register_adapter"]
