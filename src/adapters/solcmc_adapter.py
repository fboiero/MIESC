"""
SolCMC Adapter - Solidity CHC Model Checker.

Uses the Constrained Horn Clauses (CHC) engine built into the Solidity
compiler (solc) for formal verification of contract properties.

Complements SMTChecker with CHC-specific analysis:
- Assertion violations
- Overflow/underflow detection
- Division by zero
- Out-of-bounds access
- Unreachable code
- Trivial conditions

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: 2026-01-31
License: AGPL-3.0
"""

import hashlib
import json
import logging
import re
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

logger = logging.getLogger(__name__)


SOLCMC_TARGETS = {
    "assert": {
        "severity": "High",
        "swc_id": "SWC-110",
        "cwe_id": "CWE-617",
        "description": "Assertion violation detected by CHC model checker",
        "recommendation": "Fix the assertion condition or add proper preconditions",
    },
    "underflow": {
        "severity": "High",
        "swc_id": "SWC-101",
        "cwe_id": "CWE-191",
        "description": "Arithmetic underflow possible (unchecked block or pre-0.8 code)",
        "recommendation": "Use checked arithmetic or SafeMath library",
    },
    "overflow": {
        "severity": "High",
        "swc_id": "SWC-101",
        "cwe_id": "CWE-190",
        "description": "Arithmetic overflow possible (unchecked block or pre-0.8 code)",
        "recommendation": "Use checked arithmetic or SafeMath library",
    },
    "divByZero": {
        "severity": "Medium",
        "swc_id": "SWC-101",
        "cwe_id": "CWE-369",
        "description": "Division by zero possible",
        "recommendation": "Add require(divisor != 0) check before division",
    },
    "constantCondition": {
        "severity": "Low",
        "swc_id": None,
        "cwe_id": "CWE-570",
        "description": "Condition is always true or always false (trivial condition)",
        "recommendation": "Remove dead code or fix the logic error",
    },
    "popEmptyArray": {
        "severity": "Medium",
        "swc_id": None,
        "cwe_id": "CWE-129",
        "description": "Pop on empty array - array underflow",
        "recommendation": "Check array length before pop()",
    },
    "outOfBounds": {
        "severity": "High",
        "swc_id": None,
        "cwe_id": "CWE-129",
        "description": "Array/mapping index out of bounds access",
        "recommendation": "Add bounds checking before array access",
    },
    "balance": {
        "severity": "Medium",
        "swc_id": None,
        "cwe_id": "CWE-682",
        "description": "Insufficient balance for transfer operation",
        "recommendation": "Add balance check before transfer",
    },
}


class SolCMCAdapter(ToolAdapter):
    """
    Solidity CHC model checker adapter.

    Uses solc's built-in model checker with the CHC engine for
    formal verification of contract properties.
    """

    def __init__(self):
        super().__init__()
        self._solc_path: Optional[str] = None
        self._solc_version: Optional[str] = None

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="solcmc",
            version="1.0.0",
            category=ToolCategory.FORMAL_VERIFICATION,
            author="Ethereum Foundation (solc) / MIESC integration by Fernando Boiero",
            license="GPL-3.0",
            homepage="https://docs.soliditylang.org/en/latest/smtchecker.html",
            repository="https://github.com/ethereum/solidity",
            documentation="https://docs.soliditylang.org/en/latest/smtchecker.html#model-checking",
            installation_cmd="pip install solc-select && solc-select install 0.8.25 && solc-select use 0.8.25",
            capabilities=[
                ToolCapability(
                    name="chc_verification",
                    description="CHC-based formal verification of Solidity contracts",
                    supported_languages=["solidity"],
                    detection_types=[
                        "assertion_violation",
                        "overflow",
                        "underflow",
                        "division_by_zero",
                        "out_of_bounds",
                    ],
                ),
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True,
        )

    def is_available(self) -> ToolStatus:
        solc = shutil.which("solc")
        if not solc:
            return ToolStatus.NOT_INSTALLED

        try:
            result = subprocess.run(
                [solc, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            version_match = re.search(r"(\d+\.\d+\.\d+)", result.stdout)
            if version_match:
                self._solc_version = version_match.group(1)
                self._solc_path = solc
                parts = self._solc_version.split(".")
                if int(parts[0]) == 0 and int(parts[1]) >= 8:
                    return ToolStatus.AVAILABLE
        except Exception:
            pass

        return ToolStatus.NOT_INSTALLED

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        start_time = time.time()
        contract_path = str(Path(contract_path).resolve())
        timeout = kwargs.get("timeout", 120)

        if self.is_available() != ToolStatus.AVAILABLE:
            return self._run_fallback_analysis(contract_path, start_time)

        try:
            return self._run_solcmc(contract_path, start_time, timeout)
        except Exception as e:
            logger.debug(f"SolCMC failed, using fallback: {e}")
            return self._run_fallback_analysis(contract_path, start_time)

    def _run_solcmc(self, contract_path: str, start_time: float, timeout: int) -> Dict[str, Any]:
        solc = self._solc_path or shutil.which("solc")
        targets = ",".join(SOLCMC_TARGETS.keys())

        cmd = [
            solc,
            "--model-checker-engine", "chc",
            "--model-checker-targets", targets,
            "--model-checker-timeout", str(timeout * 1000),
            contract_path,
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 10,
            )

            raw_findings = self._parse_solc_output(result.stderr + result.stdout, contract_path)
            findings = self.normalize_findings(raw_findings)

            return {
                "tool": "solcmc",
                "version": self._solc_version or "unknown",
                "status": "success",
                "findings": findings,
                "metadata": {
                    "mode": "chc_engine",
                    "contract": contract_path,
                    "solc_version": self._solc_version,
                    "targets": list(SOLCMC_TARGETS.keys()),
                },
                "execution_time": time.time() - start_time,
                "error": None,
            }
        except subprocess.TimeoutExpired:
            return {
                "tool": "solcmc",
                "version": self._solc_version or "unknown",
                "status": "error",
                "findings": [],
                "metadata": {"mode": "chc_engine", "contract": contract_path},
                "execution_time": time.time() - start_time,
                "error": "CHC solver timeout exceeded",
            }

    def _parse_solc_output(self, output: str, contract_path: str) -> List[Dict[str, Any]]:
        """Parse solc model checker output for findings."""
        findings = []

        # Pattern: Warning: CHC: <target> happens here.
        warning_pattern = re.compile(
            r"Warning:\s+CHC:\s+(\w[\w\s]*?)\s+(?:happens|might happen|violation)\s+here\.\s*"
            r"(?:-->)?\s*([^:\n]+)?:?(\d+)?:?(\d+)?",
            re.MULTILINE,
        )

        for match in warning_pattern.finditer(output):
            target_text = match.group(1).strip().lower()
            file_ref = match.group(2) or contract_path
            line = int(match.group(3)) if match.group(3) else 0

            # Map to target type
            target_type = None
            for key in SOLCMC_TARGETS:
                if key.lower() in target_text:
                    target_type = key
                    break

            if not target_type:
                if "assert" in target_text:
                    target_type = "assert"
                elif "overflow" in target_text:
                    target_type = "overflow"
                elif "underflow" in target_text:
                    target_type = "underflow"
                elif "division" in target_text or "divbyzero" in target_text:
                    target_type = "divByZero"
                else:
                    target_type = "assert"  # Default

            findings.append({
                "target": target_type,
                "file": file_ref.strip(),
                "line": line,
                "raw_message": match.group(0).strip(),
            })

        # Also parse counterexample info
        ce_pattern = re.compile(
            r"Counterexample:\s*\n((?:\s+\w+\s*=\s*\S+\n?)+)",
            re.MULTILINE,
        )
        counterexamples = ce_pattern.findall(output)

        # Attach counterexamples to findings
        for i, ce in enumerate(counterexamples):
            if i < len(findings):
                findings[i]["counterexample"] = ce.strip()

        return findings

    def _run_fallback_analysis(self, contract_path: str, start_time: float) -> Dict[str, Any]:
        """Fallback analysis when solc is not available."""
        try:
            with open(contract_path, "r", errors="ignore") as f:
                source_code = f.read()
        except Exception as e:
            return {
                "tool": "solcmc",
                "version": "fallback",
                "status": "error",
                "findings": [],
                "metadata": {},
                "execution_time": time.time() - start_time,
                "error": str(e),
            }

        lines = source_code.split("\n")
        raw_findings = []

        # Check for unchecked blocks with arithmetic
        unchecked_pattern = re.compile(r"unchecked\s*\{", re.MULTILINE)
        for match in unchecked_pattern.finditer(source_code):
            line_num = source_code[:match.start()].count("\n") + 1
            # Check if arithmetic operations inside
            depth = 0
            pos = match.start() + match.end() - match.start()
            block_start = pos
            for pos in range(block_start, min(block_start + 500, len(source_code))):
                if source_code[pos] == "{":
                    depth += 1
                elif source_code[pos] == "}":
                    if depth == 0:
                        break
                    depth -= 1

            block = source_code[block_start:pos]
            if re.search(r"[+\-\*]", block):
                raw_findings.append({
                    "target": "overflow",
                    "file": contract_path,
                    "line": line_num,
                    "raw_message": "Unchecked arithmetic block - potential overflow/underflow",
                })

        # Check for assert statements
        for i, line in enumerate(lines, 1):
            if re.search(r"\bassert\s*\(", line):
                raw_findings.append({
                    "target": "assert",
                    "file": contract_path,
                    "line": i,
                    "raw_message": f"Assert statement - verify condition always holds: {line.strip()}",
                })

        # Check for division without zero check
        for i, line in enumerate(lines, 1):
            if re.search(r"\s/\s", line) and not re.search(r"require.*!=\s*0", "\n".join(lines[max(0, i - 3):i])):
                raw_findings.append({
                    "target": "divByZero",
                    "file": contract_path,
                    "line": i,
                    "raw_message": f"Division without zero check: {line.strip()}",
                })

        # Check for array access without bounds check
        for i, line in enumerate(lines, 1):
            if re.search(r"\w+\[\w+\]", line) and re.search(r"(delete|=)", line):
                context = "\n".join(lines[max(0, i - 5):i])
                if not re.search(r"require.*length|require.*<", context):
                    raw_findings.append({
                        "target": "outOfBounds",
                        "file": contract_path,
                        "line": i,
                        "raw_message": f"Array access without bounds check: {line.strip()}",
                    })

        findings = self.normalize_findings(raw_findings)

        return {
            "tool": "solcmc",
            "version": "fallback",
            "status": "success",
            "findings": findings,
            "metadata": {
                "mode": "fallback_analysis",
                "contract": contract_path,
                "solc_available": False,
            },
            "execution_time": time.time() - start_time,
            "error": None,
        }

    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        if not raw_output:
            return []

        findings = []
        for item in raw_output:
            if not isinstance(item, dict):
                continue

            target = item.get("target", "assert")
            target_config = SOLCMC_TARGETS.get(target, SOLCMC_TARGETS["assert"])

            finding_id = hashlib.md5(
                f"solcmc:{target}:{item.get('file', '')}:{item.get('line', 0)}".encode()
            ).hexdigest()[:12]

            message = item.get("raw_message", target_config["description"])
            ce = item.get("counterexample")
            if ce:
                message += f"\nCounterexample: {ce}"

            findings.append({
                "id": f"CMC-{finding_id}",
                "type": f"solcmc_{target}",
                "severity": target_config["severity"],
                "confidence": 0.85,
                "location": {
                    "file": item.get("file", ""),
                    "line": item.get("line", 0),
                    "function": "",
                },
                "message": message,
                "description": target_config["description"],
                "recommendation": target_config["recommendation"],
                "swc_id": target_config.get("swc_id"),
                "cwe_id": target_config.get("cwe_id"),
                "tool": "solcmc",
            })

        return findings
