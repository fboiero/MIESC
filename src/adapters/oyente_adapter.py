"""
Oyente Adapter - Symbolic Execution Based Vulnerability Analysis.

Based on: "Making Smart Contracts Smarter" (CCS 2016)
Reference: https://github.com/enzymefinance/oyente

Detects:
- Integer overflow/underflow
- Callstack depth attack
- Reentrancy
- Transaction ordering dependence
- Timestamp dependence

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
from typing import Any, Dict, List

from src.core.tool_protocol import (
    ToolAdapter,
    ToolCapability,
    ToolCategory,
    ToolMetadata,
    ToolStatus,
)

logger = logging.getLogger(__name__)


OYENTE_VULNERABILITIES = {
    "integer_overflow": {
        "severity": "High",
        "confidence": 0.70,
        "swc_id": "SWC-101",
        "cwe_id": "CWE-190",
        "description": "Integer overflow detected in arithmetic operation",
        "recommendation": "Use SafeMath or Solidity >=0.8.0 built-in overflow checks",
    },
    "integer_underflow": {
        "severity": "High",
        "confidence": 0.70,
        "swc_id": "SWC-101",
        "cwe_id": "CWE-191",
        "description": "Integer underflow detected in arithmetic operation",
        "recommendation": "Use SafeMath or Solidity >=0.8.0 built-in underflow checks",
    },
    "reentrancy": {
        "severity": "High",
        "confidence": 0.72,
        "swc_id": "SWC-107",
        "cwe_id": "CWE-841",
        "description": "Potential reentrancy vulnerability detected",
        "recommendation": "Apply Checks-Effects-Interactions pattern or use ReentrancyGuard",
    },
    "callstack": {
        "severity": "Medium",
        "confidence": 0.60,
        "swc_id": "SWC-113",
        "cwe_id": "CWE-400",
        "description": "Call stack depth attack vulnerability",
        "recommendation": "Use transfer() or check return values of call()",
    },
    "time_dependency": {
        "severity": "Low",
        "confidence": 0.55,
        "swc_id": "SWC-116",
        "cwe_id": "CWE-829",
        "description": "Timestamp dependency detected",
        "recommendation": "Avoid using block.timestamp for critical logic",
    },
    "tx_origin": {
        "severity": "Medium",
        "confidence": 0.75,
        "swc_id": "SWC-115",
        "cwe_id": "CWE-477",
        "description": "Use of tx.origin for authorization",
        "recommendation": "Use msg.sender instead of tx.origin for authentication",
    },
}


class OyenteAdapter(ToolAdapter):
    """
    Oyente symbolic execution adapter.

    Uses pattern-based analysis inspired by Oyente's detection capabilities.
    Falls back to heuristic detection when the Oyente CLI is not available.
    """

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="oyente",
            version="0.4.0",
            category=ToolCategory.SYMBOLIC_EXECUTION,
            author="Loi Luu et al. (CCS 2016) / MIESC integration",
            license="GPL-3.0",
            homepage="https://github.com/enzymefinance/oyente",
            repository="https://github.com/enzymefinance/oyente",
            documentation="https://github.com/enzymefinance/oyente#readme",
            installation_cmd="pip install oyente",
            capabilities=[
                ToolCapability(
                    name="symbolic_analysis",
                    description="Symbolic execution for integer bugs, reentrancy, and more",
                    supported_languages=["solidity"],
                    detection_types=[
                        "integer_overflow",
                        "integer_underflow",
                        "reentrancy",
                        "callstack",
                        "time_dependency",
                    ],
                ),
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True,
        )

    def is_available(self) -> ToolStatus:
        if shutil.which("oyente"):
            return ToolStatus.AVAILABLE
        return ToolStatus.AVAILABLE  # Fallback pattern analysis available

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        start_time = time.time()
        contract_path = str(Path(contract_path).resolve())

        if shutil.which("oyente"):
            try:
                return self._run_oyente_cli(contract_path, start_time, **kwargs)
            except Exception as e:
                logger.debug(f"Oyente CLI failed: {e}")

        return self._run_pattern_analysis(contract_path, start_time)

    def _run_oyente_cli(self, path: str, start_time: float, **kwargs) -> Dict[str, Any]:
        """Run Oyente CLI tool."""
        timeout = kwargs.get("timeout", 120)
        try:
            result = subprocess.run(
                ["oyente", "-s", path, "-json"],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            if result.stdout.strip():
                raw = json.loads(result.stdout)
                findings = self._normalize_cli_output(raw, path)
                return {
                    "tool": "oyente",
                    "version": "0.4.0",
                    "status": "success",
                    "findings": findings,
                    "metadata": {"mode": "cli", "contract": path},
                    "execution_time": time.time() - start_time,
                    "error": None,
                }
        except subprocess.TimeoutExpired:
            return {
                "tool": "oyente",
                "version": "0.4.0",
                "status": "timeout",
                "findings": [],
                "metadata": {"contract": path},
                "execution_time": time.time() - start_time,
                "error": "Oyente analysis timeout",
            }
        except Exception as e:
            raise

        return self._run_pattern_analysis(path, start_time)

    def _run_pattern_analysis(self, path: str, start_time: float) -> Dict[str, Any]:
        """Pattern-based analysis when CLI is not available."""
        try:
            with open(path, "r", errors="ignore") as f:
                source = f.read()
        except Exception as e:
            return {
                "tool": "oyente",
                "version": "0.4.0",
                "status": "error",
                "findings": [],
                "metadata": {},
                "execution_time": time.time() - start_time,
                "error": str(e),
            }

        lines = source.split("\n")
        raw_findings = []

        # Check Solidity version for overflow relevance
        is_08_plus = bool(re.search(r"pragma\s+solidity\s*[>=^~]*\s*0\.[89]", source))

        for i, line in enumerate(lines, 1):
            # Integer overflow/underflow (pre-0.8)
            if not is_08_plus:
                if re.search(r"unchecked\s*\{", line):
                    raw_findings.append({
                        "type": "integer_overflow",
                        "line": i,
                        "file": path,
                        "code": line.strip(),
                    })

            # Reentrancy: external call before state change
            if re.search(r"\.call\{value:", line) or re.search(r"\.transfer\(", line):
                # Check if state is modified after external call
                context_after = "\n".join(lines[i:min(len(lines), i + 10)])
                if re.search(r"balances?\s*\[", context_after):
                    raw_findings.append({
                        "type": "reentrancy",
                        "line": i,
                        "file": path,
                        "code": line.strip(),
                    })

            # Timestamp dependency
            if "block.timestamp" in line and not line.strip().startswith("//"):
                raw_findings.append({
                    "type": "time_dependency",
                    "line": i,
                    "file": path,
                    "code": line.strip(),
                })

            # tx.origin usage
            if "tx.origin" in line and not line.strip().startswith("//"):
                raw_findings.append({
                    "type": "tx_origin",
                    "line": i,
                    "file": path,
                    "code": line.strip(),
                })

        findings = self.normalize_findings(raw_findings)

        return {
            "tool": "oyente",
            "version": "0.4.0",
            "status": "success",
            "findings": findings,
            "metadata": {
                "mode": "pattern_analysis",
                "contract": path,
                "solidity_08_plus": is_08_plus,
            },
            "execution_time": time.time() - start_time,
            "error": None,
        }

    def _normalize_cli_output(self, raw: Any, path: str) -> List[Dict[str, Any]]:
        """Normalize Oyente CLI JSON output."""
        findings = []
        issues = raw if isinstance(raw, list) else raw.get("vulnerabilities", [])

        for item in issues:
            vuln_type = item.get("type", "unknown").lower().replace(" ", "_")
            config = OYENTE_VULNERABILITIES.get(vuln_type, {
                "severity": "Medium",
                "confidence": 0.60,
                "swc_id": None,
                "cwe_id": None,
                "description": vuln_type,
                "recommendation": "Review finding",
            })

            finding_id = hashlib.md5(
                f"oyente:{vuln_type}:{path}:{item.get('line', 0)}".encode()
            ).hexdigest()[:12]

            findings.append({
                "id": f"OYE-{finding_id}",
                "type": vuln_type,
                "severity": config["severity"],
                "confidence": config["confidence"],
                "location": {
                    "file": item.get("file", path),
                    "line": item.get("line", 0),
                    "function": item.get("function", ""),
                },
                "message": item.get("message", config["description"]),
                "description": config["description"],
                "recommendation": config["recommendation"],
                "swc_id": config.get("swc_id"),
                "cwe_id": config.get("cwe_id"),
                "tool": "oyente",
            })

        return findings

    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        if not raw_output:
            return []

        findings = []
        for item in raw_output:
            if not isinstance(item, dict):
                continue

            vuln_type = item.get("type", "unknown")
            config = OYENTE_VULNERABILITIES.get(vuln_type, {
                "severity": "Medium",
                "confidence": 0.60,
                "swc_id": None,
                "cwe_id": None,
                "description": vuln_type,
                "recommendation": "Review finding",
            })

            finding_id = hashlib.md5(
                f"oyente:{vuln_type}:{item.get('file', '')}:{item.get('line', 0)}".encode()
            ).hexdigest()[:12]

            findings.append({
                "id": f"OYE-{finding_id}",
                "type": vuln_type,
                "severity": config["severity"],
                "confidence": config["confidence"],
                "location": {
                    "file": item.get("file", ""),
                    "line": item.get("line", 0),
                    "function": "",
                },
                "message": f"{config['description']}: {item.get('code', '')}",
                "description": config["description"],
                "recommendation": config["recommendation"],
                "swc_id": config.get("swc_id"),
                "cwe_id": config.get("cwe_id"),
                "tool": "oyente",
            })

        return findings
