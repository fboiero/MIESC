"""
4naly3er Adapter - Code4rena Automated Static Analyzer.

Based on: Picodes/4naly3er (https://github.com/Picodes/4naly3er)

Detects:
- Centralization risks (single owner, admin patterns)
- Unsafe ERC20 operations (transfer without return check)
- Gas optimizations (storage vs memory, loop patterns)
- Low-severity patterns common in competitive audits

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


# Vulnerability patterns for fallback analysis
FOURANALYZER_PATTERNS = {
    "centralization_risk": {
        "severity": "Medium",
        "confidence": 0.75,
        "swc_id": "SWC-105",
        "cwe_id": "CWE-284",
        "description": "Contract has centralization risk - single owner or admin can control critical functions",
        "recommendation": "Implement multi-sig or timelock for privileged operations",
        "patterns": [
            r"onlyOwner",
            r"onlyAdmin",
            r"require\s*\(\s*msg\.sender\s*==\s*owner",
            r"function\s+\w+\s*\([^)]*\)\s*(?:external|public)\s+onlyOwner",
        ],
    },
    "unsafe_erc20_transfer": {
        "severity": "High",
        "confidence": 0.80,
        "swc_id": "SWC-104",
        "cwe_id": "CWE-252",
        "description": "ERC20 transfer/transferFrom return value not checked - tokens may silently fail",
        "recommendation": "Use SafeERC20.safeTransfer() or check return value explicitly",
        "patterns": [
            r"\.transfer\s*\([^)]+\)\s*;",
            r"\.transferFrom\s*\([^)]+\)\s*;",
        ],
        "exclude_patterns": [
            r"safeTransfer",
            r"safeTransferFrom",
            r"require\s*\(\s*\w+\.transfer",
            r"bool\s+\w+\s*=\s*\w+\.transfer",
        ],
    },
    "missing_zero_address_check": {
        "severity": "Low",
        "confidence": 0.70,
        "swc_id": None,
        "cwe_id": "CWE-20",
        "description": "Address parameter not validated against zero address",
        "recommendation": "Add require(addr != address(0)) check",
        "patterns": [
            r"function\s+\w+\s*\([^)]*address\s+\w+[^)]*\)\s*(?:external|public)",
        ],
        "exclude_patterns": [
            r"require\s*\([^)]*!=\s*address\s*\(\s*0\s*\)",
            r"if\s*\([^)]*==\s*address\s*\(\s*0\s*\)",
        ],
    },
    "use_of_block_timestamp": {
        "severity": "Low",
        "confidence": 0.60,
        "swc_id": "SWC-116",
        "cwe_id": "CWE-330",
        "description": "Use of block.timestamp for time-sensitive logic - can be manipulated by miners",
        "recommendation": "Consider using block.number or an oracle for time-critical operations",
        "patterns": [
            r"block\.timestamp",
            r"\bnow\b",
        ],
    },
    "unsafe_casting": {
        "severity": "Medium",
        "confidence": 0.70,
        "swc_id": "SWC-101",
        "cwe_id": "CWE-681",
        "description": "Unsafe downcast may silently truncate values",
        "recommendation": "Use SafeCast library from OpenZeppelin",
        "patterns": [
            r"uint8\s*\(\s*\w+\s*\)",
            r"uint16\s*\(\s*\w+\s*\)",
            r"uint32\s*\(\s*\w+\s*\)",
            r"uint64\s*\(\s*\w+\s*\)",
            r"uint128\s*\(\s*\w+\s*\)",
            r"int8\s*\(\s*\w+\s*\)",
            r"int16\s*\(\s*\w+\s*\)",
            r"int32\s*\(\s*\w+\s*\)",
            r"int64\s*\(\s*\w+\s*\)",
            r"int128\s*\(\s*\w+\s*\)",
        ],
        "exclude_patterns": [
            r"SafeCast",
        ],
    },
    "missing_event_emission": {
        "severity": "Low",
        "confidence": 0.65,
        "swc_id": None,
        "cwe_id": "CWE-778",
        "description": "State-changing function does not emit an event for off-chain tracking",
        "recommendation": "Emit events for all state-changing operations",
        "patterns": [
            r"function\s+set\w+\s*\([^)]*\)\s*(?:external|public)",
            r"function\s+update\w+\s*\([^)]*\)\s*(?:external|public)",
            r"function\s+change\w+\s*\([^)]*\)\s*(?:external|public)",
        ],
        "exclude_patterns": [
            r"emit\s+\w+",
        ],
    },
    "use_of_transfer_instead_of_call": {
        "severity": "Medium",
        "confidence": 0.75,
        "swc_id": "SWC-134",
        "cwe_id": "CWE-400",
        "description": "Use of .transfer() or .send() with fixed gas stipend (2300) may fail with EIP-1884",
        "recommendation": "Use .call{value: amount}('') with reentrancy guard instead",
        "patterns": [
            r"\.transfer\s*\(\s*\w+\s*\)\s*;",
            r"\.send\s*\(\s*\w+\s*\)\s*;",
        ],
        "exclude_patterns": [
            r"IERC20",
            r"safeTransfer",
        ],
    },
    "magic_numbers": {
        "severity": "Info",
        "confidence": 0.55,
        "swc_id": None,
        "cwe_id": "CWE-547",
        "description": "Magic number used instead of named constant",
        "recommendation": "Define named constants for numeric literals",
        "patterns": [
            r"==\s*\d{3,}",
            r">\s*\d{3,}",
            r"<\s*\d{3,}",
            r"\*\s*\d{3,}",
        ],
        "exclude_patterns": [
            r"10\*\*\d+",
            r"1e\d+",
            r"1000000",
        ],
    },
    "storage_variable_caching": {
        "severity": "Info",
        "confidence": 0.60,
        "swc_id": None,
        "cwe_id": None,
        "description": "Storage variable accessed multiple times in function - cache in memory for gas savings",
        "recommendation": "Cache storage variables in local memory variables when accessed multiple times",
        "patterns": [
            r"(\w+\.\w+).*\n.*\1",
        ],
    },
    "loop_length_caching": {
        "severity": "Info",
        "confidence": 0.65,
        "swc_id": None,
        "cwe_id": None,
        "description": "Array length accessed in loop condition - cache for gas savings",
        "recommendation": "Cache array.length in a local variable before the loop",
        "patterns": [
            r"for\s*\([^;]+;\s*\w+\s*<\s*\w+\.length\s*;",
        ],
    },
}


class FourAnalyzerAdapter(ToolAdapter):
    """
    4naly3er adapter for Code4rena-style automated analysis.

    Runs the 4naly3er CLI tool or falls back to pattern-based analysis.
    """

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="fouranalyzer",
            version="1.0.0",
            category=ToolCategory.STATIC_ANALYSIS,
            author="Picodes (4naly3er) / MIESC integration by Fernando Boiero",
            license="MIT",
            homepage="https://github.com/Picodes/4naly3er",
            repository="https://github.com/Picodes/4naly3er",
            documentation="https://github.com/Picodes/4naly3er#readme",
            installation_cmd="npm install -g @4naly3er/cli",
            capabilities=[
                ToolCapability(
                    name="centralization_analysis",
                    description="Detect centralization risks and admin patterns",
                    supported_languages=["solidity"],
                    detection_types=["centralization_risk", "access_control"],
                ),
                ToolCapability(
                    name="erc20_safety",
                    description="Detect unsafe ERC20 operations",
                    supported_languages=["solidity"],
                    detection_types=["unsafe_transfer", "unchecked_return"],
                ),
                ToolCapability(
                    name="gas_optimization",
                    description="Identify gas optimization opportunities",
                    supported_languages=["solidity"],
                    detection_types=["gas_optimization"],
                ),
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True,
        )

    def is_available(self) -> ToolStatus:
        if shutil.which("4naly3er"):
            return ToolStatus.AVAILABLE
        # Fallback pattern analysis is always available
        return ToolStatus.AVAILABLE

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        start_time = time.time()
        contract_path = str(Path(contract_path).resolve())

        try:
            if shutil.which("4naly3er"):
                return self._run_cli(contract_path, start_time, **kwargs)
        except Exception as e:
            logger.debug(f"4naly3er CLI failed, using fallback: {e}")

        return self._run_pattern_analysis(contract_path, start_time)

    def _run_cli(self, contract_path: str, start_time: float, **kwargs) -> Dict[str, Any]:
        timeout = kwargs.get("timeout", 60)
        try:
            result = subprocess.run(
                ["4naly3er", contract_path, "--json"],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            if result.returncode == 0:
                raw = json.loads(result.stdout)
                findings = self.normalize_findings(raw)
                return {
                    "tool": "fouranalyzer",
                    "version": "1.0.0",
                    "status": "success",
                    "findings": findings,
                    "metadata": {"mode": "cli", "contract": contract_path},
                    "execution_time": time.time() - start_time,
                    "error": None,
                }
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as e:
            logger.debug(f"4naly3er CLI error: {e}")

        return self._run_pattern_analysis(contract_path, start_time)

    def _run_pattern_analysis(self, contract_path: str, start_time: float) -> Dict[str, Any]:
        try:
            with open(contract_path, "r", errors="ignore") as f:
                source_code = f.read()
        except Exception as e:
            return {
                "tool": "fouranalyzer",
                "version": "1.0.0",
                "status": "error",
                "findings": [],
                "metadata": {},
                "execution_time": time.time() - start_time,
                "error": str(e),
            }

        lines = source_code.split("\n")
        raw_findings = []

        for pattern_name, pattern_config in FOURANALYZER_PATTERNS.items():
            for regex in pattern_config["patterns"]:
                for i, line in enumerate(lines, 1):
                    if re.search(regex, line):
                        # Check exclusion patterns
                        excluded = False
                        for exc in pattern_config.get("exclude_patterns", []):
                            # Check surrounding context (5 lines)
                            context_start = max(0, i - 3)
                            context_end = min(len(lines), i + 2)
                            context = "\n".join(lines[context_start:context_end])
                            if re.search(exc, context):
                                excluded = True
                                break
                        if not excluded:
                            raw_findings.append({
                                "type": pattern_name,
                                "line": i,
                                "file": contract_path,
                                "code": line.strip(),
                                "pattern_config": pattern_config,
                            })

        # Deduplicate by type+line
        seen = set()
        deduped = []
        for f in raw_findings:
            key = f"{f['type']}:{f['line']}"
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        findings = self.normalize_findings(deduped)

        return {
            "tool": "fouranalyzer",
            "version": "1.0.0",
            "status": "success",
            "findings": findings,
            "metadata": {
                "mode": "pattern_analysis",
                "contract": contract_path,
                "patterns_checked": len(FOURANALYZER_PATTERNS),
                "total_lines": len(lines),
            },
            "execution_time": time.time() - start_time,
            "error": None,
        }

    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        if not raw_output:
            return []

        findings = []
        for item in raw_output:
            if isinstance(item, dict) and "pattern_config" in item:
                config = item["pattern_config"]
                finding_id = hashlib.md5(
                    f"4naly3er:{item['type']}:{item.get('file', '')}:{item.get('line', 0)}".encode()
                ).hexdigest()[:12]

                findings.append({
                    "id": f"4NALY-{finding_id}",
                    "type": item["type"],
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
                    "tool": "fouranalyzer",
                })
            elif isinstance(item, dict):
                # CLI output format
                finding_id = hashlib.md5(
                    f"4naly3er:{item.get('title', '')}:{item.get('line', 0)}".encode()
                ).hexdigest()[:12]

                severity_map = {"H": "High", "M": "Medium", "L": "Low", "G": "Info", "NC": "Info"}
                findings.append({
                    "id": f"4NALY-{finding_id}",
                    "type": item.get("title", "unknown"),
                    "severity": severity_map.get(item.get("severity", "L"), "Low"),
                    "confidence": 0.70,
                    "location": {
                        "file": item.get("file", ""),
                        "line": item.get("line", 0),
                        "function": item.get("function", ""),
                    },
                    "message": item.get("description", ""),
                    "description": item.get("description", ""),
                    "recommendation": item.get("recommendation", ""),
                    "swc_id": item.get("swc_id"),
                    "cwe_id": item.get("cwe_id"),
                    "tool": "fouranalyzer",
                })

        return findings
