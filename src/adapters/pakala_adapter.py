"""
Pakala Adapter - Multi-Transaction Symbolic Execution.

Based on: palkeo/pakala (https://github.com/palkeo/pakala)
Research: Multi-transaction symbolic execution for finding bugs
that require 2+ transactions to exploit.

Detects:
- Multi-transaction reentrancy
- State manipulation across calls
- Fund extraction via transaction sequences
- Privilege escalation sequences
- Cross-function vulnerabilities

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


MULTI_TX_PATTERNS = {
    "multi_tx_reentrancy": {
        "severity": "Critical",
        "confidence": 0.85,
        "swc_id": "SWC-107",
        "cwe_id": "CWE-841",
        "description": "Reentrancy exploitable across multiple transactions - state not properly locked between calls",
        "recommendation": "Use reentrancy guard and ensure state updates before external calls across all entry points",
        "patterns": [
            (r"function\s+(\w+)[^{]*\{[^}]*\.call\{", r"function\s+(\w+)[^{]*\{[^}]*balances?\s*\["),
        ],
    },
    "state_manipulation": {
        "severity": "High",
        "confidence": 0.75,
        "swc_id": "SWC-132",
        "cwe_id": "CWE-362",
        "description": "Contract state can be manipulated through a sequence of transactions to reach an unintended state",
        "recommendation": "Implement state machine pattern with explicit valid transitions",
        "indicators": [
            r"mapping\s*\([^)]*\)\s*(public|internal|private)\s+\w+",
            r"function\s+\w+\s*\([^)]*\)\s*(?:external|public)[^{]*\{[^}]*\w+\s*=\s*",
        ],
    },
    "fund_extraction": {
        "severity": "Critical",
        "confidence": 0.80,
        "swc_id": "SWC-105",
        "cwe_id": "CWE-284",
        "description": "Funds can be extracted through a multi-step transaction sequence bypassing access controls",
        "recommendation": "Add withdrawal limits, timelocks, and multi-sig for large transfers",
        "indicators": [
            r"\.call\{value:",
            r"\.transfer\s*\(",
            r"payable\s*\(",
        ],
        "guards": [
            r"onlyOwner",
            r"require\s*\(\s*msg\.sender\s*==",
            r"onlyRole",
        ],
    },
    "privilege_escalation_sequence": {
        "severity": "High",
        "confidence": 0.70,
        "swc_id": "SWC-105",
        "cwe_id": "CWE-269",
        "description": "Privilege can be escalated through a sequence of calls exploiting role transitions",
        "recommendation": "Implement role hierarchy with explicit checks at each transition",
        "indicators": [
            r"function\s+\w*(grant|set|add|assign|transfer)\w*\s*\(",
            r"mapping\s*\(\s*address\s*=>\s*bool\s*\)",
            r"isAdmin|isOwner|hasRole",
        ],
    },
    "cross_function_vulnerability": {
        "severity": "High",
        "confidence": 0.72,
        "swc_id": "SWC-107",
        "cwe_id": "CWE-367",
        "description": "Vulnerability that spans multiple functions - one function modifies state that another depends on unsafely",
        "recommendation": "Use mutex pattern or ensure atomic state updates across dependent functions",
        "indicators": [
            r"function\s+deposit\s*\(",
            r"function\s+withdraw\s*\(",
            r"function\s+claim\s*\(",
        ],
    },
    "flash_loan_multi_tx": {
        "severity": "Critical",
        "confidence": 0.78,
        "swc_id": None,
        "cwe_id": "CWE-362",
        "description": "Flash loan attack vector exploiting state changes across multiple function calls within one transaction",
        "recommendation": "Implement flash loan protection: check invariants before and after, use access control on callbacks",
        "indicators": [
            r"flashLoan|flashloan|flash_loan",
            r"onFlashLoan|executeOperation|receiveFlashLoan",
            r"IFlashLoanReceiver|IFlashBorrower",
        ],
    },
    "donation_attack": {
        "severity": "High",
        "confidence": 0.73,
        "swc_id": None,
        "cwe_id": "CWE-682",
        "description": "Share-based vault vulnerable to donation attack via direct token transfer before first deposit",
        "recommendation": "Implement virtual offset or minimum deposit requirement to prevent share inflation attacks",
        "indicators": [
            r"totalSupply\s*\(\s*\)\s*==\s*0",
            r"totalAssets|totalBalance",
            r"shares?\s*=.*amount\s*\*\s*totalSupply",
            r"previewDeposit|convertToShares",
        ],
    },
}


class PakalaAdapter(ToolAdapter):
    """
    Multi-transaction symbolic execution adapter.

    Analyzes contracts for vulnerabilities requiring 2+ transactions.
    Falls back to pattern-based multi-tx analysis if pakala CLI unavailable.
    """

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="pakala",
            version="1.0.0",
            category=ToolCategory.SYMBOLIC_EXECUTION,
            author="palkeo / MIESC integration by Fernando Boiero",
            license="GPL-3.0",
            homepage="https://github.com/palkeo/pakala",
            repository="https://github.com/palkeo/pakala",
            documentation="https://github.com/palkeo/pakala#readme",
            installation_cmd="pip install pakala",
            capabilities=[
                ToolCapability(
                    name="multi_tx_analysis",
                    description="Detect vulnerabilities requiring multiple transactions",
                    supported_languages=["solidity", "evm_bytecode"],
                    detection_types=[
                        "multi_tx_reentrancy",
                        "state_manipulation",
                        "fund_extraction",
                        "privilege_escalation",
                    ],
                ),
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True,
        )

    def is_available(self) -> ToolStatus:
        if shutil.which("pakala"):
            return ToolStatus.AVAILABLE
        return ToolStatus.AVAILABLE  # Fallback analysis always available

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        start_time = time.time()
        contract_path = str(Path(contract_path).resolve())

        try:
            if shutil.which("pakala"):
                return self._run_cli(contract_path, start_time, **kwargs)
        except Exception as e:
            logger.debug(f"Pakala CLI failed, using fallback: {e}")

        return self._run_pattern_analysis(contract_path, start_time)

    def _run_cli(self, contract_path: str, start_time: float, **kwargs) -> Dict[str, Any]:
        timeout = kwargs.get("timeout", 300)
        try:
            result = subprocess.run(
                ["pakala", "analyze", contract_path, "--json"],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            if result.returncode == 0 and result.stdout.strip():
                raw = json.loads(result.stdout)
                findings = self.normalize_findings(raw)
                return {
                    "tool": "pakala",
                    "version": "1.0.0",
                    "status": "success",
                    "findings": findings,
                    "metadata": {"mode": "cli", "contract": contract_path},
                    "execution_time": time.time() - start_time,
                    "error": None,
                }
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as e:
            logger.debug(f"Pakala CLI error: {e}")

        return self._run_pattern_analysis(contract_path, start_time)

    def _run_pattern_analysis(self, contract_path: str, start_time: float) -> Dict[str, Any]:
        try:
            with open(contract_path, "r", errors="ignore") as f:
                source_code = f.read()
        except Exception as e:
            return {
                "tool": "pakala",
                "version": "1.0.0",
                "status": "error",
                "findings": [],
                "metadata": {},
                "execution_time": time.time() - start_time,
                "error": str(e),
            }

        lines = source_code.split("\n")
        raw_findings = []

        # Extract function bodies for cross-function analysis
        functions = self._extract_functions(source_code)

        for pattern_name, config in MULTI_TX_PATTERNS.items():
            indicators = config.get("indicators", [])
            guards = config.get("guards", [])

            matched_lines = []
            for regex in indicators:
                for i, line in enumerate(lines, 1):
                    if re.search(regex, line):
                        matched_lines.append((i, line.strip()))

            if len(matched_lines) >= 2:
                # Check if guards are present
                has_guard = False
                for guard in guards:
                    if re.search(guard, source_code):
                        has_guard = True
                        break

                confidence = config["confidence"]
                if has_guard:
                    confidence *= 0.5  # Reduce confidence if guards found

                if confidence >= 0.35:
                    raw_findings.append({
                        "type": pattern_name,
                        "line": matched_lines[0][0],
                        "file": contract_path,
                        "code": matched_lines[0][1],
                        "related_lines": [m[0] for m in matched_lines[1:]],
                        "has_guard": has_guard,
                        "config": config,
                        "confidence_override": confidence,
                    })

            # Check paired patterns
            if "patterns" in config:
                for pattern_pair in config["patterns"]:
                    if isinstance(pattern_pair, tuple) and len(pattern_pair) == 2:
                        matches_a = [
                            (i, l.strip())
                            for i, l in enumerate(lines, 1)
                            if re.search(pattern_pair[0], l)
                        ]
                        matches_b = [
                            (i, l.strip())
                            for i, l in enumerate(lines, 1)
                            if re.search(pattern_pair[1], l)
                        ]
                        if matches_a and matches_b:
                            raw_findings.append({
                                "type": pattern_name,
                                "line": matches_a[0][0],
                                "file": contract_path,
                                "code": matches_a[0][1],
                                "related_lines": [m[0] for m in matches_b],
                                "config": config,
                            })

        # Cross-function analysis
        cross_func_findings = self._analyze_cross_function(functions, contract_path)
        raw_findings.extend(cross_func_findings)

        # Deduplicate
        seen = set()
        deduped = []
        for f in raw_findings:
            key = f"{f['type']}:{f['line']}"
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        findings = self.normalize_findings(deduped)

        return {
            "tool": "pakala",
            "version": "1.0.0",
            "status": "success",
            "findings": findings,
            "metadata": {
                "mode": "multi_tx_pattern_analysis",
                "contract": contract_path,
                "functions_analyzed": len(functions),
                "patterns_checked": len(MULTI_TX_PATTERNS),
            },
            "execution_time": time.time() - start_time,
            "error": None,
        }

    def _extract_functions(self, source_code: str) -> Dict[str, Dict[str, Any]]:
        """Extract function names and their bodies from source code."""
        functions = {}
        pattern = r"function\s+(\w+)\s*\(([^)]*)\)[^{]*\{"
        for match in re.finditer(pattern, source_code):
            name = match.group(1)
            params = match.group(2)
            start = match.start()
            # Find matching closing brace
            depth = 0
            body_start = source_code.index("{", start)
            pos = body_start
            for pos in range(body_start, len(source_code)):
                if source_code[pos] == "{":
                    depth += 1
                elif source_code[pos] == "}":
                    depth -= 1
                    if depth == 0:
                        break
            body = source_code[body_start:pos + 1]
            line_num = source_code[:start].count("\n") + 1
            functions[name] = {"body": body, "params": params, "line": line_num}
        return functions

    def _analyze_cross_function(
        self, functions: Dict, contract_path: str
    ) -> List[Dict[str, Any]]:
        """Analyze cross-function vulnerabilities."""
        findings = []

        deposit_funcs = {n: f for n, f in functions.items() if "deposit" in n.lower()}
        withdraw_funcs = {n: f for n, f in functions.items() if "withdraw" in n.lower()}

        if deposit_funcs and withdraw_funcs:
            for wname, wfunc in withdraw_funcs.items():
                has_external_call = bool(re.search(r"\.call\{|\.transfer\(|\.send\(", wfunc["body"]))
                has_state_update = bool(re.search(r"balances?\s*\[.*\]\s*[-=]", wfunc["body"]))

                if has_external_call and has_state_update:
                    # Check order: state update should be before external call
                    call_pos = re.search(r"\.call\{|\.transfer\(|\.send\(", wfunc["body"])
                    state_pos = re.search(r"balances?\s*\[.*\]\s*[-=]", wfunc["body"])

                    if call_pos and state_pos and call_pos.start() < state_pos.start():
                        findings.append({
                            "type": "cross_function_vulnerability",
                            "line": wfunc["line"],
                            "file": contract_path,
                            "code": f"Function {wname}: external call before state update",
                            "config": MULTI_TX_PATTERNS["cross_function_vulnerability"],
                        })

        return findings

    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        if not raw_output:
            return []

        findings = []
        for item in raw_output:
            if isinstance(item, dict) and "config" in item:
                config = item["config"]
                finding_id = hashlib.md5(
                    f"pakala:{item['type']}:{item.get('file', '')}:{item.get('line', 0)}".encode()
                ).hexdigest()[:12]

                confidence = item.get("confidence_override", config["confidence"])
                related = item.get("related_lines", [])
                desc = config["description"]
                if related:
                    desc += f" (related lines: {', '.join(str(l) for l in related[:5])})"

                findings.append({
                    "id": f"PKL-{finding_id}",
                    "type": item["type"],
                    "severity": config["severity"],
                    "confidence": confidence,
                    "location": {
                        "file": item.get("file", ""),
                        "line": item.get("line", 0),
                        "function": "",
                    },
                    "message": desc,
                    "description": config["description"],
                    "recommendation": config["recommendation"],
                    "swc_id": config.get("swc_id"),
                    "cwe_id": config.get("cwe_id"),
                    "tool": "pakala",
                })

        return findings
