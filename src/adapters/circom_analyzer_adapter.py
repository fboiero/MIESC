"""
Circom Analyzer Adapter - ZK Circuit Security Analysis.

Based on: Trail of Bits circomspect (https://github.com/trailofbits/circomspect)

Detects:
- Under-constrained signals
- Signal aliasing
- Unchecked field arithmetic
- Non-quadratic constraints
- Unused signals
- Unsafe component usage

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


CIRCOM_VULNERABILITIES = {
    "under_constrained_signal": {
        "severity": "Critical",
        "confidence": 0.88,
        "swc_id": None,
        "cwe_id": "CWE-682",
        "description": "Signal not fully constrained - prover can choose arbitrary values",
        "recommendation": "Add constraints to fully determine the signal value from inputs",
    },
    "signal_aliasing": {
        "severity": "High",
        "confidence": 0.80,
        "swc_id": None,
        "cwe_id": "CWE-682",
        "description": "Signal value exceeds field prime causing aliasing - unexpected behavior",
        "recommendation": "Add range checks to prevent signal values from exceeding field modulus",
    },
    "unchecked_field_arithmetic": {
        "severity": "High",
        "confidence": 0.78,
        "swc_id": None,
        "cwe_id": "CWE-190",
        "description": "Arithmetic operation may overflow finite field boundary",
        "recommendation": "Add explicit range constraints before arithmetic operations",
    },
    "non_quadratic_constraint": {
        "severity": "Medium",
        "confidence": 0.75,
        "swc_id": None,
        "cwe_id": "CWE-682",
        "description": "Constraint uses non-quadratic expression which may not be R1CS compatible",
        "recommendation": "Rewrite constraint using only quadratic expressions (A * B + C = 0)",
    },
    "unused_signal": {
        "severity": "Medium",
        "confidence": 0.70,
        "swc_id": None,
        "cwe_id": "CWE-561",
        "description": "Declared signal never used in constraints - may indicate missing constraint",
        "recommendation": "Either add constraints using this signal or remove the declaration",
    },
    "unsafe_component_usage": {
        "severity": "Medium",
        "confidence": 0.72,
        "swc_id": None,
        "cwe_id": "CWE-829",
        "description": "Component with known security issues or missing constraint propagation",
        "recommendation": "Verify component constraints propagate correctly or use audited version",
    },
    "unconstrained_output": {
        "severity": "Critical",
        "confidence": 0.90,
        "swc_id": None,
        "cwe_id": "CWE-682",
        "description": "Output signal not constrained by input signals - proof can be forged",
        "recommendation": "Ensure all output signals are fully determined by input constraints",
    },
}

# Patterns for Solidity contracts that use ZK proofs
ZK_SOLIDITY_PATTERNS = {
    "unverified_proof": {
        "severity": "Critical",
        "confidence": 0.85,
        "swc_id": None,
        "cwe_id": "CWE-345",
        "description": "ZK proof accepted without proper verification",
        "recommendation": "Always verify proofs using the verifier contract before processing",
        "patterns": [
            r"function\s+\w*(?:submit|process|execute)\w*\s*\([^)]*bytes\s+(?:calldata\s+)?proof",
        ],
        "verification_patterns": [
            r"verifier\.verify",
            r"verifyProof\s*\(",
            r"require\s*\(\s*\w*[Vv]erif",
        ],
    },
    "missing_nullifier_check": {
        "severity": "Critical",
        "confidence": 0.83,
        "swc_id": None,
        "cwe_id": "CWE-294",
        "description": "Missing nullifier check allows proof replay (double-spend)",
        "recommendation": "Track and reject used nullifiers to prevent proof replay",
        "patterns": [
            r"nullifier|Nullifier",
        ],
        "guard_patterns": [
            r"usedNullifiers|nullifierUsed|require\s*\(\s*!.*nullifier",
        ],
    },
}


class CircomAnalyzerAdapter(ToolAdapter):
    """
    ZK circuit security analyzer using circomspect and pattern analysis.

    Analyzes .circom files with circomspect CLI or performs pattern-based
    analysis of Solidity contracts that interact with ZK proofs.
    """

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="circom_analyzer",
            version="1.0.0",
            category=ToolCategory.CROSSCHAIN_ZK,
            author="Trail of Bits (circomspect) / MIESC integration by Fernando Boiero",
            license="AGPL-3.0",
            homepage="https://github.com/trailofbits/circomspect",
            repository="https://github.com/trailofbits/circomspect",
            documentation="https://github.com/trailofbits/circomspect#readme",
            installation_cmd="cargo install circomspect",
            capabilities=[
                ToolCapability(
                    name="circuit_analysis",
                    description="Detect ZK circuit vulnerabilities and proof system issues",
                    supported_languages=["circom", "solidity"],
                    detection_types=[
                        "under_constrained_signal",
                        "signal_aliasing",
                        "unconstrained_output",
                        "unused_signal",
                    ],
                ),
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True,
        )

    def is_available(self) -> ToolStatus:
        if shutil.which("circomspect"):
            return ToolStatus.AVAILABLE
        return ToolStatus.AVAILABLE  # Fallback analysis available

    def can_analyze(self, contract_path: str) -> bool:
        return contract_path.endswith((".sol", ".circom"))

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        start_time = time.time()
        contract_path = str(Path(contract_path).resolve())

        if contract_path.endswith(".circom"):
            return self._analyze_circom(contract_path, start_time, **kwargs)
        else:
            return self._analyze_solidity_zk(contract_path, start_time)

    def _analyze_circom(self, path: str, start_time: float, **kwargs) -> Dict[str, Any]:
        if shutil.which("circomspect"):
            try:
                timeout = kwargs.get("timeout", 120)
                result = subprocess.run(
                    ["circomspect", path, "--json"],
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
                if result.stdout.strip():
                    raw = json.loads(result.stdout)
                    findings = self._normalize_circomspect(raw, path)
                    return {
                        "tool": "circom_analyzer",
                        "version": "1.0.0",
                        "status": "success",
                        "findings": findings,
                        "metadata": {"mode": "circomspect_cli", "contract": path},
                        "execution_time": time.time() - start_time,
                        "error": None,
                    }
            except Exception as e:
                logger.debug(f"circomspect CLI failed: {e}")

        return self._analyze_circom_patterns(path, start_time)

    def _analyze_circom_patterns(self, path: str, start_time: float) -> Dict[str, Any]:
        try:
            with open(path, "r", errors="ignore") as f:
                source = f.read()
        except Exception as e:
            return {
                "tool": "circom_analyzer",
                "version": "1.0.0",
                "status": "error",
                "findings": [],
                "metadata": {},
                "execution_time": time.time() - start_time,
                "error": str(e),
            }

        lines = source.split("\n")
        raw_findings = []

        # Find all signal declarations
        signals = set()
        signal_lines = {}
        for i, line in enumerate(lines, 1):
            sig_match = re.search(r"signal\s+(?:input|output|intermediate)?\s*(\w+)", line)
            if sig_match:
                name = sig_match.group(1)
                signals.add(name)
                signal_lines[name] = i

        # Find all constrained signals (used in <== or === or -->)
        constrained = set()
        for line in lines:
            constraint_match = re.findall(r"(\w+)\s*(?:<==|===|-->)", line)
            constrained.update(constraint_match)
            # Also check right side of constraints
            rhs_match = re.findall(r"(?:<==|===|-->)\s*.*?(\w+)", line)
            constrained.update(rhs_match)

        # Check for unused signals
        for sig in signals:
            if sig not in constrained:
                raw_findings.append({
                    "type": "unused_signal",
                    "line": signal_lines.get(sig, 0),
                    "file": path,
                    "code": f"Signal '{sig}' declared but never used in constraints",
                })

        # Check for output signals not in LHS of constraints
        for i, line in enumerate(lines, 1):
            out_match = re.search(r"signal\s+output\s+(\w+)", line)
            if out_match:
                out_name = out_match.group(1)
                if out_name not in constrained:
                    raw_findings.append({
                        "type": "unconstrained_output",
                        "line": i,
                        "file": path,
                        "code": f"Output signal '{out_name}' not constrained",
                    })

        findings = self.normalize_findings(raw_findings)

        return {
            "tool": "circom_analyzer",
            "version": "1.0.0",
            "status": "success",
            "findings": findings,
            "metadata": {"mode": "pattern_analysis", "contract": path, "signals_found": len(signals)},
            "execution_time": time.time() - start_time,
            "error": None,
        }

    def _analyze_solidity_zk(self, path: str, start_time: float) -> Dict[str, Any]:
        try:
            with open(path, "r", errors="ignore") as f:
                source = f.read()
        except Exception as e:
            return {
                "tool": "circom_analyzer",
                "version": "1.0.0",
                "status": "error",
                "findings": [],
                "metadata": {},
                "execution_time": time.time() - start_time,
                "error": str(e),
            }

        lines = source.split("\n")
        is_zk = bool(re.search(
            r"verif|proof|snark|groth16|plonk|nullifier|commitment|merkleRoot",
            source, re.IGNORECASE,
        ))

        if not is_zk:
            return {
                "tool": "circom_analyzer",
                "version": "1.0.0",
                "status": "success",
                "findings": [],
                "metadata": {"contract": path, "is_zk_contract": False},
                "execution_time": time.time() - start_time,
                "error": None,
            }

        raw_findings = []

        for vuln_name, config in ZK_SOLIDITY_PATTERNS.items():
            for pattern in config["patterns"]:
                for i, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        context = "\n".join(lines[max(0, i - 2):min(len(lines), i + 15)])
                        has_guard = any(
                            re.search(g, context) for g in config.get("verification_patterns", config.get("guard_patterns", []))
                        )
                        if not has_guard:
                            raw_findings.append({
                                "type": vuln_name,
                                "line": i,
                                "file": path,
                                "code": line.strip(),
                                "config": config,
                            })

        findings = self.normalize_findings(raw_findings)

        return {
            "tool": "circom_analyzer",
            "version": "1.0.0",
            "status": "success",
            "findings": findings,
            "metadata": {"contract": path, "is_zk_contract": True, "mode": "solidity_zk_analysis"},
            "execution_time": time.time() - start_time,
            "error": None,
        }

    def _normalize_circomspect(self, raw: Any, path: str) -> List[Dict[str, Any]]:
        findings = []
        issues = raw if isinstance(raw, list) else raw.get("issues", [])
        for item in issues:
            severity_map = {"error": "Critical", "warning": "High", "info": "Medium", "hint": "Low"}
            vuln_type = item.get("type", "unknown").lower().replace(" ", "_")
            config = CIRCOM_VULNERABILITIES.get(vuln_type, {
                "severity": "Medium", "confidence": 0.70,
                "swc_id": None, "cwe_id": None,
                "description": item.get("message", ""),
                "recommendation": "Review circuit constraint",
            })

            finding_id = hashlib.md5(
                f"circom:{vuln_type}:{path}:{item.get('line', 0)}".encode()
            ).hexdigest()[:12]

            findings.append({
                "id": f"CRC-{finding_id}",
                "type": vuln_type,
                "severity": severity_map.get(item.get("level", "warning"), "Medium"),
                "confidence": config["confidence"],
                "location": {
                    "file": item.get("file", path),
                    "line": item.get("line", 0),
                    "function": item.get("template", ""),
                },
                "message": item.get("message", config["description"]),
                "description": config["description"],
                "recommendation": config["recommendation"],
                "swc_id": config.get("swc_id"),
                "cwe_id": config.get("cwe_id"),
                "tool": "circom_analyzer",
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
            config = item.get("config") or CIRCOM_VULNERABILITIES.get(vuln_type, {
                "severity": "Medium", "confidence": 0.70,
                "swc_id": None, "cwe_id": None,
                "description": vuln_type, "recommendation": "Review ZK security",
            })

            finding_id = hashlib.md5(
                f"circom:{vuln_type}:{item.get('file', '')}:{item.get('line', 0)}".encode()
            ).hexdigest()[:12]

            findings.append({
                "id": f"CRC-{finding_id}",
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
                "tool": "circom_analyzer",
            })

        return findings
