"""
Scribble Adapter - ConsenSys Annotation-Based Runtime Verification.

Based on: ConsenSys/scribble (https://github.com/ConsenSys/scribble)
Enables specification-driven verification of smart contracts using
Solidity annotations (#if_succeeds, #invariant, #if_updated).

Detects:
- Invariant violations
- Pre/post-condition failures
- Access control violations
- State invariant breaks
- Annotation coverage gaps

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


SCRIBBLE_ANNOTATION_PATTERNS = {
    "invariant_violation": {
        "severity": "High",
        "confidence": 0.85,
        "swc_id": None,
        "cwe_id": "CWE-682",
        "description": "Contract invariant may be violated - state constraint not maintained across transactions",
        "recommendation": "Add explicit invariant checks or use Scribble #invariant annotations",
        "indicators": [
            r"totalSupply",
            r"balanceOf\s*\[",
            r"_totalSupply\s*[+\-=]",
        ],
        "invariant_checks": [
            r"assert\s*\(\s*totalSupply",
            r"require\s*\(\s*totalSupply",
            r"#invariant",
        ],
    },
    "precondition_failure": {
        "severity": "Medium",
        "confidence": 0.75,
        "swc_id": "SWC-123",
        "cwe_id": "CWE-20",
        "description": "Function precondition may not be properly enforced - inputs not validated",
        "recommendation": "Add require() checks at function entry or Scribble #if_succeeds annotations",
        "indicators": [
            r"function\s+\w+\s*\([^)]*uint\d*\s+\w+[^)]*\)\s*(?:external|public)",
        ],
        "validation_checks": [
            r"require\s*\(",
            r"#if_succeeds",
        ],
    },
    "postcondition_failure": {
        "severity": "High",
        "confidence": 0.78,
        "swc_id": None,
        "cwe_id": "CWE-682",
        "description": "Function postcondition may not hold - return value or state change not guaranteed",
        "recommendation": "Add postcondition checks or Scribble #if_succeeds with old() references",
        "indicators": [
            r"function\s+\w+\s*\([^)]*\)\s*(?:external|public)[^{]*returns\s*\(",
        ],
    },
    "access_control_violation": {
        "severity": "Critical",
        "confidence": 0.82,
        "swc_id": "SWC-105",
        "cwe_id": "CWE-284",
        "description": "Access control property may be violated - privileged function callable by unauthorized users",
        "recommendation": "Add access control modifiers and Scribble annotations for authorization",
        "indicators": [
            r"function\s+\w*(withdraw|transfer|mint|burn|pause|upgrade|set|admin)\w*\s*\([^)]*\)\s*(?:external|public)",
        ],
        "guards": [
            r"onlyOwner",
            r"onlyAdmin",
            r"onlyRole",
            r"require\s*\(\s*msg\.sender\s*==",
            r"_checkOwner",
            r"_checkRole",
        ],
    },
    "state_invariant_break": {
        "severity": "High",
        "confidence": 0.76,
        "swc_id": None,
        "cwe_id": "CWE-662",
        "description": "State invariant may break during execution - intermediate state accessible via reentrancy",
        "recommendation": "Follow Checks-Effects-Interactions pattern and use reentrancy guards",
        "indicators": [
            r"\.call\{value:",
            r"\.transfer\(",
            r"\.send\(",
        ],
        "state_updates": [
            r"\w+\s*=\s*\w+\s*[+\-\*\/]",
            r"balances?\s*\[[^\]]+\]\s*[+\-=]",
            r"mapping.*=",
        ],
    },
    "missing_annotation_coverage": {
        "severity": "Info",
        "confidence": 0.60,
        "swc_id": None,
        "cwe_id": None,
        "description": "Public/external function lacks Scribble annotations for formal verification coverage",
        "recommendation": "Add #if_succeeds annotation to specify expected behavior",
        "indicators": [
            r"function\s+\w+\s*\([^)]*\)\s*(?:external|public)",
        ],
        "annotation_checks": [
            r"///\s*#if_succeeds",
            r"///\s*#invariant",
            r"///\s*#if_updated",
        ],
    },
}


class ScribbleAdapter(ToolAdapter):
    """
    ConsenSys Scribble adapter for annotation-based verification.

    Runs scribble CLI for annotation processing or falls back to
    annotation coverage analysis.
    """

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="scribble",
            version="1.0.0",
            category=ToolCategory.FORMAL_VERIFICATION,
            author="ConsenSys Diligence / MIESC integration by Fernando Boiero",
            license="Apache-2.0",
            homepage="https://consensys.io/diligence/scribble",
            repository="https://github.com/ConsenSys/scribble",
            documentation="https://docs.scribble.codes/",
            installation_cmd="npm install -g eth-scribble",
            capabilities=[
                ToolCapability(
                    name="annotation_verification",
                    description="Verify Scribble annotations and detect property violations",
                    supported_languages=["solidity"],
                    detection_types=[
                        "invariant_violation",
                        "precondition_failure",
                        "postcondition_failure",
                        "access_control_violation",
                    ],
                ),
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True,
        )

    def is_available(self) -> ToolStatus:
        if shutil.which("scribble"):
            return ToolStatus.AVAILABLE
        return ToolStatus.AVAILABLE  # Fallback analysis available

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        start_time = time.time()
        contract_path = str(Path(contract_path).resolve())

        try:
            if shutil.which("scribble"):
                return self._run_cli(contract_path, start_time, **kwargs)
        except Exception as e:
            logger.debug(f"Scribble CLI failed, using fallback: {e}")

        return self._run_pattern_analysis(contract_path, start_time)

    def _run_cli(self, contract_path: str, start_time: float, **kwargs) -> Dict[str, Any]:
        timeout = kwargs.get("timeout", 120)
        try:
            result = subprocess.run(
                ["scribble", "--arm", contract_path, "--output-mode", "json"],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            if result.returncode == 0 and result.stdout.strip():
                raw = json.loads(result.stdout)
                findings = self.normalize_findings(raw.get("violations", []))
                return {
                    "tool": "scribble",
                    "version": "1.0.0",
                    "status": "success",
                    "findings": findings,
                    "metadata": {
                        "mode": "cli",
                        "contract": contract_path,
                        "annotations_found": raw.get("annotations_processed", 0),
                    },
                    "execution_time": time.time() - start_time,
                    "error": None,
                }
        except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as e:
            logger.debug(f"Scribble CLI error: {e}")

        return self._run_pattern_analysis(contract_path, start_time)

    def _run_pattern_analysis(self, contract_path: str, start_time: float) -> Dict[str, Any]:
        try:
            with open(contract_path, "r", errors="ignore") as f:
                source_code = f.read()
        except Exception as e:
            return {
                "tool": "scribble",
                "version": "1.0.0",
                "status": "error",
                "findings": [],
                "metadata": {},
                "execution_time": time.time() - start_time,
                "error": str(e),
            }

        lines = source_code.split("\n")
        raw_findings = []

        # Count existing annotations
        annotation_count = sum(
            1
            for line in lines
            if re.search(r"///\s*#(if_succeeds|invariant|if_updated)", line)
        )

        for pattern_name, config in SCRIBBLE_ANNOTATION_PATTERNS.items():
            indicators = config.get("indicators", [])
            guards = config.get("guards", [])
            checks = (
                config.get("invariant_checks", [])
                + config.get("validation_checks", [])
                + config.get("annotation_checks", [])
            )

            for regex in indicators:
                for i, line in enumerate(lines, 1):
                    if re.search(regex, line):
                        # Check if guards/checks exist in surrounding context
                        context_start = max(0, i - 5)
                        context_end = min(len(lines), i + 20)
                        context = "\n".join(lines[context_start:context_end])

                        has_guard = any(
                            re.search(g, context) for g in guards
                        )
                        has_check = any(
                            re.search(c, context) for c in checks
                        )

                        if not has_guard and not has_check:
                            confidence = config["confidence"]
                            if annotation_count > 0:
                                confidence *= 0.7  # Contract has some annotations

                            raw_findings.append({
                                "type": pattern_name,
                                "line": i,
                                "file": contract_path,
                                "code": line.strip(),
                                "config": config,
                                "confidence_override": confidence,
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
            "tool": "scribble",
            "version": "1.0.0",
            "status": "success",
            "findings": findings,
            "metadata": {
                "mode": "annotation_analysis",
                "contract": contract_path,
                "existing_annotations": annotation_count,
                "patterns_checked": len(SCRIBBLE_ANNOTATION_PATTERNS),
            },
            "execution_time": time.time() - start_time,
            "error": None,
        }

    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        if not raw_output:
            return []

        findings = []
        for item in raw_output:
            if isinstance(item, dict) and "config" in item:
                config = item["config"]
                finding_id = hashlib.md5(
                    f"scribble:{item['type']}:{item.get('file', '')}:{item.get('line', 0)}".encode()
                ).hexdigest()[:12]

                findings.append({
                    "id": f"SCR-{finding_id}",
                    "type": item["type"],
                    "severity": config["severity"],
                    "confidence": item.get("confidence_override", config["confidence"]),
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
                    "tool": "scribble",
                })
            elif isinstance(item, dict):
                # CLI output format
                finding_id = hashlib.md5(
                    f"scribble:{item.get('annotation', '')}:{item.get('line', 0)}".encode()
                ).hexdigest()[:12]

                findings.append({
                    "id": f"SCR-{finding_id}",
                    "type": item.get("type", "annotation_violation"),
                    "severity": item.get("severity", "High"),
                    "confidence": 0.90,
                    "location": {
                        "file": item.get("file", ""),
                        "line": item.get("line", 0),
                        "function": item.get("function", ""),
                    },
                    "message": item.get("message", "Annotation violation detected"),
                    "description": item.get("description", ""),
                    "recommendation": item.get("recommendation", "Fix the annotation violation"),
                    "swc_id": item.get("swc_id"),
                    "cwe_id": item.get("cwe_id"),
                    "tool": "scribble",
                })

        return findings
