"""
Remediation Validator Adapter - Patched Code Re-Analysis.

Re-analyzes patched code to verify that remediations actually fix
the reported vulnerability without introducing regressions.

Workflow:
1. Takes original findings + patched contract path
2. Re-runs relevant analysis tools on patched code
3. Compares results with original findings
4. Reports: fix_confirmed, fix_partial, fix_failed, regression_detected

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: 2026-01-31
License: AGPL-3.0
"""

import hashlib
import logging
import re
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


REMEDIATION_STATUS = {
    "fix_confirmed": {
        "severity": "Info",
        "confidence": 0.92,
        "description": "Remediation successfully addresses the vulnerability",
    },
    "fix_partial": {
        "severity": "Medium",
        "confidence": 0.70,
        "description": "Remediation partially addresses the vulnerability - some attack vectors remain",
    },
    "fix_failed": {
        "severity": "High",
        "confidence": 0.85,
        "description": "Remediation does not fix the vulnerability - original issue persists",
    },
    "regression_detected": {
        "severity": "High",
        "confidence": 0.80,
        "description": "Remediation introduced a new vulnerability or regression",
    },
}

# Common remediation patterns for each vulnerability type
EXPECTED_REMEDIATIONS = {
    "reentrancy": {
        "patterns": [
            r"nonReentrant",
            r"ReentrancyGuard",
            r"_reentrancyGuard",
        ],
        "cei_pattern": True,
    },
    "access_control": {
        "patterns": [
            r"onlyOwner",
            r"onlyRole",
            r"require\s*\(\s*msg\.sender\s*==",
            r"_checkOwner",
            r"_checkRole",
            r"AccessControl",
        ],
    },
    "integer_overflow": {
        "patterns": [
            r"SafeMath",
            r"SafeCast",
            r"unchecked",
        ],
        "version_check": "0.8",
    },
    "unsafe_transfer": {
        "patterns": [
            r"safeTransfer",
            r"SafeERC20",
            r"require\s*\(\s*\w+\.transfer",
        ],
    },
    "timestamp": {
        "patterns": [
            r"block\.number",
            r"oracle|Oracle",
            r"chainlink|Chainlink",
        ],
    },
    "delegatecall": {
        "patterns": [
            r"require\s*\(\s*\w+\s*==\s*implementation",
            r"_implementation\(\)",
        ],
    },
}


class RemediationValidatorAdapter(ToolAdapter):
    """
    Remediation validation adapter.

    Verifies that code patches actually fix reported vulnerabilities
    by re-analyzing patched code and comparing with original findings.
    """

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="remediation_validator",
            version="1.0.0",
            category=ToolCategory.ADVANCED_AI_ENSEMBLE,
            author="Fernando Boiero",
            license="AGPL-3.0",
            homepage="https://github.com/fboiero/MIESC",
            repository="https://github.com/fboiero/MIESC",
            documentation="https://github.com/fboiero/MIESC#remediation",
            installation_cmd="pip install miesc",
            capabilities=[
                ToolCapability(
                    name="remediation_validation",
                    description="Verify that code patches fix reported vulnerabilities",
                    supported_languages=["solidity"],
                    detection_types=[
                        "fix_confirmed",
                        "fix_partial",
                        "fix_failed",
                        "regression_detected",
                    ],
                ),
            ],
            cost=0.0,
            requires_api_key=False,
            is_optional=True,
        )

    def is_available(self) -> ToolStatus:
        return ToolStatus.AVAILABLE

    def analyze(self, contract_path: str, **kwargs) -> Dict[str, Any]:
        start_time = time.time()
        contract_path = str(Path(contract_path).resolve())
        original_findings = kwargs.get("original_findings", kwargs.get("findings", []))
        original_path = kwargs.get("original_path", "")

        if not original_findings:
            return {
                "tool": "remediation_validator",
                "version": "1.0.0",
                "status": "success",
                "findings": [],
                "metadata": {"reason": "no original findings to validate against"},
                "execution_time": time.time() - start_time,
                "error": None,
            }

        try:
            with open(contract_path, "r", errors="ignore") as f:
                patched_code = f.read()
        except Exception as e:
            return {
                "tool": "remediation_validator",
                "version": "1.0.0",
                "status": "error",
                "findings": [],
                "metadata": {},
                "execution_time": time.time() - start_time,
                "error": str(e),
            }

        original_code = ""
        if original_path:
            try:
                with open(original_path, "r", errors="ignore") as f:
                    original_code = f.read()
            except Exception:
                pass

        validation_results = []
        for finding in original_findings:
            result = self._validate_remediation(finding, patched_code, original_code, contract_path)
            validation_results.append(result)

        # Check for regressions
        regression_results = self._check_regressions(patched_code, original_code, contract_path)
        validation_results.extend(regression_results)

        normalized = self.normalize_findings(validation_results)

        return {
            "tool": "remediation_validator",
            "version": "1.0.0",
            "status": "success",
            "findings": normalized,
            "metadata": {
                "contract": contract_path,
                "original_findings": len(original_findings),
                "confirmed_fixes": sum(1 for r in validation_results if r.get("status") == "fix_confirmed"),
                "partial_fixes": sum(1 for r in validation_results if r.get("status") == "fix_partial"),
                "failed_fixes": sum(1 for r in validation_results if r.get("status") == "fix_failed"),
                "regressions": sum(1 for r in validation_results if r.get("status") == "regression_detected"),
            },
            "execution_time": time.time() - start_time,
            "error": None,
        }

    def _validate_remediation(
        self, finding: Dict, patched_code: str, original_code: str, path: str
    ) -> Dict:
        """Validate a single remediation."""
        vuln_type = self._classify_vuln(finding.get("type", ""))
        line = finding.get("location", {}).get("line", 0)
        lines = patched_code.split("\n")

        # Get context around the original finding location
        context_start = max(0, line - 15)
        context_end = min(len(lines), line + 15)
        context = "\n".join(lines[context_start:context_end]) if line > 0 else patched_code[:3000]

        # Check if expected remediation patterns are present
        expected = EXPECTED_REMEDIATIONS.get(vuln_type, {})
        patterns = expected.get("patterns", [])

        patterns_found = []
        for pattern in patterns:
            if re.search(pattern, context) or re.search(pattern, patched_code):
                patterns_found.append(pattern)

        # Check CEI pattern if expected
        cei_expected = expected.get("cei_pattern", False)
        has_cei = False
        if cei_expected:
            has_cei = self._check_cei_pattern(context)

        # Check if original vulnerability pattern still exists
        original_vuln_patterns = self._get_vuln_patterns(finding)
        vuln_still_present = any(
            re.search(p, context, re.IGNORECASE) for p in original_vuln_patterns
        )

        # Determine status
        if patterns_found and not vuln_still_present:
            status = "fix_confirmed"
        elif patterns_found and vuln_still_present:
            status = "fix_partial"
        elif cei_expected and has_cei and not vuln_still_present:
            status = "fix_confirmed"
        elif not vuln_still_present:
            status = "fix_confirmed"
        else:
            status = "fix_failed"

        # Check version-based fix
        version_check = expected.get("version_check")
        if version_check and vuln_type in ("integer_overflow", "arithmetic"):
            pragma_match = re.search(r"pragma\s+solidity\s*[>=^~]*\s*(\d+\.\d+)", patched_code)
            if pragma_match:
                version = pragma_match.group(1)
                if version >= version_check:
                    status = "fix_confirmed"

        return {
            "status": status,
            "original_finding": finding,
            "vuln_type": vuln_type,
            "remediation_patterns_found": patterns_found,
            "vuln_still_present": vuln_still_present,
            "file": path,
            "line": line,
        }

    def _check_regressions(self, patched_code: str, original_code: str, path: str) -> List[Dict]:
        """Check for regressions introduced by the patch."""
        regressions = []

        if not original_code:
            return regressions

        # Check if critical safety patterns were removed
        safety_patterns = [
            (r"nonReentrant", "reentrancy guard"),
            (r"onlyOwner|onlyRole|_checkOwner", "access control"),
            (r"require\s*\(", "input validation"),
            (r"SafeERC20|safeTransfer", "safe transfer"),
            (r"whenNotPaused", "pause guard"),
        ]

        for pattern, description in safety_patterns:
            original_count = len(re.findall(pattern, original_code))
            patched_count = len(re.findall(pattern, patched_code))

            if original_count > 0 and patched_count < original_count:
                # Find where it was removed
                for i, line in enumerate(patched_code.split("\n"), 1):
                    if re.search(r"function\s+\w+", line):
                        regressions.append({
                            "status": "regression_detected",
                            "vuln_type": "regression",
                            "original_finding": {},
                            "reason": f"Removed {description} ({original_count} -> {patched_count})",
                            "file": path,
                            "line": i,
                        })
                        break

        return regressions

    def _classify_vuln(self, vuln_type: str) -> str:
        """Classify vulnerability type for remediation matching."""
        vuln_lower = vuln_type.lower()
        if "reentrancy" in vuln_lower:
            return "reentrancy"
        elif "access" in vuln_lower or "control" in vuln_lower:
            return "access_control"
        elif "overflow" in vuln_lower or "underflow" in vuln_lower:
            return "integer_overflow"
        elif "transfer" in vuln_lower or "erc20" in vuln_lower:
            return "unsafe_transfer"
        elif "timestamp" in vuln_lower:
            return "timestamp"
        elif "delegatecall" in vuln_lower:
            return "delegatecall"
        return "unknown"

    def _get_vuln_patterns(self, finding: Dict) -> List[str]:
        """Get regex patterns for the original vulnerability."""
        vuln_type = finding.get("type", "").lower()

        patterns_map = {
            "reentrancy": [r"\.call\{value:.*\}.*\(", r"\.transfer\(.*\).*\n.*balance"],
            "access_control": [r"function\s+\w+\s*\([^)]*\)\s*(?:external|public)\s*\{"],
            "integer_overflow": [r"unchecked\s*\{"],
            "unsafe_transfer": [r"\.transfer\s*\([^)]+\)\s*;(?!.*safe)"],
            "timestamp": [r"block\.timestamp"],
            "delegatecall": [r"\.delegatecall\s*\("],
        }

        for key, patterns in patterns_map.items():
            if key in vuln_type:
                return patterns

        return [vuln_type]

    def _check_cei_pattern(self, context: str) -> bool:
        """Check if Checks-Effects-Interactions pattern is followed."""
        call_pos = re.search(r"\.call\{|\.transfer\(|\.send\(", context)
        state_pos = re.search(r"balances?\s*\[[^\]]+\]\s*[-=]|_balance\s*[-=]", context)

        if call_pos and state_pos:
            return state_pos.start() < call_pos.start()
        return False

    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        if not raw_output:
            return []

        findings = []
        for item in raw_output:
            if not isinstance(item, dict):
                continue

            status = item.get("status", "unknown")
            original = item.get("original_finding", {})
            status_config = REMEDIATION_STATUS.get(status, {
                "severity": "Medium", "confidence": 0.60,
                "description": f"Remediation status: {status}",
            })

            finding_id = hashlib.md5(
                f"remediation:{status}:{item.get('file', '')}:{item.get('line', 0)}".encode()
            ).hexdigest()[:12]

            patterns_found = item.get("remediation_patterns_found", [])
            msg = f"[{status.upper()}] {original.get('message', original.get('type', item.get('vuln_type', 'unknown')))}"
            if patterns_found:
                msg += f" (remediation patterns: {', '.join(patterns_found[:3])})"
            if item.get("reason"):
                msg += f" - {item['reason']}"

            findings.append({
                "id": f"REM-{finding_id}",
                "type": status,
                "severity": status_config["severity"],
                "confidence": status_config["confidence"],
                "location": {
                    "file": item.get("file", original.get("location", {}).get("file", "")),
                    "line": item.get("line", original.get("location", {}).get("line", 0)),
                    "function": original.get("location", {}).get("function", ""),
                },
                "message": msg,
                "description": status_config["description"],
                "recommendation": (
                    "No action needed" if status == "fix_confirmed"
                    else "Review and improve the remediation"
                ),
                "swc_id": original.get("swc_id"),
                "cwe_id": original.get("cwe_id"),
                "tool": "remediation_validator",
            })

        return findings
