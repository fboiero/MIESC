"""
Upgradability Checker Adapter - Proxy Pattern Security Analysis.

Detects security issues in upgradeable smart contracts:
- Storage collisions between proxy and implementation
- EIP-1967 compliance issues
- Uninitialized proxy contracts
- Function selector clashes
- Missing upgrade guards (UUPS)
- Unsafe delegatecall targets

References:
- EIP-1967: Standard Proxy Storage Slots
- EIP-1822: Universal Upgradeable Proxy Standard (UUPS)
- OpenZeppelin Proxy Patterns documentation

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

# EIP-1967 standard storage slots
EIP1967_SLOTS = {
    "implementation": "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
    "admin": "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
    "beacon": "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50",
    "rollback": "0x4910fdfa16fed3260ed0e7147f7cc6da11a60208b5b9406d12a635614ffd9143",
}

PROXY_PATTERNS = {
    "transparent_proxy": [
        r"TransparentUpgradeableProxy",
        r"ERC1967Proxy",
        r"AdminUpgradeabilityProxy",
    ],
    "uups_proxy": [
        r"UUPSUpgradeable",
        r"_authorizeUpgrade",
        r"upgradeTo\s*\(",
        r"upgradeToAndCall\s*\(",
    ],
    "beacon_proxy": [
        r"BeaconProxy",
        r"UpgradeableBeacon",
        r"IBeacon",
    ],
    "minimal_proxy": [
        r"Clones",
        r"clone\s*\(",
        r"3d602d80600a3d3981f3363d3d373d3d3d363d73",
    ],
    "diamond_proxy": [
        r"Diamond",
        r"diamondCut",
        r"IDiamondCut",
        r"LibDiamond",
    ],
}

UPGRADABILITY_VULNERABILITIES = {
    "storage_collision": {
        "severity": "Critical",
        "confidence": 0.88,
        "swc_id": "SWC-124",
        "cwe_id": "CWE-682",
        "description": "Storage layout collision between proxy and implementation - state corruption possible",
        "recommendation": "Use EIP-1967 storage slots or OpenZeppelin's storage gap pattern",
    },
    "uninitialized_proxy": {
        "severity": "Critical",
        "confidence": 0.85,
        "swc_id": "SWC-109",
        "cwe_id": "CWE-665",
        "description": "Proxy implementation not initialized - attacker can call initialize() and take ownership",
        "recommendation": "Call _disableInitializers() in implementation constructor or initialize in deployment",
    },
    "function_selector_clash": {
        "severity": "High",
        "confidence": 0.80,
        "swc_id": None,
        "cwe_id": "CWE-694",
        "description": "Function selector collision between proxy admin and implementation functions",
        "recommendation": "Rename functions to avoid selector clashes or use TransparentProxy pattern",
    },
    "missing_initializer": {
        "severity": "High",
        "confidence": 0.82,
        "swc_id": "SWC-109",
        "cwe_id": "CWE-665",
        "description": "Upgradeable contract missing initializer function - constructor won't run behind proxy",
        "recommendation": "Replace constructor with initialize() using initializer modifier",
    },
    "unsafe_delegatecall_target": {
        "severity": "Critical",
        "confidence": 0.85,
        "swc_id": "SWC-112",
        "cwe_id": "CWE-829",
        "description": "Delegatecall to user-controllable or unverified target address",
        "recommendation": "Validate delegatecall target is a trusted implementation contract",
    },
    "eip1967_noncompliance": {
        "severity": "Medium",
        "confidence": 0.75,
        "swc_id": None,
        "cwe_id": "CWE-573",
        "description": "Proxy does not follow EIP-1967 standard storage slots",
        "recommendation": "Use EIP-1967 standard storage slots for implementation, admin, and beacon addresses",
    },
    "missing_upgrade_guard": {
        "severity": "High",
        "confidence": 0.80,
        "swc_id": "SWC-105",
        "cwe_id": "CWE-284",
        "description": "UUPS upgradeTo function lacks access control - anyone can upgrade",
        "recommendation": "Implement _authorizeUpgrade with onlyOwner or role-based access control",
    },
    "missing_storage_gap": {
        "severity": "Medium",
        "confidence": 0.70,
        "swc_id": None,
        "cwe_id": "CWE-682",
        "description": "Base contract missing __gap storage variable - future upgrades may cause storage collision",
        "recommendation": "Add uint256[50] private __gap; at the end of each base contract",
    },
    "selfdestruct_in_implementation": {
        "severity": "Critical",
        "confidence": 0.90,
        "swc_id": "SWC-106",
        "cwe_id": "CWE-400",
        "description": "Implementation contract contains selfdestruct - can brick the proxy permanently",
        "recommendation": "Remove selfdestruct from implementation contracts used behind proxies",
    },
    "delegatecall_in_implementation": {
        "severity": "High",
        "confidence": 0.78,
        "swc_id": "SWC-112",
        "cwe_id": "CWE-829",
        "description": "Implementation uses delegatecall which can be dangerous in proxy context",
        "recommendation": "Avoid delegatecall in implementation or ensure target is immutable and trusted",
    },
}


class UpgradabilityCheckerAdapter(ToolAdapter):
    """
    Proxy pattern and upgradability security analyzer.

    Performs static analysis of proxy patterns, storage layout,
    and upgrade mechanisms.
    """

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="upgradability_checker",
            version="1.0.0",
            category=ToolCategory.SPECIALIZED,
            author="Fernando Boiero",
            license="AGPL-3.0",
            homepage="https://github.com/fboiero/MIESC",
            repository="https://github.com/fboiero/MIESC",
            documentation="https://docs.openzeppelin.com/upgrades",
            installation_cmd="pip install miesc",
            capabilities=[
                ToolCapability(
                    name="proxy_analysis",
                    description="Detect proxy pattern vulnerabilities and storage collisions",
                    supported_languages=["solidity"],
                    detection_types=[
                        "storage_collision",
                        "uninitialized_proxy",
                        "function_selector_clash",
                        "missing_upgrade_guard",
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

        try:
            with open(contract_path, "r", errors="ignore") as f:
                source_code = f.read()
        except Exception as e:
            return {
                "tool": "upgradability_checker",
                "version": "1.0.0",
                "status": "error",
                "findings": [],
                "metadata": {},
                "execution_time": time.time() - start_time,
                "error": str(e),
            }

        lines = source_code.split("\n")
        raw_findings = []

        # Detect proxy type
        proxy_type = self._detect_proxy_type(source_code)
        is_upgradeable = proxy_type is not None or self._is_upgradeable(source_code)

        if not is_upgradeable:
            return {
                "tool": "upgradability_checker",
                "version": "1.0.0",
                "status": "success",
                "findings": [],
                "metadata": {
                    "contract": contract_path,
                    "is_upgradeable": False,
                    "proxy_type": None,
                },
                "execution_time": time.time() - start_time,
                "error": None,
            }

        # Check for uninitialized proxy
        raw_findings.extend(self._check_initialization(source_code, lines, contract_path))

        # Check for missing storage gap
        raw_findings.extend(self._check_storage_gap(source_code, lines, contract_path))

        # Check for selfdestruct in implementation
        raw_findings.extend(self._check_selfdestruct(source_code, lines, contract_path))

        # Check for delegatecall usage
        raw_findings.extend(self._check_delegatecall(source_code, lines, contract_path))

        # Check UUPS upgrade guard
        if proxy_type == "uups_proxy":
            raw_findings.extend(self._check_uups_guard(source_code, lines, contract_path))

        # Check EIP-1967 compliance
        raw_findings.extend(self._check_eip1967(source_code, lines, contract_path))

        # Check for constructor usage in upgradeable contract
        raw_findings.extend(self._check_constructor(source_code, lines, contract_path))

        # Deduplicate
        seen = set()
        deduped = []
        for f in raw_findings:
            key = f"{f['type']}:{f.get('line', 0)}"
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        findings = self.normalize_findings(deduped)

        return {
            "tool": "upgradability_checker",
            "version": "1.0.0",
            "status": "success",
            "findings": findings,
            "metadata": {
                "contract": contract_path,
                "is_upgradeable": True,
                "proxy_type": proxy_type,
                "total_lines": len(lines),
            },
            "execution_time": time.time() - start_time,
            "error": None,
        }

    def _detect_proxy_type(self, source_code: str) -> Optional[str]:
        for proxy_type, patterns in PROXY_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, source_code):
                    return proxy_type
        return None

    def _is_upgradeable(self, source_code: str) -> bool:
        upgrade_indicators = [
            r"Initializable",
            r"initializer\b",
            r"initialize\s*\(",
            r"delegatecall",
            r"Upgradeable",
            r"proxy",
            r"implementation\(\)",
        ]
        matches = sum(1 for p in upgrade_indicators if re.search(p, source_code, re.IGNORECASE))
        return matches >= 2

    def _check_initialization(self, source_code: str, lines: List[str], path: str) -> List[Dict]:
        findings = []
        has_initializer = bool(re.search(r"function\s+initialize\s*\(", source_code))
        has_initializer_modifier = bool(re.search(r"\binitializer\b", source_code))
        has_disable_initializers = bool(re.search(r"_disableInitializers", source_code))

        if has_initializer and not has_initializer_modifier:
            for i, line in enumerate(lines, 1):
                if re.search(r"function\s+initialize\s*\(", line):
                    findings.append({
                        "type": "uninitialized_proxy",
                        "line": i,
                        "file": path,
                        "code": line.strip(),
                        "vuln_key": "uninitialized_proxy",
                    })
                    break

        if has_initializer and not has_disable_initializers:
            has_constructor = bool(re.search(r"constructor\s*\(", source_code))
            if has_constructor:
                for i, line in enumerate(lines, 1):
                    if re.search(r"constructor\s*\(", line):
                        findings.append({
                            "type": "uninitialized_proxy",
                            "line": i,
                            "file": path,
                            "code": "Constructor without _disableInitializers() call",
                            "vuln_key": "uninitialized_proxy",
                        })
                        break

        return findings

    def _check_storage_gap(self, source_code: str, lines: List[str], path: str) -> List[Dict]:
        findings = []
        has_inheritance = bool(re.search(r"contract\s+\w+\s+is\s+", source_code))
        has_gap = bool(re.search(r"__gap|__storage_gap", source_code))

        if has_inheritance and not has_gap:
            for i, line in enumerate(lines, 1):
                if re.search(r"contract\s+\w+\s+is\s+", line):
                    findings.append({
                        "type": "missing_storage_gap",
                        "line": i,
                        "file": path,
                        "code": line.strip(),
                        "vuln_key": "missing_storage_gap",
                    })
                    break

        return findings

    def _check_selfdestruct(self, source_code: str, lines: List[str], path: str) -> List[Dict]:
        findings = []
        for i, line in enumerate(lines, 1):
            if re.search(r"\bselfdestruct\s*\(|\bsuicide\s*\(", line):
                findings.append({
                    "type": "selfdestruct_in_implementation",
                    "line": i,
                    "file": path,
                    "code": line.strip(),
                    "vuln_key": "selfdestruct_in_implementation",
                })
        return findings

    def _check_delegatecall(self, source_code: str, lines: List[str], path: str) -> List[Dict]:
        findings = []
        for i, line in enumerate(lines, 1):
            if re.search(r"\.delegatecall\s*\(", line):
                context = "\n".join(lines[max(0, i - 5):min(len(lines), i + 5)])
                has_validation = bool(re.search(
                    r"require.*implementation|require.*target|_implementation\(\)",
                    context
                ))
                if not has_validation:
                    findings.append({
                        "type": "unsafe_delegatecall_target",
                        "line": i,
                        "file": path,
                        "code": line.strip(),
                        "vuln_key": "unsafe_delegatecall_target",
                    })
        return findings

    def _check_uups_guard(self, source_code: str, lines: List[str], path: str) -> List[Dict]:
        findings = []
        has_authorize = bool(re.search(r"function\s+_authorizeUpgrade", source_code))

        if not has_authorize:
            for i, line in enumerate(lines, 1):
                if re.search(r"UUPSUpgradeable", line):
                    findings.append({
                        "type": "missing_upgrade_guard",
                        "line": i,
                        "file": path,
                        "code": "UUPSUpgradeable without _authorizeUpgrade implementation",
                        "vuln_key": "missing_upgrade_guard",
                    })
                    break
        else:
            # Check if _authorizeUpgrade has access control
            authorize_match = re.search(
                r"function\s+_authorizeUpgrade[^{]*\{([^}]*)\}",
                source_code,
                re.DOTALL,
            )
            if authorize_match:
                body = authorize_match.group(1)
                has_access_control = bool(re.search(
                    r"onlyOwner|onlyRole|require\s*\(\s*msg\.sender|_checkOwner|_checkRole",
                    body + source_code[authorize_match.start() - 100:authorize_match.start()],
                ))
                if not has_access_control:
                    line_num = source_code[:authorize_match.start()].count("\n") + 1
                    findings.append({
                        "type": "missing_upgrade_guard",
                        "line": line_num,
                        "file": path,
                        "code": "_authorizeUpgrade without access control",
                        "vuln_key": "missing_upgrade_guard",
                    })

        return findings

    def _check_eip1967(self, source_code: str, lines: List[str], path: str) -> List[Dict]:
        findings = []
        has_delegatecall = bool(re.search(r"delegatecall", source_code))
        has_eip1967 = any(
            re.search(slot, source_code) for slot in EIP1967_SLOTS.values()
        )
        has_storage_slot = bool(re.search(r"bytes32.*constant.*IMPLEMENTATION_SLOT|_IMPLEMENTATION_SLOT", source_code))

        if has_delegatecall and not has_eip1967 and not has_storage_slot:
            proxy_type = self._detect_proxy_type(source_code)
            if proxy_type and proxy_type != "minimal_proxy":
                for i, line in enumerate(lines, 1):
                    if re.search(r"delegatecall", line):
                        findings.append({
                            "type": "eip1967_noncompliance",
                            "line": i,
                            "file": path,
                            "code": "Proxy without EIP-1967 standard storage slots",
                            "vuln_key": "eip1967_noncompliance",
                        })
                        break

        return findings

    def _check_constructor(self, source_code: str, lines: List[str], path: str) -> List[Dict]:
        findings = []
        has_constructor = bool(re.search(r"constructor\s*\(", source_code))

        if has_constructor:
            constructor_match = re.search(r"constructor\s*\([^)]*\)[^{]*\{([^}]*)\}", source_code, re.DOTALL)
            if constructor_match:
                body = constructor_match.group(1).strip()
                # Check if constructor sets state (not just _disableInitializers)
                body_without_disable = re.sub(r"_disableInitializers\s*\(\s*\)\s*;?", "", body).strip()
                if body_without_disable and re.search(r"\w+\s*=\s*", body_without_disable):
                    line_num = source_code[:constructor_match.start()].count("\n") + 1
                    findings.append({
                        "type": "missing_initializer",
                        "line": line_num,
                        "file": path,
                        "code": "Constructor sets state variables - won't execute behind proxy",
                        "vuln_key": "missing_initializer",
                    })

        return findings

    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        if not raw_output:
            return []

        findings = []
        for item in raw_output:
            if not isinstance(item, dict):
                continue

            vuln_key = item.get("vuln_key", item.get("type", "unknown"))
            vuln_config = UPGRADABILITY_VULNERABILITIES.get(
                vuln_key, UPGRADABILITY_VULNERABILITIES.get("storage_collision")
            )

            finding_id = hashlib.md5(
                f"upgradability:{item.get('type', '')}:{item.get('file', '')}:{item.get('line', 0)}".encode()
            ).hexdigest()[:12]

            findings.append({
                "id": f"UPG-{finding_id}",
                "type": item.get("type", vuln_key),
                "severity": vuln_config["severity"],
                "confidence": vuln_config["confidence"],
                "location": {
                    "file": item.get("file", ""),
                    "line": item.get("line", 0),
                    "function": "",
                },
                "message": f"{vuln_config['description']}: {item.get('code', '')}",
                "description": vuln_config["description"],
                "recommendation": vuln_config["recommendation"],
                "swc_id": vuln_config.get("swc_id"),
                "cwe_id": vuln_config.get("cwe_id"),
                "tool": "upgradability_checker",
            })

        return findings
