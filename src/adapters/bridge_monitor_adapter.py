"""
Bridge Monitor Adapter - Bridge Invariant Verification.

Based on: "Xscope: Hunting for Cross-chain Bridge Attacks" (USENIX Security 2023)

Detects:
- Bridge invariant violations (deposit/withdrawal balance)
- Unverified relay messages
- Missing nonce tracking
- Insufficient finality checks
- Unprotected mint/burn operations

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: 2026-01-31
License: AGPL-3.0
"""

import hashlib
import logging
import re
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


BRIDGE_VULNERABILITIES = {
    "bridge_invariant_violation": {
        "severity": "Critical",
        "confidence": 0.85,
        "swc_id": None,
        "cwe_id": "CWE-682",
        "description": "Bridge invariant may be violated - total locked != total minted across chains",
        "recommendation": "Implement and verify bridge invariants: locked_amount == minted_amount at all times",
    },
    "unverified_relay_message": {
        "severity": "Critical",
        "confidence": 0.88,
        "swc_id": None,
        "cwe_id": "CWE-345",
        "description": "Cross-chain message accepted without proper verification (signature, merkle proof, or oracle consensus)",
        "recommendation": "Verify all relay messages with cryptographic proofs or multi-sig oracle consensus",
    },
    "deposit_withdrawal_imbalance": {
        "severity": "High",
        "confidence": 0.80,
        "swc_id": None,
        "cwe_id": "CWE-682",
        "description": "Deposit and withdrawal logic may allow imbalanced operations leading to fund extraction",
        "recommendation": "Ensure atomic deposit-lock and withdrawal-burn with balance tracking",
    },
    "missing_nonce_tracking": {
        "severity": "Critical",
        "confidence": 0.85,
        "swc_id": None,
        "cwe_id": "CWE-294",
        "description": "Missing nonce or message ID tracking allows replay of cross-chain messages",
        "recommendation": "Track processed message IDs/nonces and reject duplicates",
    },
    "insufficient_finality_check": {
        "severity": "High",
        "confidence": 0.78,
        "swc_id": None,
        "cwe_id": "CWE-367",
        "description": "Bridge does not verify source chain finality before processing - vulnerable to chain reorgs",
        "recommendation": "Wait for sufficient block confirmations or use finality gadget verification",
    },
    "unprotected_mint": {
        "severity": "Critical",
        "confidence": 0.90,
        "swc_id": "SWC-105",
        "cwe_id": "CWE-284",
        "description": "Mint function callable without proper bridge verification - unlimited token creation",
        "recommendation": "Restrict mint to verified bridge messages only with proper access control",
    },
    "missing_pause_mechanism": {
        "severity": "High",
        "confidence": 0.75,
        "swc_id": None,
        "cwe_id": "CWE-693",
        "description": "Bridge lacks emergency pause mechanism for incident response",
        "recommendation": "Implement pausable pattern with guardian/multisig emergency shutdown",
    },
    "single_relayer_trust": {
        "severity": "High",
        "confidence": 0.77,
        "swc_id": None,
        "cwe_id": "CWE-346",
        "description": "Bridge relies on a single relayer/oracle - single point of failure",
        "recommendation": "Use multi-sig or threshold signature scheme for relayer consensus",
    },
}


class BridgeMonitorAdapter(ToolAdapter):
    """
    Bridge invariant verification and cross-chain security analyzer.
    """

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="bridge_monitor",
            version="1.0.0",
            category=ToolCategory.CROSSCHAIN_ZK,
            author="Fernando Boiero (based on Xscope USENIX 2023)",
            license="AGPL-3.0",
            homepage="https://github.com/fboiero/MIESC",
            repository="https://github.com/fboiero/MIESC",
            documentation="https://www.usenix.org/conference/usenixsecurity23",
            installation_cmd="pip install miesc",
            capabilities=[
                ToolCapability(
                    name="bridge_security",
                    description="Detect bridge invariant violations and cross-chain vulnerabilities",
                    supported_languages=["solidity"],
                    detection_types=[
                        "bridge_invariant_violation",
                        "unverified_relay_message",
                        "missing_nonce_tracking",
                        "unprotected_mint",
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
                "tool": "bridge_monitor",
                "version": "1.0.0",
                "status": "error",
                "findings": [],
                "metadata": {},
                "execution_time": time.time() - start_time,
                "error": str(e),
            }

        lines = source_code.split("\n")
        is_bridge = self._is_bridge_contract(source_code)

        if not is_bridge:
            return {
                "tool": "bridge_monitor",
                "version": "1.0.0",
                "status": "success",
                "findings": [],
                "metadata": {"contract": contract_path, "is_bridge": False},
                "execution_time": time.time() - start_time,
                "error": None,
            }

        raw_findings = []

        # Check relay message verification
        raw_findings.extend(self._check_relay_verification(source_code, lines, contract_path))

        # Check nonce tracking
        raw_findings.extend(self._check_nonce_tracking(source_code, lines, contract_path))

        # Check mint/burn protection
        raw_findings.extend(self._check_mint_protection(source_code, lines, contract_path))

        # Check pause mechanism
        raw_findings.extend(self._check_pause_mechanism(source_code, lines, contract_path))

        # Check relayer trust model
        raw_findings.extend(self._check_relayer_trust(source_code, lines, contract_path))

        # Check deposit/withdrawal balance
        raw_findings.extend(self._check_deposit_withdrawal(source_code, lines, contract_path))

        # Check finality
        raw_findings.extend(self._check_finality(source_code, lines, contract_path))

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
            "tool": "bridge_monitor",
            "version": "1.0.0",
            "status": "success",
            "findings": findings,
            "metadata": {"contract": contract_path, "is_bridge": True},
            "execution_time": time.time() - start_time,
            "error": None,
        }

    def _is_bridge_contract(self, source: str) -> bool:
        indicators = [
            r"bridge|Bridge",
            r"deposit.*withdraw|lock.*unlock|lock.*mint",
            r"crossChain|cross_chain|relay|relayer",
            r"sendMessage|receiveMessage|processMessage",
            r"L1.*L2|L2.*L1|source.*destination",
        ]
        matches = sum(1 for p in indicators if re.search(p, source, re.IGNORECASE))
        return matches >= 2

    def _check_relay_verification(self, source: str, lines: List[str], path: str) -> List[Dict]:
        findings = []
        relay_funcs = re.findall(
            r"function\s+(\w*(?:receive|process|handle|execute|relay)\w*)\s*\(",
            source, re.IGNORECASE,
        )
        for func_name in relay_funcs:
            func_match = re.search(
                rf"function\s+{func_name}\s*\([^)]*\)[^{{]*\{{",
                source,
            )
            if func_match:
                # Get function body
                start = func_match.end()
                depth = 1
                pos = start
                for pos in range(start, min(start + 2000, len(source))):
                    if source[pos] == "{":
                        depth += 1
                    elif source[pos] == "}":
                        depth -= 1
                        if depth == 0:
                            break
                body = source[start:pos]
                has_verify = bool(re.search(
                    r"verify|ecrecover|keccak256|merkle|proof|signature|abi\.decode.*bytes32",
                    body, re.IGNORECASE,
                ))
                if not has_verify:
                    line_num = source[:func_match.start()].count("\n") + 1
                    findings.append({
                        "type": "unverified_relay_message",
                        "line": line_num,
                        "file": path,
                        "code": f"Function {func_name} processes messages without verification",
                    })
        return findings

    def _check_nonce_tracking(self, source: str, lines: List[str], path: str) -> List[Dict]:
        findings = []
        has_nonce = bool(re.search(r"nonce|messageId|processedMessages|usedHashes", source, re.IGNORECASE))
        has_relay = bool(re.search(r"relay|receive|process.*message", source, re.IGNORECASE))

        if has_relay and not has_nonce:
            for i, line in enumerate(lines, 1):
                if re.search(r"function\s+\w*(?:relay|receive|process)\w*", line, re.IGNORECASE):
                    findings.append({
                        "type": "missing_nonce_tracking",
                        "line": i,
                        "file": path,
                        "code": "Message processing without nonce/ID tracking",
                    })
                    break
        return findings

    def _check_mint_protection(self, source: str, lines: List[str], path: str) -> List[Dict]:
        findings = []
        for i, line in enumerate(lines, 1):
            if re.search(r"function\s+\w*mint\w*\s*\(", line, re.IGNORECASE):
                context = "\n".join(lines[max(0, i - 3):min(len(lines), i + 15)])
                has_protection = bool(re.search(
                    r"onlyBridge|onlyRelayer|onlyRole|require\s*\(\s*msg\.sender\s*==\s*bridge",
                    context, re.IGNORECASE,
                ))
                if not has_protection:
                    findings.append({
                        "type": "unprotected_mint",
                        "line": i,
                        "file": path,
                        "code": line.strip(),
                    })
        return findings

    def _check_pause_mechanism(self, source: str, lines: List[str], path: str) -> List[Dict]:
        findings = []
        has_pause = bool(re.search(r"Pausable|pause|whenNotPaused|_pause\(\)", source, re.IGNORECASE))
        if not has_pause:
            for i, line in enumerate(lines, 1):
                if re.search(r"contract\s+\w+", line):
                    findings.append({
                        "type": "missing_pause_mechanism",
                        "line": i,
                        "file": path,
                        "code": "Bridge contract without emergency pause mechanism",
                    })
                    break
        return findings

    def _check_relayer_trust(self, source: str, lines: List[str], path: str) -> List[Dict]:
        findings = []
        has_single_relayer = bool(re.search(r"address\s+(public\s+)?relayer\b", source))
        has_multisig = bool(re.search(r"multisig|threshold|quorum|signatures\.length", source, re.IGNORECASE))

        if has_single_relayer and not has_multisig:
            for i, line in enumerate(lines, 1):
                if re.search(r"address\s+(public\s+)?relayer", line):
                    findings.append({
                        "type": "single_relayer_trust",
                        "line": i,
                        "file": path,
                        "code": line.strip(),
                    })
                    break
        return findings

    def _check_deposit_withdrawal(self, source: str, lines: List[str], path: str) -> List[Dict]:
        findings = []
        has_deposit = bool(re.search(r"function\s+\w*deposit\w*\s*\(", source, re.IGNORECASE))
        has_withdraw = bool(re.search(r"function\s+\w*withdraw\w*\s*\(", source, re.IGNORECASE))
        has_balance_tracking = bool(re.search(r"totalDeposited|totalLocked|bridgeBalance", source))

        if has_deposit and has_withdraw and not has_balance_tracking:
            for i, line in enumerate(lines, 1):
                if re.search(r"function\s+\w*deposit\w*", line, re.IGNORECASE):
                    findings.append({
                        "type": "deposit_withdrawal_imbalance",
                        "line": i,
                        "file": path,
                        "code": "Deposit/withdrawal without balance invariant tracking",
                    })
                    break
        return findings

    def _check_finality(self, source: str, lines: List[str], path: str) -> List[Dict]:
        findings = []
        has_finality = bool(re.search(
            r"finality|confirmations|blockConfirmations|minConfirmations|finalized",
            source, re.IGNORECASE,
        ))
        has_cross_chain = bool(re.search(r"sourceChain|fromChain|originChain", source, re.IGNORECASE))

        if has_cross_chain and not has_finality:
            for i, line in enumerate(lines, 1):
                if re.search(r"sourceChain|fromChain|originChain", line, re.IGNORECASE):
                    findings.append({
                        "type": "insufficient_finality_check",
                        "line": i,
                        "file": path,
                        "code": "Cross-chain operation without finality verification",
                    })
                    break
        return findings

    def normalize_findings(self, raw_output: Any) -> List[Dict[str, Any]]:
        if not raw_output:
            return []

        findings = []
        for item in raw_output:
            if not isinstance(item, dict):
                continue

            vuln_type = item.get("type", "unknown")
            config = BRIDGE_VULNERABILITIES.get(vuln_type, {
                "severity": "Medium",
                "confidence": 0.70,
                "swc_id": None,
                "cwe_id": None,
                "description": vuln_type,
                "recommendation": "Review bridge security",
            })

            finding_id = hashlib.md5(
                f"bridge:{vuln_type}:{item.get('file', '')}:{item.get('line', 0)}".encode()
            ).hexdigest()[:12]

            findings.append({
                "id": f"BRG-{finding_id}",
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
                "tool": "bridge_monitor",
            })

        return findings
