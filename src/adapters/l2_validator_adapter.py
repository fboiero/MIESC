"""
L2 Validator Adapter - Layer 2 Security Analysis.

Based on: L2Beat research on Layer 2 security properties.

Detects:
- Unsafe cross-domain messaging
- Sequencer trust assumptions
- Missing forced inclusion mechanisms
- Withdrawal delay bypasses
- L2-to-L1 verification gaps
- Centralized sequencer risks

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


L2_VULNERABILITIES = {
    "unsafe_cross_domain_message": {
        "severity": "Critical",
        "confidence": 0.85,
        "swc_id": None,
        "cwe_id": "CWE-345",
        "description": "Cross-domain message not properly validated - sender verification missing",
        "recommendation": "Verify msg.sender is the cross-domain messenger and xDomainMessageSender is trusted",
    },
    "sequencer_trust_assumption": {
        "severity": "High",
        "confidence": 0.75,
        "swc_id": None,
        "cwe_id": "CWE-346",
        "description": "Contract assumes sequencer honesty without fallback mechanism",
        "recommendation": "Implement forced inclusion or escape hatch for sequencer liveness failures",
    },
    "missing_forced_inclusion": {
        "severity": "High",
        "confidence": 0.78,
        "swc_id": None,
        "cwe_id": "CWE-693",
        "description": "No forced transaction inclusion mechanism - sequencer can censor users",
        "recommendation": "Implement L1 forced inclusion queue for censorship resistance",
    },
    "withdrawal_delay_bypass": {
        "severity": "Critical",
        "confidence": 0.82,
        "swc_id": None,
        "cwe_id": "CWE-367",
        "description": "Withdrawal delay can be bypassed allowing premature fund extraction",
        "recommendation": "Enforce minimum withdrawal delay with immutable timelock",
    },
    "l2_to_l1_verification_gap": {
        "severity": "High",
        "confidence": 0.80,
        "swc_id": None,
        "cwe_id": "CWE-354",
        "description": "L2 to L1 message lacks proper state proof verification",
        "recommendation": "Verify L2 state root or merkle proof before processing L1 withdrawal",
    },
    "centralized_sequencer_risk": {
        "severity": "Medium",
        "confidence": 0.72,
        "swc_id": None,
        "cwe_id": "CWE-654",
        "description": "Single sequencer controls transaction ordering - MEV extraction and censorship risk",
        "recommendation": "Plan for decentralized sequencer or implement fair ordering protocol",
    },
    "missing_dispute_mechanism": {
        "severity": "High",
        "confidence": 0.77,
        "swc_id": None,
        "cwe_id": "CWE-693",
        "description": "Optimistic rollup without proper fraud proof / dispute resolution mechanism",
        "recommendation": "Implement challenge period with fraud proof verification",
    },
    "unsafe_l2_gas_estimation": {
        "severity": "Medium",
        "confidence": 0.68,
        "swc_id": None,
        "cwe_id": "CWE-400",
        "description": "L2 gas estimation differs from L1 - transaction may fail or be exploitable",
        "recommendation": "Account for L1 data cost in gas estimation and add safety margin",
    },
}


class L2ValidatorAdapter(ToolAdapter):
    """
    Layer 2 security analysis adapter.

    Analyzes contracts for L2-specific vulnerabilities including
    cross-domain messaging, sequencer trust, and withdrawal safety.
    """

    def get_metadata(self) -> ToolMetadata:
        return ToolMetadata(
            name="l2_validator",
            version="1.0.0",
            category=ToolCategory.CROSSCHAIN_ZK,
            author="Fernando Boiero (based on L2Beat research)",
            license="AGPL-3.0",
            homepage="https://l2beat.com",
            repository="https://github.com/fboiero/MIESC",
            documentation="https://l2beat.com/scaling/summary",
            installation_cmd="pip install miesc",
            capabilities=[
                ToolCapability(
                    name="l2_security",
                    description="Detect Layer 2 specific vulnerabilities",
                    supported_languages=["solidity"],
                    detection_types=[
                        "unsafe_cross_domain_message",
                        "sequencer_trust",
                        "withdrawal_delay_bypass",
                        "forced_inclusion",
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
                "tool": "l2_validator",
                "version": "1.0.0",
                "status": "error",
                "findings": [],
                "metadata": {},
                "execution_time": time.time() - start_time,
                "error": str(e),
            }

        lines = source_code.split("\n")
        is_l2 = self._is_l2_contract(source_code)

        if not is_l2:
            return {
                "tool": "l2_validator",
                "version": "1.0.0",
                "status": "success",
                "findings": [],
                "metadata": {"contract": contract_path, "is_l2": False},
                "execution_time": time.time() - start_time,
                "error": None,
            }

        raw_findings = []
        raw_findings.extend(self._check_cross_domain_messaging(source_code, lines, contract_path))
        raw_findings.extend(self._check_withdrawal_safety(source_code, lines, contract_path))
        raw_findings.extend(self._check_sequencer_dependency(source_code, lines, contract_path))
        raw_findings.extend(self._check_dispute_mechanism(source_code, lines, contract_path))
        raw_findings.extend(self._check_l2_gas(source_code, lines, contract_path))

        seen = set()
        deduped = []
        for f in raw_findings:
            key = f"{f['type']}:{f.get('line', 0)}"
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        findings = self.normalize_findings(deduped)

        return {
            "tool": "l2_validator",
            "version": "1.0.0",
            "status": "success",
            "findings": findings,
            "metadata": {"contract": contract_path, "is_l2": True},
            "execution_time": time.time() - start_time,
            "error": None,
        }

    def _is_l2_contract(self, source: str) -> bool:
        indicators = [
            r"L1|L2|layer2|rollup",
            r"CrossDomainMessenger|crossDomainMessage",
            r"sequencer|Sequencer",
            r"OptimismPortal|ArbSys|ScrollMessenger",
            r"l1Token|l2Token|bridged",
            r"stateRoot|outputRoot",
            r"withdrawalDelay|challengePeriod",
        ]
        matches = sum(1 for p in indicators if re.search(p, source, re.IGNORECASE))
        return matches >= 2

    def _check_cross_domain_messaging(self, source: str, lines: List[str], path: str) -> List[Dict]:
        findings = []
        messenger_patterns = [
            r"ICrossDomainMessenger",
            r"CrossDomainMessenger",
            r"xDomainMessageSender",
            r"sendMessage\s*\(",
        ]
        has_messenger = any(re.search(p, source) for p in messenger_patterns)

        if has_messenger:
            for i, line in enumerate(lines, 1):
                if re.search(r"function\s+\w*(?:receive|handle|process|finalize)\w*\s*\(", line, re.IGNORECASE):
                    context = "\n".join(lines[max(0, i - 2):min(len(lines), i + 15)])
                    has_sender_check = bool(re.search(
                        r"xDomainMessageSender|require\s*\(\s*msg\.sender\s*==\s*messenger",
                        context,
                    ))
                    if not has_sender_check:
                        findings.append({
                            "type": "unsafe_cross_domain_message",
                            "line": i,
                            "file": path,
                            "code": line.strip(),
                        })

        return findings

    def _check_withdrawal_safety(self, source: str, lines: List[str], path: str) -> List[Dict]:
        findings = []
        has_withdrawal = bool(re.search(r"function\s+\w*withdraw\w*|finalizeWithdrawal", source, re.IGNORECASE))

        if has_withdrawal:
            has_delay = bool(re.search(
                r"withdrawalDelay|FINALIZATION_PERIOD|challengePeriod|block\.timestamp\s*>=?\s*\w+\s*\+",
                source,
            ))
            has_proof = bool(re.search(r"proveWithdrawal|merkleProof|stateRoot|outputRoot", source))

            if not has_delay:
                for i, line in enumerate(lines, 1):
                    if re.search(r"function\s+\w*withdraw\w*", line, re.IGNORECASE):
                        findings.append({
                            "type": "withdrawal_delay_bypass",
                            "line": i,
                            "file": path,
                            "code": "Withdrawal without timelock delay enforcement",
                        })
                        break

            if not has_proof:
                for i, line in enumerate(lines, 1):
                    if re.search(r"function\s+\w*finalize\w*withdraw\w*", line, re.IGNORECASE):
                        findings.append({
                            "type": "l2_to_l1_verification_gap",
                            "line": i,
                            "file": path,
                            "code": "L2-to-L1 withdrawal without state proof verification",
                        })
                        break

        return findings

    def _check_sequencer_dependency(self, source: str, lines: List[str], path: str) -> List[Dict]:
        findings = []
        has_sequencer = bool(re.search(r"sequencer|Sequencer", source))

        if has_sequencer:
            has_forced_inclusion = bool(re.search(
                r"forceInclude|forcedInclusion|enqueueL2|appendSequencerBatch|delayedInbox",
                source, re.IGNORECASE,
            ))
            if not has_forced_inclusion:
                for i, line in enumerate(lines, 1):
                    if re.search(r"sequencer", line, re.IGNORECASE):
                        findings.append({
                            "type": "missing_forced_inclusion",
                            "line": i,
                            "file": path,
                            "code": "Sequencer dependency without forced inclusion mechanism",
                        })
                        break

            has_single_sequencer = bool(re.search(r"address\s+(public\s+)?sequencer\b", source))
            has_decentralization = bool(re.search(r"sequencerSet|validators|committee", source, re.IGNORECASE))
            if has_single_sequencer and not has_decentralization:
                for i, line in enumerate(lines, 1):
                    if re.search(r"address\s+(public\s+)?sequencer", line):
                        findings.append({
                            "type": "centralized_sequencer_risk",
                            "line": i,
                            "file": path,
                            "code": line.strip(),
                        })
                        break

        return findings

    def _check_dispute_mechanism(self, source: str, lines: List[str], path: str) -> List[Dict]:
        findings = []
        is_optimistic = bool(re.search(r"optimistic|challenge|fraud|dispute", source, re.IGNORECASE))

        if is_optimistic:
            has_dispute = bool(re.search(
                r"challengeState|submitFraudProof|disputeGame|bisect|challenge\s*\(",
                source, re.IGNORECASE,
            ))
            if not has_dispute:
                for i, line in enumerate(lines, 1):
                    if re.search(r"optimistic|stateCommitment", line, re.IGNORECASE):
                        findings.append({
                            "type": "missing_dispute_mechanism",
                            "line": i,
                            "file": path,
                            "code": "Optimistic system without fraud proof mechanism",
                        })
                        break

        return findings

    def _check_l2_gas(self, source: str, lines: List[str], path: str) -> List[Dict]:
        findings = []
        has_l1_data_cost = bool(re.search(r"l1DataFee|l1GasCost|getL1Fee|L1_FEE_OVERHEAD", source))
        has_gas_estimation = bool(re.search(r"gasEstimate|estimateGas|gasLimit", source, re.IGNORECASE))

        if has_gas_estimation and not has_l1_data_cost:
            for i, line in enumerate(lines, 1):
                if re.search(r"gasEstimate|estimateGas|gasLimit", line, re.IGNORECASE):
                    findings.append({
                        "type": "unsafe_l2_gas_estimation",
                        "line": i,
                        "file": path,
                        "code": "Gas estimation without L1 data cost consideration",
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
            config = L2_VULNERABILITIES.get(vuln_type, {
                "severity": "Medium", "confidence": 0.70,
                "swc_id": None, "cwe_id": None,
                "description": vuln_type, "recommendation": "Review L2 security",
            })

            finding_id = hashlib.md5(
                f"l2:{vuln_type}:{item.get('file', '')}:{item.get('line', 0)}".encode()
            ).hexdigest()[:12]

            findings.append({
                "id": f"L2V-{finding_id}",
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
                "tool": "l2_validator",
            })

        return findings
