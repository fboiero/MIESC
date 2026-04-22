"""
Bridge Vulnerability Pattern Detector.

Patterns derived from real cross-chain bridge exploits totalling $1B+ in losses:

  1. Missing message replay protection  — Wormhole   $326M  (Feb 2022)
  2. Insufficient signature validation  — Ronin       $624M  (Mar 2022)
  3. Hash collision in proof verification— BNB Bridge $586M  (Oct 2022)
  4. Missing origin validation          — Nomad       $190M  (Aug 2022)
  5. Unprotected relay function         — generic
  6. Missing amount bounds              — generic
  7. Token mapping inconsistency        — generic

Entry point: detect_bridge_vulnerabilities(source_code) -> List[Dict]

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL-3.0
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# =============================================================================
# Pattern definitions
# =============================================================================

@dataclass
class BridgePattern:
    """Definition of a single bridge vulnerability pattern."""

    name: str
    severity: str               # Critical | High | Medium | Low
    swc_id: Optional[str]
    description: str
    exploit_ref: str            # Real-world incident reference
    fix: str
    patterns: List[str]         # Regex patterns to match in Solidity source
    absence_patterns: List[str] = field(default_factory=list)  # Must NOT match if present


BRIDGE_EXPLOIT_PATTERNS: Dict[str, BridgePattern] = {
    # -------------------------------------------------------------------------
    # 1. Missing message replay protection (Wormhole $326M, Feb 2022)
    # VAA signature was valid but nonces were not tracked, so the same
    # verified message could be replayed to mint tokens repeatedly.
    # -------------------------------------------------------------------------
    "missing_replay_protection": BridgePattern(
        name="missing_replay_protection",
        severity="Critical",
        swc_id=None,
        description=(
            "Cross-chain message processed without nonce/hash tracking — "
            "allows identical messages to be replayed, minting tokens multiple times."
        ),
        exploit_ref="Wormhole $326M (Feb 2022): VAA verified but nonce not tracked",
        fix=(
            "Track processed message IDs or nonces in a mapping: "
            "`mapping(bytes32 => bool) public processedMessages;` "
            "and revert if already seen."
        ),
        patterns=[
            # Any function that looks like it processes/receives a cross-chain message
            r"function\s+\w*(?:process|receive|execute|complete|finalize)\w*\s*\([^)]*(?:message|payload|vaa|proof)\b",
            r"function\s+\w*(?:relay|bridge|claim)\w*\s*\([^)]*(?:bytes|message|data)\b",
        ],
        absence_patterns=[
            # If any of these are present nearby the contract, replay protection exists
            r"processedMessages|usedNonces|usedHashes|processedVAAs|executedMessages",
            r"mapping\s*\(.*bytes32.*=>\s*bool\)",
            r"nonce\s*[\+\-]?=|nonceUsed|_usedNonce",
        ],
    ),

    # -------------------------------------------------------------------------
    # 2. Insufficient signature validation (Ronin $624M, Mar 2022)
    # Validator set had only 5 keys controlled by the team; attacker compromised
    # 5/9 validators. Pattern: threshold is hardcoded too low or unprotected.
    # -------------------------------------------------------------------------
    "insufficient_signature_validation": BridgePattern(
        name="insufficient_signature_validation",
        severity="Critical",
        swc_id=None,
        description=(
            "Validator/signer threshold is hardcoded or insufficiently enforced — "
            "compromising a small number of validators lets an attacker forge approvals."
        ),
        exploit_ref="Ronin Bridge $624M (Mar 2022): 5/9 validators controlled by one entity",
        fix=(
            "Use a dynamic validator set with a configurable threshold (≥2/3 of validators). "
            "Store validators in a managed set; emit events on every change."
        ),
        patterns=[
            # Hardcoded small threshold literals next to validator/signature checks
            r"require\s*\([^)]*signatures?\.length\s*[><=!]+\s*[1-4]\b",
            r"validatorCount\s*[><=!]+\s*[1-4]\b",
            r"uint\d*\s+(public\s+)?(?:required|threshold|minSigners)\s*=\s*[1-4]\b",
        ],
        absence_patterns=[],
    ),

    # -------------------------------------------------------------------------
    # 3. Hash collision in proof verification (BNB Bridge $586M, Oct 2022)
    # IAVL Merkle proof library had a bug that allowed forging arbitrary proofs
    # via hash collision. Pattern: proof verification without leaf encoding guard.
    # -------------------------------------------------------------------------
    "hash_collision_proof_verification": BridgePattern(
        name="hash_collision_proof_verification",
        severity="Critical",
        swc_id=None,
        description=(
            "Merkle/inclusion proof verified without distinguishing leaf from inner nodes — "
            "enables second-preimage (hash collision) proof forgery."
        ),
        exploit_ref="BNB Bridge $586M (Oct 2022): IAVL proof forging via missing leaf prefix",
        fix=(
            "Prefix leaf hashes with 0x00 and inner-node hashes with 0x01 before hashing "
            "(RFC 6962 / OpenZeppelin MerkleProof). Never use raw keccak256(a, b) for both."
        ),
        patterns=[
            r"keccak256\s*\(\s*abi\.encodePacked\s*\([^)]*proof",
            r"verifyProof|verify_proof|verifyMerkle|MerkleProof\.verify",
            r"function\s+\w*(?:verify|check)\w*Proof\w*\s*\(",
        ],
        absence_patterns=[
            # OpenZeppelin's MerkleProof already applies the leaf/inner prefix
            r"@openzeppelin.*MerkleProof|import.*MerkleProof",
            r"0x00.*keccak|leaf.*0x00|leafHash",
        ],
    ),

    # -------------------------------------------------------------------------
    # 4. Missing cross-chain message origin validation (Nomad $190M, Aug 2022)
    # Nomad accepted a zero-hash root as a valid Merkle root, which meant ANY
    # message could be processed without a legitimate proof.
    # -------------------------------------------------------------------------
    "missing_origin_validation": BridgePattern(
        name="missing_origin_validation",
        severity="Critical",
        swc_id=None,
        description=(
            "Incoming cross-chain message accepted without validating its origin chain/sender — "
            "allows any caller to inject arbitrary messages (Nomad zero-hash root)."
        ),
        exploit_ref="Nomad Bridge $190M (Aug 2022): zero-hash accepted as valid Merkle root",
        fix=(
            "Always validate: (1) the source chain ID matches an allow-listed chain, "
            "(2) the sender address matches the registered remote contract, "
            "(3) the Merkle root is non-zero before verification."
        ),
        patterns=[
            # Function that receives a message with a bytes32 root/hash param but no require
            r"function\s+\w*(?:process|handle|dispatch|receive)\w*\s*\([^)]*bytes32[^)]*\)",
        ],
        absence_patterns=[
            r"require\s*\([^)]*!=\s*bytes32\(0\)|acceptableRoot|committedRoot",
            r"trustedRemote|allowedSender|originSender",
        ],
    ),

    # -------------------------------------------------------------------------
    # 5. Unprotected relay function (generic)
    # A relay/execute function that any EOA can call without access control.
    # -------------------------------------------------------------------------
    "unprotected_relay_function": BridgePattern(
        name="unprotected_relay_function",
        severity="High",
        swc_id="SWC-105",
        description=(
            "Relay or bridge execution function has no access control modifier — "
            "anyone can call it with arbitrary parameters."
        ),
        exploit_ref="Generic pattern — no specific incident but present in multiple audits",
        fix=(
            "Add `onlyRelayer`, `onlyOwner`, or a role-based modifier to relay functions. "
            "Alternatively, rely on cryptographic proof verification inside the function."
        ),
        patterns=[
            r"function\s+\w*(?:relay|execute|dispatch)\w*\s*\([^)]*\)\s*(?:external|public)\s*\{",
        ],
        absence_patterns=[
            r"onlyRelayer|onlyOwner|onlyRole|whenNotPaused|nonReentrant|require\s*\(\s*msg\.sender",
        ],
    ),

    # -------------------------------------------------------------------------
    # 6. Missing amount bounds (generic)
    # No maximum per-transfer limit — attacker drains the bridge in one tx.
    # -------------------------------------------------------------------------
    "missing_amount_bounds": BridgePattern(
        name="missing_amount_bounds",
        severity="High",
        swc_id=None,
        description=(
            "Bridge transfer function lacks a maximum per-transaction amount limit — "
            "a single call can drain the entire bridge liquidity pool."
        ),
        exploit_ref="Generic pattern — defense-in-depth best practice for all bridges",
        fix=(
            "Enforce `require(amount <= maxTransferAmount, 'exceeds limit');` "
            "and consider daily aggregate limits with a rate-limiter contract."
        ),
        patterns=[
            r"function\s+\w*(?:deposit|lock|bridge|send)\w*\s*\([^)]*uint\d*\s+amount\b",
        ],
        absence_patterns=[
            r"maxTransfer|transferLimit|MAX_AMOUNT|dailyLimit|require\s*\([^)]*amount\s*<=",
        ],
    ),

    # -------------------------------------------------------------------------
    # 7. Token mapping inconsistency (generic)
    # Source chain token address mapped to a wrong destination token, or no
    # mapping check at all, leading to wrong token being minted/burned.
    # -------------------------------------------------------------------------
    "token_mapping_inconsistency": BridgePattern(
        name="token_mapping_inconsistency",
        severity="High",
        swc_id=None,
        description=(
            "Bridge does not verify that the destination token corresponds to the source token — "
            "minting the wrong token or minting on the wrong chain."
        ),
        exploit_ref="Generic pattern — common finding in bridge security audits",
        fix=(
            "Maintain an explicit bidirectional mapping: "
            "`mapping(address => address) public tokenMapping;` "
            "and require `tokenMapping[sourceToken] == destToken` before minting."
        ),
        patterns=[
            # Mint is called with a token address that is not cross-referenced
            r"function\s+\w*mint\w*\s*\([^)]*address\s+token",
            r"IMintable\([^)]+\)\.mint\s*\(",
        ],
        absence_patterns=[
            r"tokenMapping|tokenMap|localToRemote|remoteToLocal|supportedTokens\[",
        ],
    ),
}


# =============================================================================
# Detection function
# =============================================================================


def detect_bridge_vulnerabilities(source_code: str) -> List[Dict[str, Any]]:
    """Scan Solidity source code for known bridge exploit patterns.

    Returns a list of finding dicts compatible with the MIESC finding schema.
    Each finding includes severity, description, exploit reference, and fix advice.

    Parameters
    ----------
    source_code:
        Raw Solidity source as a string.

    Returns
    -------
    list of dict
        Zero or more findings, each with keys: type, severity, swc_id,
        description, exploit_ref, fix, line, tool.
    """
    findings: List[Dict[str, Any]] = []
    lines = source_code.split("\n")

    for pattern_name, bp in BRIDGE_EXPLOIT_PATTERNS.items():
        # Check whether any trigger pattern fires
        trigger_line: Optional[int] = None
        for pat in bp.patterns:
            for i, line in enumerate(lines, 1):
                if re.search(pat, line, re.IGNORECASE):
                    trigger_line = i
                    break
            if trigger_line is not None:
                break

        if trigger_line is None:
            # No trigger found — pattern does not apply
            continue

        # Check whether any absence_pattern (mitigating factor) is present
        mitigated = False
        for absence_pat in bp.absence_patterns:
            if re.search(absence_pat, source_code, re.IGNORECASE):
                mitigated = True
                break

        if mitigated:
            continue

        findings.append({
            "type": pattern_name,
            "severity": bp.severity,
            "swc_id": bp.swc_id,
            "description": bp.description,
            "exploit_ref": bp.exploit_ref,
            "fix": bp.fix,
            "line": trigger_line,
            "tool": "bridge-patterns",
            "confidence": 0.80,
            "message": bp.description,
            "recommendation": bp.fix,
        })

    return findings
