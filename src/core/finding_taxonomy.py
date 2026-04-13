"""
Finding taxonomy normalization.

Maps tool-specific finding types (Slither's `arbitrary-send-eth`, Aderyn's
`unprotected-upgrade`, Mythril's `integer-overflow`, etc.) onto a canonical
vocabulary so downstream logic (DeepAuditAgent Phase 3 branches, FP
classifier, reporting) can operate uniformly.

Why this exists: real-world tools use idiosyncratic detector names. The
pre-v5.1.7 DeepAuditAgent tried to match by substring ("oracle" in ftype)
which silently missed the bulk of relevant findings. This module gives us
a deterministic mapping and a single source of truth.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL-3.0
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, Iterable, Optional


class CanonicalCategory(str, Enum):
    """The canonical finding categories MIESC reasons about."""

    REENTRANCY = "reentrancy"
    ACCESS_CONTROL = "access_control"
    ORACLE_MANIPULATION = "oracle_manipulation"
    FLASH_LOAN = "flash_loan"
    ARITHMETIC = "arithmetic"
    UNCHECKED_CALL = "unchecked_call"
    INITIALIZATION = "initialization"
    SIGNATURE_VERIFICATION = "signature_verification"
    BAD_RANDOMNESS = "bad_randomness"
    TIME_MANIPULATION = "time_manipulation"
    DENIAL_OF_SERVICE = "denial_of_service"
    FRONT_RUNNING = "front_running"
    PROXY_UPGRADE = "proxy_upgrade"
    CENTRALIZATION = "centralization"
    INPUT_VALIDATION = "input_validation"
    OTHER = "other"


# =============================================================================
# Tool-specific type -> canonical category
#
# Built from real detector vocabularies:
#   - Slither: https://github.com/crytic/slither/wiki/Detector-Documentation
#   - Aderyn:  https://github.com/Cyfrin/aderyn/tree/dev/src/detect
#   - Mythril: https://github.com/Consensys/mythril
#   - SWC:     https://swcregistry.io/
# =============================================================================

_DIRECT_MAP: Dict[str, CanonicalCategory] = {
    # ----- Reentrancy -----
    "reentrancy-eth": CanonicalCategory.REENTRANCY,
    "reentrancy-no-eth": CanonicalCategory.REENTRANCY,
    "reentrancy-unlimited-gas": CanonicalCategory.REENTRANCY,
    "reentrancy-events": CanonicalCategory.REENTRANCY,
    "reentrancy-benign": CanonicalCategory.REENTRANCY,
    "reentrancy": CanonicalCategory.REENTRANCY,
    "cross-function-reentrancy": CanonicalCategory.REENTRANCY,
    "external-call-before-state-change": CanonicalCategory.REENTRANCY,
    "read-only-reentrancy": CanonicalCategory.REENTRANCY,
    "SWC-107": CanonicalCategory.REENTRANCY,

    # ----- Access control / authorization -----
    "arbitrary-send-eth": CanonicalCategory.ACCESS_CONTROL,
    "arbitrary-send-erc20": CanonicalCategory.ACCESS_CONTROL,
    "arbitrary-send-erc20-permit": CanonicalCategory.ACCESS_CONTROL,
    "suicidal": CanonicalCategory.ACCESS_CONTROL,
    "selfdestruct-identifier": CanonicalCategory.ACCESS_CONTROL,
    "tx-origin": CanonicalCategory.ACCESS_CONTROL,
    "tx.origin": CanonicalCategory.ACCESS_CONTROL,
    "unprotected-upgrade": CanonicalCategory.ACCESS_CONTROL,
    "access-control": CanonicalCategory.ACCESS_CONTROL,
    "access-control-missing": CanonicalCategory.ACCESS_CONTROL,
    "missing-access-control": CanonicalCategory.ACCESS_CONTROL,
    "incorrect-owner": CanonicalCategory.ACCESS_CONTROL,
    "protected-vars": CanonicalCategory.ACCESS_CONTROL,
    "SWC-105": CanonicalCategory.ACCESS_CONTROL,
    "SWC-106": CanonicalCategory.ACCESS_CONTROL,
    "SWC-115": CanonicalCategory.ACCESS_CONTROL,

    # ----- Oracle / price manipulation -----
    "oracle-manipulation": CanonicalCategory.ORACLE_MANIPULATION,
    "price-oracle": CanonicalCategory.ORACLE_MANIPULATION,
    "spot-price": CanonicalCategory.ORACLE_MANIPULATION,
    "stale-price": CanonicalCategory.ORACLE_MANIPULATION,
    "stale-oracle": CanonicalCategory.ORACLE_MANIPULATION,
    "chainlink-stale": CanonicalCategory.ORACLE_MANIPULATION,
    "twap-missing": CanonicalCategory.ORACLE_MANIPULATION,
    "pragma_oracle_stale": CanonicalCategory.ORACLE_MANIPULATION,

    # ----- Flash loan -----
    "flash-loan": CanonicalCategory.FLASH_LOAN,
    "flash-loan-attack": CanonicalCategory.FLASH_LOAN,
    "flash-loan-governance": CanonicalCategory.FLASH_LOAN,
    "single-tx-vote": CanonicalCategory.FLASH_LOAN,

    # ----- Arithmetic -----
    "integer-overflow": CanonicalCategory.ARITHMETIC,
    "integer-underflow": CanonicalCategory.ARITHMETIC,
    "divide-before-multiply": CanonicalCategory.ARITHMETIC,
    "unchecked_u256": CanonicalCategory.ARITHMETIC,
    "overflow": CanonicalCategory.ARITHMETIC,
    "underflow": CanonicalCategory.ARITHMETIC,
    "SWC-101": CanonicalCategory.ARITHMETIC,

    # ----- Unchecked calls -----
    "unchecked-transfer": CanonicalCategory.UNCHECKED_CALL,
    "unchecked-lowlevel": CanonicalCategory.UNCHECKED_CALL,
    "unchecked-low-level-calls": CanonicalCategory.UNCHECKED_CALL,
    "unchecked-send": CanonicalCategory.UNCHECKED_CALL,
    "unchecked-call": CanonicalCategory.UNCHECKED_CALL,
    "unused-return": CanonicalCategory.UNCHECKED_CALL,
    "unchecked_syscall_result": CanonicalCategory.UNCHECKED_CALL,
    "SWC-104": CanonicalCategory.UNCHECKED_CALL,

    # ----- Initialization -----
    "uninitialized-local": CanonicalCategory.INITIALIZATION,
    "uninitialized-state": CanonicalCategory.INITIALIZATION,
    "uninitialized-storage": CanonicalCategory.INITIALIZATION,
    "upgrade_no_init_guard": CanonicalCategory.INITIALIZATION,
    "missing-initializer-guard": CanonicalCategory.INITIALIZATION,

    # ----- Signature verification -----
    "ecrecover-malleable": CanonicalCategory.SIGNATURE_VERIFICATION,
    "ecrecover-no-zero-check": CanonicalCategory.SIGNATURE_VERIFICATION,
    "signature-malleability": CanonicalCategory.SIGNATURE_VERIFICATION,
    "signature_replay": CanonicalCategory.SIGNATURE_VERIFICATION,
    "merkle-proof-forge": CanonicalCategory.SIGNATURE_VERIFICATION,

    # ----- Randomness -----
    "weak-prng": CanonicalCategory.BAD_RANDOMNESS,
    "bad-randomness": CanonicalCategory.BAD_RANDOMNESS,
    "weak-randomness": CanonicalCategory.BAD_RANDOMNESS,
    "block-other-parameters": CanonicalCategory.BAD_RANDOMNESS,
    "SWC-120": CanonicalCategory.BAD_RANDOMNESS,

    # ----- Time manipulation -----
    "timestamp": CanonicalCategory.TIME_MANIPULATION,
    "time-manipulation": CanonicalCategory.TIME_MANIPULATION,
    "block.timestamp": CanonicalCategory.TIME_MANIPULATION,
    "SWC-116": CanonicalCategory.TIME_MANIPULATION,

    # ----- DoS -----
    "msg-value-loop": CanonicalCategory.DENIAL_OF_SERVICE,
    "calls-loop": CanonicalCategory.DENIAL_OF_SERVICE,
    "gas-limit-loop": CanonicalCategory.DENIAL_OF_SERVICE,
    "dos": CanonicalCategory.DENIAL_OF_SERVICE,
    "SWC-113": CanonicalCategory.DENIAL_OF_SERVICE,
    "SWC-128": CanonicalCategory.DENIAL_OF_SERVICE,

    # ----- Front-running -----
    "front-running": CanonicalCategory.FRONT_RUNNING,
    "race-condition": CanonicalCategory.FRONT_RUNNING,
    "tod": CanonicalCategory.FRONT_RUNNING,
    "SWC-114": CanonicalCategory.FRONT_RUNNING,

    # ----- Proxy / upgrade -----
    "delegatecall-loop": CanonicalCategory.PROXY_UPGRADE,
    "delegate-call-unchecked-address": CanonicalCategory.PROXY_UPGRADE,
    "controlled-delegatecall": CanonicalCategory.PROXY_UPGRADE,
    "proxy_upgrade": CanonicalCategory.PROXY_UPGRADE,
    "storage-collision": CanonicalCategory.PROXY_UPGRADE,
    "SWC-112": CanonicalCategory.PROXY_UPGRADE,

    # ----- Centralization -----
    "centralization-risk": CanonicalCategory.CENTRALIZATION,
    "owner-privileged": CanonicalCategory.CENTRALIZATION,
}


# Substring fallbacks for when the exact type is unknown but the string
# contains a strong keyword. Ordered by specificity (first match wins).
_SUBSTRING_FALLBACKS: list = [
    ("reentran", CanonicalCategory.REENTRANCY),
    ("readonly-reentran", CanonicalCategory.REENTRANCY),
    ("flash", CanonicalCategory.FLASH_LOAN),
    ("arbitrary-send", CanonicalCategory.ACCESS_CONTROL),
    ("unprotected", CanonicalCategory.ACCESS_CONTROL),
    ("suicid", CanonicalCategory.ACCESS_CONTROL),
    ("selfdestruct", CanonicalCategory.ACCESS_CONTROL),
    ("tx-origin", CanonicalCategory.ACCESS_CONTROL),
    ("tx.origin", CanonicalCategory.ACCESS_CONTROL),
    ("delegatecall", CanonicalCategory.PROXY_UPGRADE),
    ("oracle", CanonicalCategory.ORACLE_MANIPULATION),
    ("price", CanonicalCategory.ORACLE_MANIPULATION),
    ("manipul", CanonicalCategory.ORACLE_MANIPULATION),
    ("overflow", CanonicalCategory.ARITHMETIC),
    ("underflow", CanonicalCategory.ARITHMETIC),
    ("unchecked-transfer", CanonicalCategory.UNCHECKED_CALL),
    ("unchecked-lowlevel", CanonicalCategory.UNCHECKED_CALL),
    ("unchecked-send", CanonicalCategory.UNCHECKED_CALL),
    ("unused-return", CanonicalCategory.UNCHECKED_CALL),
    ("uninitialized", CanonicalCategory.INITIALIZATION),
    ("initializer", CanonicalCategory.INITIALIZATION),
    ("ecrecover", CanonicalCategory.SIGNATURE_VERIFICATION),
    ("signature", CanonicalCategory.SIGNATURE_VERIFICATION),
    ("randomness", CanonicalCategory.BAD_RANDOMNESS),
    ("timestamp", CanonicalCategory.TIME_MANIPULATION),
    ("front-run", CanonicalCategory.FRONT_RUNNING),
    ("race-condition", CanonicalCategory.FRONT_RUNNING),
    ("centraliz", CanonicalCategory.CENTRALIZATION),
    ("owner", CanonicalCategory.ACCESS_CONTROL),  # weakest signal, last
]


def normalize_finding_type(
    finding_or_type: Any,
    *,
    default: Optional[CanonicalCategory] = None,
) -> Optional[CanonicalCategory]:
    """
    Return the canonical category for a finding (or raw type string).

    Accepts:
      - a dict representing a finding (will read .type, .check, .title, .swc_id)
      - a plain string (treated as the type)

    Returns:
      - CanonicalCategory on match
      - `default` if no mapping is found (None unless specified)
    """
    if isinstance(finding_or_type, dict):
        candidates: Iterable[str] = (
            str(finding_or_type.get("type", "")),
            str(finding_or_type.get("check", "")),
            str(finding_or_type.get("swc_id", "")),
            str(finding_or_type.get("title", "")),
        )
    else:
        candidates = (str(finding_or_type),)

    # 1) Direct exact match (case-insensitive on the raw type tokens)
    for raw in candidates:
        key = raw.strip()
        if not key:
            continue
        if key in _DIRECT_MAP:
            return _DIRECT_MAP[key]
        lower = key.lower()
        if lower in _DIRECT_MAP:
            return _DIRECT_MAP[lower]

    # 2) Substring fallbacks against the concatenated text blob
    blob = " ".join(str(c) for c in candidates).lower()
    for needle, cat in _SUBSTRING_FALLBACKS:
        if needle in blob:
            return cat

    return default


def is_category(
    finding_or_type: Any,
    category: CanonicalCategory,
) -> bool:
    """Convenience predicate — True when the finding maps to `category`."""
    return normalize_finding_type(finding_or_type) is category


__all__ = [
    "CanonicalCategory",
    "normalize_finding_type",
    "is_category",
]
