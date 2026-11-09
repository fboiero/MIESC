"""
Tests for miesc/ml/reentrancy_triage.py

Covers:
  - The REVIEW vs NOISE partition on REAL Slither descriptions extracted from the
    dogfooding corpus (committed fixture), including the Royco redemption vector.
  - Per-branch unit tests (admin setter, access-only calls, no value-state, the
    REVIEW case) on minimal faithful descriptions.
  - Named-signal reporting and the helper surfaces.

Honesty note: a "review" expected-tier means the finding is a value-moving
reentrancy candidate worth a human's review — NOT that it is exploitable. The
triage deliberately does not model nonReentrant / CEI / token hooks, so a guarded
value-op (e.g. Arcadia's liquidateAccount) is correctly REVIEW here and cleared
by the reviewer, not by this layer.
"""

from __future__ import annotations

import json
from pathlib import Path

from miesc.ml.reentrancy_triage import (
    review_tier,
    triage_reentrancy,
    triage_summary,
)

_FIXTURE = Path(__file__).parent / "fixtures" / "reentrancy_triage_corpus.json"


def _one(description: str, ftype: str = "reentrancy-no-eth"):
    return triage_reentrancy([{"type": ftype, "description": description}])[0]


# ---------------------------------------------------------------------------
# Real-corpus partition (committed fixture of verbatim Slither descriptions)
# ---------------------------------------------------------------------------


def test_real_corpus_findings_land_in_expected_tier():
    fixtures = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    assert fixtures, "fixture must not be empty"
    for fx in fixtures:
        [t] = triage_reentrancy([{"type": fx["type"], "description": fx["description"]}])
        assert t.tier == fx["expected_tier"], (
            f"{fx['target']} :: {t.function} expected {fx['expected_tier']} got {t.tier} "
            f"(signals: {t.signals})"
        )


def test_royco_redemption_vector_is_in_review():
    # The real ERC-777 redemption reentrancy sits in the redemption flow; the
    # triage must keep stRedeem in REVIEW, not drop it with the admin noise.
    fixtures = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    stredeem = next(f for f in fixtures if "RoycoKernel.stRedeem" in f["description"])
    [t] = triage_reentrancy([{"type": stredeem["type"], "description": stredeem["description"]}])
    assert t.tier == "review"
    assert "value-function" in t.signals
    assert "value-state-after" in t.signals


# ---------------------------------------------------------------------------
# Per-branch unit tests
# ---------------------------------------------------------------------------

_REVIEW_DESC = (
    "Reentrancy in Vault.redeem(uint256,address) "
    "(src/Vault.sol#10-30): External calls: "
    "- claims = IKernel(kernel()).settleRedeem(shares,receiver) (src/Vault.sol#20) "
    "State variables written after the call(s): "
    "- totalShares = totalShares - shares (src/Vault.sol#25) "
    "Vault.totalShares can be used in cross function reentrancies:"
)

_ADMIN_DESC = (
    "Reentrancy in Accountant.setBeta(uint96) (src/Accountant.sol#1-9): "
    "External calls: - IKernel(kernel()).sync() (src/Accountant.sol#5) "
    "State variables written after the call(s): - beta = newBeta (src/Accountant.sol#7)"
)

_ACCESS_ONLY_DESC = (
    "Reentrancy in Vault.claim(uint256) (src/Vault.sol#40-50): External calls: "
    "- restricted() (src/Vault.sol#41) "
    "- IAccessManager(authority()).consumeScheduledOp(caller,data) (lib/AM.sol#126) "
    "State variables written after the call(s): - totalShares = 0 (src/Vault.sol#48)"
)

_NO_VALUE_STATE_DESC = (
    "Reentrancy in Vault.redeem(uint256) (src/Vault.sol#60-70): External calls: "
    "- IKernel(kernel()).settle(shares) (src/Vault.sol#64) "
    "State variables written after the call(s): - lastCaller = msg.sender (src/Vault.sol#68)"
)


def test_value_op_with_value_state_is_review():
    t = _one(_REVIEW_DESC)
    assert t.tier == "review"
    assert set(t.signals) >= {"value-function", "non-access-external-call", "value-state-after"}


def test_admin_setter_is_noise():
    t = _one(_ADMIN_DESC)
    assert t.tier == "noise"
    assert "admin-function" in t.signals
    assert "configuration" in t.reason


def test_access_only_calls_is_noise():
    # Only access/authorization external calls -> not a real reentrancy source.
    t = _one(_ACCESS_ONLY_DESC)
    assert t.tier == "noise"
    assert "access-only-calls" in t.signals
    assert "access" in t.reason


def test_no_value_state_after_is_noise():
    t = _one(_NO_VALUE_STATE_DESC)
    assert t.tier == "noise"
    assert "value-state-after" not in t.signals


def test_non_reentrancy_findings_are_ignored():
    findings = [
        {"type": "naming-convention", "description": "Parameter _x is not in mixedCase"},
        {"type": "reentrancy-no-eth", "description": _REVIEW_DESC},
    ]
    out = triage_reentrancy(findings)
    assert len(out) == 1
    assert out[0].tier == "review"


def test_reentrancy_events_variant_is_triaged_too():
    # Partition applies to every reentrancy-* type, not only reentrancy-no-eth.
    t = _one(_ADMIN_DESC, ftype="reentrancy-events")
    assert t.tier == "noise"


def test_helpers():
    findings = [
        {"type": "reentrancy-no-eth", "description": _REVIEW_DESC},
        {"type": "reentrancy-no-eth", "description": _ADMIN_DESC},
    ]
    assert triage_summary(findings) == {"reentrancy_total": 2, "review": 1, "noise": 1}
    rev = review_tier(findings)
    assert len(rev) == 1 and rev[0].tier == "review"
