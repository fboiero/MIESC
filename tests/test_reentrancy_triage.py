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
    annotate_results,
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
    assert triage_summary(findings) == {
        "reentrancy_total": 2,
        "review": 1,
        "guarded": 0,
        "noise": 1,
    }
    rev = review_tier(findings)
    assert len(rev) == 1 and rev[0].tier == "review"


# ---------------------------------------------------------------------------
# annotate_results — the scan-pipeline wiring (in-place, recall-safe)
# ---------------------------------------------------------------------------


def test_annotate_results_labels_in_place_and_counts():
    review = {"type": "reentrancy-no-eth", "description": _REVIEW_DESC}
    admin = {"type": "reentrancy-no-eth", "description": _ADMIN_DESC}
    other = {"type": "naming-convention", "description": "Parameter _x not mixedCase"}
    all_results = [{"findings": [review, other]}, {"findings": [admin]}]

    counts = annotate_results(all_results)

    assert counts == {"reentrancy_total": 2, "review": 1, "guarded": 0, "noise": 1}
    # Annotation is written onto the original finding dicts (in place).
    assert review["reentrancy_triage"]["tier"] == "review"
    assert "value-function" in review["reentrancy_triage"]["signals"]
    assert admin["reentrancy_triage"]["tier"] == "noise"
    assert admin["reentrancy_triage"]["reason"]
    # Non-reentrancy findings are never touched, and nothing is dropped.
    assert "reentrancy_triage" not in other
    assert len(all_results[0]["findings"]) == 2
    assert len(all_results[1]["findings"]) == 1


def test_annotate_results_handles_missing_findings_key():
    # A per-tool result without a findings list must not crash the annotation.
    assert annotate_results([{"tool": "x"}, {"findings": []}]) == {
        "reentrancy_total": 0,
        "review": 0,
        "guarded": 0,
        "noise": 0,
    }


# ---------------------------------------------------------------------------
# Guard evidence (source-read, opt-in) — demote only the narrow safe case
# ---------------------------------------------------------------------------


def _reader(mapping):
    """A source reader over an in-memory {file: text} map."""
    return lambda f: mapping.get(f)


def _finding(signature: str, file: str, start: int, end: int, *, cross_fn: bool = False):
    desc = (
        f"Reentrancy in {signature} ({file}#{start}-{end}): External calls: "
        f"- IK(k()).settle(s) ({file}#{start + 2}) "
        "State variables written after the call(s): "
        f"- totalShares = 0 ({file}#{start + 4})"
    )
    if cross_fn:
        desc += " V.totalShares can be used in cross function reentrancies:"
    return {"type": "reentrancy-no-eth", "description": desc}


# Verbatim guard preamble from the real v4lend V4Vault.liquidate (positioned at
# line 1 so the finding's line range matches this snippet).
_V4VAULT_LIQUIDATE = """function liquidate(LiquidateParams calldata params) external returns (uint256 a) {
    if (transformedTokenId != 0) {
        revert TransformNotAllowed();
    }
    if (liquidatingTokenId != 0 && liquidatingTokenId == params.tokenId) {
        revert Reentrancy();
    }
    IK(k()).settle(params);
    totalShares = 0;
}"""

# A Royco-style redemption entrypoint with no reentrancy guard at all.
_ROYCO_REDEEM = """function redeem(uint256 shares, address receiver, address controller) external {
    restricted();
    (claims, metadata) = IRoycoKernel(kernel()).stRedeem(shares, receiver, controller);
    totalShares = 0;
}"""

# A plain OpenZeppelin-guarded value op.
_OZ_WITHDRAW = """function withdraw(uint256 a) external nonReentrant {
    IK(k()).settle(a);
    totalShares = 0;
}"""


def test_custom_mutex_is_surfaced_not_demoted():
    f = _finding("V4Vault.liquidate(IVault.LiquidateParams)", "src/V4Vault.sol", 1, 9)
    [t] = triage_reentrancy([f], source_reader=_reader({"src/V4Vault.sol": _V4VAULT_LIQUIDATE}))
    assert t.guard == "custom-mutex-candidate"
    assert t.tier == "review"  # never demoted on a custom mutex
    assert "guard:custom-mutex-candidate" in t.signals
    assert "verify" in t.reason.lower()


def test_no_guard_keeps_review_and_reports_none():
    f = _finding("RoycoVaultTranche.redeem(uint256,address,address)", "src/Tranche.sol", 1, 4)
    [t] = triage_reentrancy([f], source_reader=_reader({"src/Tranche.sol": _ROYCO_REDEEM}))
    assert t.guard == "none"
    assert t.tier == "review"


def test_oz_nonreentrant_without_cross_fn_is_demoted_to_guarded():
    f = _finding("V.withdraw(uint256)", "src/V.sol", 1, 4)
    [t] = triage_reentrancy([f], source_reader=_reader({"src/V.sol": _OZ_WITHDRAW}))
    assert t.guard == "oz-nonreentrant"
    assert t.tier == "guarded"  # recognized guard, no cross-function reach -> covered


def test_oz_nonreentrant_with_cross_fn_stays_review():
    # Recall-safety: a self-guard does NOT clear a cross-function reentrancy, since
    # another writer of the shared slot may be unguarded. Must stay REVIEW.
    f = _finding("V.withdraw(uint256)", "src/V.sol", 1, 4, cross_fn=True)
    [t] = triage_reentrancy([f], source_reader=_reader({"src/V.sol": _OZ_WITHDRAW}))
    assert t.guard == "oz-nonreentrant"
    assert t.tier == "review"
    assert "cross-function reach remains" in t.reason


def test_no_source_reader_leaves_guard_unknown_and_no_signal():
    # Backward compatible: the pure (source-free) triage is unchanged.
    f = _finding("V.withdraw(uint256)", "src/V.sol", 1, 4)
    [t] = triage_reentrancy([f])
    assert t.guard == "unknown"
    assert not any(s.startswith("guard:") for s in t.signals)


def test_unreadable_source_degrades_to_unknown():
    f = _finding("V.withdraw(uint256)", "src/Missing.sol", 1, 4)
    [t] = triage_reentrancy([f], source_reader=_reader({}))  # file not in the map
    assert t.guard == "unknown"
    assert t.tier == "review"  # never demoted without evidence


def test_handles_live_markdown_description_format():
    # Regression: the live scan pipeline markdown-linkifies descriptions as
    # `Reentrancy in [C.fn(x)](file#L27-L37):` (bracketed, `L`-prefixed lines),
    # unlike the raw Slither corpus form. Both the function/signal parsing and the
    # source-read location must handle it.
    desc = (
        "Reentrancy in [V.withdraw(uint256)](src/V.sol#L1-L4):\n"
        "\tExternal calls:\n"
        "\t- [IK(k()).settle(a)](src/V.sol#L2)\n"
        "\tState variables written after the call(s):\n"
        "\t- [totalShares = 0](src/V.sol#L3)"
    )
    f = {"type": "reentrancy-no-eth", "description": desc}
    [t] = triage_reentrancy([f], source_reader=_reader({"src/V.sol": _OZ_WITHDRAW}))
    assert t.function == "V.withdraw(uint256)"  # leading '[' stripped
    assert t.guard == "oz-nonreentrant"
    assert t.tier == "guarded"


def test_live_markdown_with_cross_fn_stays_review():
    # Recall-safety on the format users actually see: the live scan keeps the
    # "cross function reentrancies" clause (verified against a real scan), so an
    # oz-nonreentrant function with cross-fn reach must NOT be demoted.
    desc = (
        "Reentrancy in [V.withdraw(uint256)](src/V.sol#L1-L4):\n"
        "\tExternal calls:\n"
        "\t- [IK(k()).settle(a)](src/V.sol#L2)\n"
        "\tState variables written after the call(s):\n"
        "\t- [totalShares = 0](src/V.sol#L3)\n"
        "\t[V.totalShares](src/V.sol#L1) can be used in\n\tcross function reentrancies:"
    )
    f = {"type": "reentrancy-no-eth", "description": desc}
    [t] = triage_reentrancy([f], source_reader=_reader({"src/V.sol": _OZ_WITHDRAW}))
    assert t.guard == "oz-nonreentrant"
    assert t.tier == "review"  # cross-fn reach blocks the demotion
    assert "cross-fn-reach" in t.signals
