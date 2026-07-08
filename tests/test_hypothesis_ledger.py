"""
Tests for HypothesisLedger - Explicit Agentic Memory

Covers the dedup/stable-id contract that makes agentic passes compound
instead of repeat (design §4, D4).
"""

from src.agents.hypothesis_ledger import (
    Hypothesis,
    HypothesisLedger,
    hypothesis_id,
)


# ---------------------------------------------------------------------------
# Stable id + normalization
# ---------------------------------------------------------------------------


def test_id_is_stable_and_normalizes_claim():
    h1 = Hypothesis.make("Vault", "withdraw", "reentrancy", "Missing nonReentrant guard")
    h2 = Hypothesis.make(
        "Vault", "withdraw", "reentrancy", "  missing   NONREENTRANT   guard "
    )
    # Same contract/function + whitespace/case-different claim => same id.
    assert h1.id == h2.id
    assert h1.id == hypothesis_id("Vault", "withdraw", "Missing nonReentrant guard")


def test_different_claims_get_different_ids():
    h1 = Hypothesis.make("Vault", "withdraw", "reentrancy", "Missing guard")
    h2 = Hypothesis.make("Vault", "withdraw", "arithmetic", "Overflow on total")
    assert h1.id != h2.id


def test_make_fills_defaults():
    h = Hypothesis.make("Token", "mint", "access_control", "Anyone can mint")
    assert h.status == "open"
    assert h.evidence == []
    assert h.severity is None
    assert h.id


# ---------------------------------------------------------------------------
# add / dedup
# ---------------------------------------------------------------------------


def test_add_returns_true_then_false_on_dup():
    ledger = HypothesisLedger()
    h = Hypothesis.make("Vault", "withdraw", "reentrancy", "Missing guard")
    assert ledger.add(h) is True
    # Same id again (fresh object, same fields) => dup.
    dup = Hypothesis.make("Vault", "withdraw", "reentrancy", "missing GUARD")
    assert dup.id == h.id
    assert ledger.add(dup) is False
    assert len(ledger.all()) == 1


def test_rule_out_removes_from_open_ids():
    ledger = HypothesisLedger()
    h = Hypothesis.make("Vault", "withdraw", "reentrancy", "Missing guard")
    ledger.add(h)
    assert h.id in ledger.open_ids()

    ledger.rule_out(h.id, "guard present on line 42")
    assert h.id not in ledger.open_ids()
    assert h.id in [x.id for x in ledger.ruled_out()]


def test_ruled_out_id_can_never_be_reopened_by_add():
    ledger = HypothesisLedger()
    h = Hypothesis.make("Vault", "withdraw", "reentrancy", "Missing guard")
    ledger.add(h)
    ledger.rule_out(h.id, "false positive")

    # A new add of the same id must not resurrect it.
    reopened = Hypothesis.make("Vault", "withdraw", "reentrancy", "Missing guard")
    assert ledger.add(reopened) is False
    assert h.id not in ledger.open_ids()
    # Still ruled out, not open.
    assert ledger._by_id[h.id].status == "ruled_out"


def test_confirmed_id_is_not_re_added():
    ledger = HypothesisLedger()
    h = Hypothesis.make("Token", "mint", "access_control", "Anyone can mint")
    ledger.add(h)
    ledger.confirm(h.id, "no onlyOwner modifier", "high")

    again = Hypothesis.make("Token", "mint", "access_control", "Anyone can mint")
    assert ledger.add(again) is False


# ---------------------------------------------------------------------------
# confirm / confirmed()
# ---------------------------------------------------------------------------


def test_confirm_moves_to_confirmed_with_severity_and_evidence():
    ledger = HypothesisLedger()
    h = Hypothesis.make("Token", "mint", "access_control", "Anyone can mint")
    ledger.add(h)
    assert ledger.confirmed() == []

    ledger.confirm(h.id, "no access modifier on mint()", "critical")
    confirmed = ledger.confirmed()
    assert len(confirmed) == 1
    assert confirmed[0].id == h.id
    assert confirmed[0].severity == "critical"
    assert any("no access modifier" in e for e in confirmed[0].evidence)
    # Confirmed items are no longer open.
    assert h.id not in ledger.open_ids()


# ---------------------------------------------------------------------------
# summary_for_prompt
# ---------------------------------------------------------------------------


def test_summary_renders_open_and_ruled_out():
    ledger = HypothesisLedger()
    open_h = Hypothesis.make("Vault", "withdraw", "reentrancy", "Missing guard")
    ruled_h = Hypothesis.make("Vault", "deposit", "arithmetic", "Overflow on amount")
    confirmed_h = Hypothesis.make("Token", "mint", "access_control", "Anyone can mint")
    ledger.add(open_h)
    ledger.add(ruled_h)
    ledger.add(confirmed_h)

    ledger.rule_out(ruled_h.id, "checked-arithmetic in 0.8")
    ledger.confirm(confirmed_h.id, "no modifier", "high")

    summary = ledger.summary_for_prompt()
    assert "OPEN" in summary
    assert "RULED OUT" in summary
    # Open claim present.
    assert "Missing guard" in summary
    # Ruled-out claim + its reason present.
    assert "Overflow on amount" in summary
    assert "checked-arithmetic in 0.8" in summary
    # Confirmed items are deliberately not in the "already checked" digest.
    assert "Anyone can mint" not in summary


def test_summary_when_empty():
    assert "No hypotheses" in HypothesisLedger().summary_for_prompt()
