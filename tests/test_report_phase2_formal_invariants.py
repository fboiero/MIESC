"""Phase 2 lock-in: formal / invariant evidence layer in the audit report.

These tests guard the two additive, honest pieces added in Phase 2:

* **Piece A** — a per-finding "Verification" field (§4.1 summary table and §5
  metadata): execution-reproduced counterexamples read "Execution-reproduced
  (Foundry)"; everything else reads "Static analysis (<tool>)". This is the
  honest replacement for PR-0's removed "Manual Review" step and changes no
  counts and no scores.
* **Piece B** — a new §4.4 "Property & Invariant Analysis" section: (a) Layer 4
  formal verification ran/not-run/#findings only, (b) execution-verified
  findings with their real evidence traces, labelled "reproduced by execution".

The non-negotiable honesty invariant: a Foundry-reproduced counterexample is
NEVER called "proven" or "formally verified" in rendered output.
"""

import json
import re
from pathlib import Path

import pytest
from click.testing import CliRunner

import miesc
from miesc.cli.commands.report import report
from miesc.llm.revert_invariant_findings import counterexample_findings

REPO_ROOT = Path(miesc.__file__).parent.parent
STATIC_SAMPLE = REPO_ROOT / "examples" / "contracts" / "results.json"
FIXTURE = REPO_ROOT / "examples" / "contracts" / "results_with_counterexample.json"

EXECUTION_LABEL = "Execution-reproduced (Foundry)"

# The synthetic executor output used to BUILD the fixture. Kept identical to
# scripts that generated examples/contracts/results_with_counterexample.json so
# the drift-guard test can prove the fixture was machine-built, not hand-written.
_SOURCE_CODE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault {
    address public owner;
    bool public paused;

    function setFeeRecipient(address who) external {
        owner = who;
    }

    function emergencyWithdraw(uint256 amount) external {
        // no pause gate
        payable(msg.sender).transfer(amount);
    }
}
"""

_EXECUTIONS = [
    {
        "promotion_state": "counterexample",
        "category": "access_control",
        "counterexamples": ["setFeeRecipient"],
        "evidence": [
            "an unauthorized caller (address(0xBEEF)) called `setFeeRecipient`: the call "
            "did not revert and wrote the contract's storage -- no access-control guard "
            "rejected it",
        ],
    },
    {
        "promotion_state": "counterexample",
        "category": "pause_toggle",
        "counterexamples": ["emergencyWithdraw"],
        "evidence": [
            "a Foundry probe called `pause` and the guarded sibling `deposit`, which "
            "succeeds in a fresh state, then reverted; in that state `emergencyWithdraw` "
            "did not revert and wrote the contract's storage -- no pause gate protects "
            "`emergencyWithdraw`",
        ],
    },
    {
        "promotion_state": "hypothesis",
        "category": "access_control",
        "counterexamples": ["setFeeRecipient"],
        "evidence": ["not promoted"],
    },
]


def _render(results_path: Path, template: str, tmp_path: Path) -> str:
    out = tmp_path / f"{template}.md"
    result = CliRunner().invoke(
        report, [str(results_path), "-t", template, "-f", "markdown", "-o", str(out)]
    )
    assert result.exit_code == 0, result.output
    return out.read_text(encoding="utf-8")


def _assert_no_overclaim(text: str) -> None:
    """Dynamic PoCs are never "proven"/"formally verified" in rendered output.

    Word-boundary matched so the legitimate "Provenance" heading and the
    "Formal Verification" layer label never trip the guard.
    """
    assert re.search(r"\bproven\b", text) is None
    assert re.search(r"formally verified", text, re.IGNORECASE) is None


# ---------------------------------------------------------------------------
# Static sample — §4.4 "Not performed", honesty, and unchanged counts.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("template", ["premium", "profesional"])
def test_static_sample_property_section_not_performed(template, tmp_path):
    if not STATIC_SAMPLE.exists():  # pragma: no cover - sample ships with the repo
        pytest.skip("bundled sample results.json not found")
    text = _render(STATIC_SAMPLE, template, tmp_path)

    # §4.4 exists and honestly reports that nothing ran.
    assert "## 4.4 Property & Invariant Analysis" in text
    assert "Not performed in this engagement." in text

    # Honesty invariants.
    assert text.count("Manual Review") == 0
    _assert_no_overclaim(text)

    # §2.3 Layer 4 must not contradict the "not performed" statement.
    assert "Layer 4: Formal Verification    [-- Not Run]" in text


@pytest.mark.parametrize("template", ["premium", "profesional"])
def test_static_sample_counts_and_score_unchanged(template, tmp_path):
    """§1 and §4 finding counts (and the risk score) are byte-identical to Phase 1."""
    if not STATIC_SAMPLE.exists():  # pragma: no cover
        pytest.skip("bundled sample results.json not found")
    text = _render(STATIC_SAMPLE, template, tmp_path)

    # Severity table and total (§1.3) — unchanged.
    assert "| **Critical** | 0 |" in text
    assert "| **High** | 8 |" in text
    assert "| **Medium** | 1 |" in text
    assert "| **Low** | 1 |" in text
    assert "| **Total** | **10** |" in text

    # Risk score (§1.3) — unchanged.
    assert "| **Overall Risk Score** | 85/100 |" in text

    # §4.1 holds exactly the 10 static findings and no injected counterexample.
    assert "| F-010 |" in text
    assert "| F-011 |" not in text

    # Every static finding is attributed to static analysis, never execution.
    assert EXECUTION_LABEL not in text
    assert "Static analysis (slither)" in text
    assert "Static analysis (aderyn)" in text


# ---------------------------------------------------------------------------
# Fixture — execution-verified findings surface with their evidence.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("template", ["premium", "profesional"])
def test_fixture_execution_verified_findings(template, tmp_path):
    assert FIXTURE.exists(), "committed fixture must exist"
    text = _render(FIXTURE, template, tmp_path)

    # §4.4.2 lists exactly the two execution-verified findings.
    assert "### 4.4.2 Execution-Verified Findings" in text
    assert "F-011. Missing access control on `setFeeRecipient`" in text
    assert "F-012. Missing pause gating on `emergencyWithdraw`" in text

    # Their real evidence traces are rendered verbatim (not invented).
    assert "no access-control guard" in text
    assert "no pause gate protects" in text

    # Execution-verified findings carry a real CVSS score, never a withheld blank.
    # A pause/DoS counterexample is High (an execution-reproduced emergency-stop
    # bypass), so its Critical-scoring vector lands within one band of the reported
    # severity and the directional guard no longer withholds it.
    assert "not scored (inconsistent with reported severity)" not in text
    f012_summary = [ln for ln in text.splitlines() if ln.startswith("| F-012 ") and "conf.)" in ln]
    assert f012_summary and "9.6" in f012_summary[0], f012_summary

    # Their Verification field is the execution label; it appears exactly twice
    # in the §4.1 summary table (one row each) plus once per §4.4.2 entry and
    # once per §5 metadata row — i.e. it is present and tied only to them.
    assert EXECUTION_LABEL in text
    # Summary table: exactly two rows carry the execution label.
    summary_rows = [
        ln for ln in text.splitlines() if ln.startswith("| F-01") and EXECUTION_LABEL in ln
    ]
    assert len(summary_rows) == 2, summary_rows
    assert any("F-011" in ln for ln in summary_rows)
    assert any("F-012" in ln for ln in summary_rows)

    # A static finding keeps a static-analysis label, never the execution one.
    # Pick the §4.1 summary row (it carries the status "conf.)" column), not the
    # §3.2 CVSS row which shares the "| F-001 " prefix.
    static_rows = [ln for ln in text.splitlines() if ln.startswith("| F-001 ") and "conf.)" in ln]
    assert static_rows and "Static analysis (slither)" in static_rows[0]
    assert EXECUTION_LABEL not in static_rows[0]

    # Honesty invariant holds on the fixture too.
    _assert_no_overclaim(text)


def test_fixture_matches_builder_output():
    """Drift guard: the fixture's execution findings equal the builder's output.

    Proves the fixture was produced by ``counterexample_findings()`` on the
    synthetic executor dict, not hand-authored — so its shape cannot silently
    drift from the real builders.
    """
    expected = counterexample_findings(
        _EXECUTIONS, _SOURCE_CODE, contract_path="VulnerableDeFi.sol"
    )
    assert len(expected) == 2  # the hypothesis entry yields no finding

    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    embedded = [
        f
        for tr in data.get("results", [])
        for f in tr.get("findings", [])
        if f.get("source") in {"revert_invariant_executor", "revert_invariant_reasoning"}
    ]

    def _key(f):
        return (f["title"], f["type"], f["severity"], f["source"], tuple(f["evidence"]))

    assert sorted(map(_key, embedded)) == sorted(map(_key, expected))


def test_hypothesis_never_becomes_a_finding():
    """Only ``promotion_state == 'counterexample'`` is promoted; hypotheses are advisory."""
    only_hypotheses = [
        {
            "promotion_state": "hypothesis",
            "category": "access_control",
            "counterexamples": ["setFeeRecipient"],
            "evidence": ["not promoted"],
        }
    ]
    assert counterexample_findings(only_hypotheses, _SOURCE_CODE, "V.sol") == []
