"""Phase 3 lock-in: §4.5 "Trust Model & Privileged Roles" in the audit report.

Phase 3 adds an additive, honest trust-model section with two blocks:

* **(a) Privileged roles identified** — the deterministic authority inventory
  (``miesc.llm.privileged_governance_lifecycle.mine_privileged_governance_lifecycle``)
  persisted by the agentic audit writer and read back by the report, rendered as an
  **advisory static model** with source anchors. Absent on the default path, where it
  reads "not extracted".
* **(b) Trust-relevant findings** — existing findings whose canonical category is
  access control / centralization / proxy-upgrade, cross-referenced by F-id. This is
  the findings-based floor that works even for directory audits.

Non-negotiable honesty invariants (the governance analog of Phase 2's
"execution != formal proof"):

* A role is NOT a finding: the inventory changes no §1/§4 count and no risk score.
* Neutral, non-custody language: the inventory is a trust *assumption*, and the section
  never claims roles are "verified"/"confirmed"/"exhaustive" or that key custody was
  established.

The writer (``hoist_advisory_plans``) and the reader (``read_governance_plans``) share
one module so the persisted key cannot drift from the consumed key.
"""

import json
import re
from pathlib import Path

import pytest
from click.testing import CliRunner

import miesc
from miesc.agents.deep_audit_agent import DeepAuditAgent, DeepAuditConfig
from miesc.cli.commands.report import report
from miesc.core.advisory_plans_io import (
    ADVISORY_PLANS_KEY,
    hoist_advisory_plans,
    read_governance_plans,
)
from miesc.llm.privileged_governance_lifecycle import mine_privileged_governance_lifecycle

REPO_ROOT = Path(miesc.__file__).parent.parent
STATIC_SAMPLE = REPO_ROOT / "examples" / "contracts" / "results.json"
FIXTURE = REPO_ROOT / "examples" / "contracts" / "results_with_governance.json"

# The Solidity source the committed fixture was machine-built from (Ownable + an
# AccessControl role + a pause + an upgrade path). Kept identical to the generator so
# the drift-guard test can prove the fixture's authority graph was mined, not
# hand-authored.
_FIXTURE_FILE_NAME = "Governed.sol"
_SOURCE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Governed is Ownable, AccessControl {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    uint256 public config;
    bool public paused;

    function pause() external onlyRole(PAUSER_ROLE) {
        paused = true;
    }

    function setConfig(uint256 x) external onlyOwner {
        config = x;
    }

    function grantMinter(address who) external onlyOwner {
        grantRole(MINTER_ROLE, who);
    }

    function revokeMinter(address who) external onlyRole(DEFAULT_ADMIN_ROLE) {
        revokeRole(MINTER_ROLE, who);
    }

    function upgradeTo(address impl) external onlyUpgrader {
        config = uint256(uint160(impl));
    }
}
"""

# Banned words for the inventory (word-boundary), the governance analog of Phase 2's
# "proven"/"formally verified" ban. "verify" is allowed ("did not verify"); "verified"
# is not.
_BANNED_WORDS = ["verified", "confirmed", "exhaustive", "proven"]
_BANNED_PHRASES = ["formally verified", "all privileged functions"]


def _render(results_path: Path, template: str, tmp_path: Path) -> str:
    out = tmp_path / f"{template}.md"
    result = CliRunner().invoke(
        report, [str(results_path), "-t", template, "-f", "markdown", "-o", str(out)]
    )
    assert result.exit_code == 0, result.output
    return out.read_text(encoding="utf-8")


def _section_45(text: str) -> str:
    """Return just the §4.5 block, so banned-word grepping never sees §4.4's
    legitimate 'Execution-Verified' / 'Formal Verification' labels."""
    start = text.index("## 4.5 Trust Model & Privileged Roles")
    tail = text[start:]
    end = tail.find("# 5. Detailed Findings")
    return tail[:end] if end != -1 else tail


# ---------------------------------------------------------------------------
# Writer <-> reader contract (no drift between persisted key and consumed key).
# ---------------------------------------------------------------------------


def test_round_trip_writer_key_is_reader_key():
    """What ``hoist_advisory_plans`` emits is exactly what ``read_governance_plans``
    reads back — they share the key, so they cannot drift apart."""
    phase = DeepAuditAgent(
        config=DeepAuditConfig(enable_llm=False, enable_rag=False)
    )._extract_advisory_plans(_SOURCE, _FIXTURE_FILE_NAME)
    block = hoist_advisory_plans({"phases": {"advisory_plans": phase}})
    assert block is not None

    # The writer persists at the shared top-level key; the reader consumes it.
    persisted = {ADVISORY_PLANS_KEY: block}
    plans = read_governance_plans(persisted)
    assert plans is not None and len(plans) == 1
    assert plans[0]["authority_graph"]["actors"]


def test_writer_omits_key_when_phase_absent():
    """Default path (no advisory-plan phase) emits nothing — reader reports 'absent'."""
    assert hoist_advisory_plans({"phases": {}}) is None
    assert hoist_advisory_plans({}) is None
    # 'absent' (None) is distinct from 'ran but empty' ([]).
    assert read_governance_plans({"results": []}) is None
    assert read_governance_plans({ADVISORY_PLANS_KEY: {"capabilities": {}}}) == []


# ---------------------------------------------------------------------------
# Fixture drift guard — the authority graph is mined, not hand-authored.
# ---------------------------------------------------------------------------


def test_fixture_authority_graph_matches_live_miner():
    """The committed fixture's authority graph equals a fresh mine of the same
    source + filename — proof it was machine-built and stays in sync."""
    assert FIXTURE.exists(), "committed fixture must exist"
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))

    plans = read_governance_plans(data)
    assert plans, "fixture must carry governance plans at the shared key"

    expected = [
        p.to_dict() for p in mine_privileged_governance_lifecycle(_SOURCE, _FIXTURE_FILE_NAME)
    ]
    fixture_graphs = [p["authority_graph"] for p in plans]
    expected_graphs = [p["authority_graph"] for p in expected]
    assert fixture_graphs == expected_graphs


# ---------------------------------------------------------------------------
# Static sample — (a) "not extracted", (b) lists the trust-relevant F-ids.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("template", ["premium", "profesional"])
def test_static_sample_section_present_and_floor(template, tmp_path):
    if not STATIC_SAMPLE.exists():  # pragma: no cover - sample ships with the repo
        pytest.skip("bundled sample results.json not found")
    text = _render(STATIC_SAMPLE, template, tmp_path)
    section = _section_45(text)

    assert "## 4.5 Trust Model & Privileged Roles" in text
    # (a) No inventory was extracted on the default (non-agentic) path.
    assert "Role inventory not extracted in this engagement." in section
    # (b) The findings-based floor lists exactly the trust-relevant findings.
    for fid in ("F-002", "F-003", "F-006", "F-007", "F-010"):
        assert re.search(rf"\| {fid} \|", section), f"{fid} missing from §4.5.2"
    # A non-trust finding (e.g. weak-prng F-001) is NOT in the trust cross-reference.
    assert not re.search(r"\| F-001 \|", section)


@pytest.mark.parametrize("template", ["premium", "profesional"])
def test_static_sample_counts_and_score_unchanged(template, tmp_path):
    """§1.3 severity table and the risk score are byte-identical to Phase 2."""
    if not STATIC_SAMPLE.exists():  # pragma: no cover
        pytest.skip("bundled sample results.json not found")
    text = _render(STATIC_SAMPLE, template, tmp_path)
    assert "| **Critical** | 0 |" in text
    assert "| **High** | 8 |" in text
    assert "| **Medium** | 1 |" in text
    assert "| **Low** | 1 |" in text
    assert "| **Total** | **10** |" in text
    assert "| **Overall Risk Score** | 85/100 |" in text
    assert "Manual Review" not in text


# ---------------------------------------------------------------------------
# Fixture — N roles with anchors + disclaimers, and role != finding.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("template", ["premium", "profesional"])
def test_fixture_roles_rendered_with_anchors_and_disclaimers(template, tmp_path):
    text = _render(FIXTURE, template, tmp_path)
    section = _section_45(text)

    # (a) actors + roles rendered as an advisory inventory.
    assert "Identified by static extraction (advisory)." in section
    assert "`owner`" in section and "`upgrader`" in section
    assert "`MINTER_ROLE`" in section and "`PAUSER_ROLE`" in section
    assert "`DEFAULT_ADMIN_ROLE`" in section
    # Source anchors present (actor owner was seen on two lines).
    assert "Governed.sol:15" in section and "Governed.sol:19" in section
    assert "Governed.sol:27" in section
    # Grant/revoke functions surfaced.
    assert "grantMinter" in section and "revokeMinter" in section

    # Mandatory disclaimers (fragments chosen to sit within one wrapped line).
    assert "did not verify key custody or off-chain governance" in section
    assert "identified by static extraction" in section
    assert "inherited, proxied, or assembly-level authority" in section

    # (b) trust-relevant findings cross-referenced; the reentrancy finding is excluded.
    assert re.search(r"\| F-001 \|", section)  # centralization
    assert re.search(r"\| F-002 \|", section)  # access_control
    assert re.search(r"\| F-003 \|", section)  # proxy_upgrade
    assert "Reentrancy in withdraw" not in section


@pytest.mark.parametrize("template", ["premium", "profesional"])
def test_fixture_section_has_no_banned_overclaim(template, tmp_path):
    text = _render(FIXTURE, template, tmp_path)
    section = _section_45(text)
    for word in _BANNED_WORDS:
        assert re.search(rf"\b{word}\b", section, re.IGNORECASE) is None, word
    for phrase in _BANNED_PHRASES:
        assert phrase.lower() not in section.lower(), phrase


def test_fixture_inventory_does_not_change_counts_or_score(tmp_path):
    """Role != finding: deleting the inventory key changes no count and no score."""
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    with_key = tmp_path / "with_key.json"
    without_key = tmp_path / "without_key.json"
    with_key.write_text(json.dumps(data), encoding="utf-8")
    data.pop(ADVISORY_PLANS_KEY)
    without_key.write_text(json.dumps(data), encoding="utf-8")

    def _digest(path: Path) -> list[str]:
        text = _render(path, "premium", tmp_path)
        return [
            ln
            for ln in text.splitlines()
            if "Overall Risk Score" in ln
            or re.match(r"\| \*\*(Critical|High|Medium|Low|Total)\*\* \|", ln)
        ]

    assert _digest(with_key) == _digest(without_key)
