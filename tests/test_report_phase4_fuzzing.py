"""Phase 4 lock-in: §4.6 "Dynamic Testing & Fuzzing" in the audit report.

Phase 4 preserves fuzzing-campaign statistics (which the per-tool results schema
otherwise drops — it carries only ``metadata``) and renders them in an additive,
honest §4.6 with a tool + scope for each campaign.

Non-negotiable honesty invariants:

* **A stat is not a finding.** The campaign numbers change no §1/§4 count and no risk
  score; fuzzer findings are already counted in §1/§4 and are only cross-referenced
  here by F-id, never re-counted.
* **No overclaim.** ``test_limit`` / ``fuzz_runs`` are *configured* caps, never
  "sequences run"/"executed". Coverage and gas are never surfaced (CUTS). The banned
  words "proven"/"formally verified"/"exhaustive"/"verified"/"confirmed" never appear
  in §4.6, and the honest empty state ("not performed") is the expected default.

The writer (``collect_fuzz_campaign``) and the reader (``read_fuzz_campaign``) share one
module and one allow-list, so the persisted key set cannot drift from the consumed one.
"""

import json
import re
from pathlib import Path
from unittest import mock

import pytest
from click.testing import CliRunner

import miesc
from miesc.cli.commands.report import report
from miesc.cli.utils import run_tool
from miesc.core.fuzz_campaign_io import (
    FIELDS_BY_TOOL,
    FUZZ_CAMPAIGN_KEY,
    collect_fuzz_campaign,
    read_fuzz_campaign,
)
from miesc.core.tool_protocol import ToolStatus

REPO_ROOT = Path(miesc.__file__).parent.parent
STATIC_SAMPLE = REPO_ROOT / "examples" / "contracts" / "results.json"
COUNTEREXAMPLE_SAMPLE = REPO_ROOT / "examples" / "contracts" / "results_with_counterexample.json"
FIXTURE = REPO_ROOT / "examples" / "contracts" / "results_with_fuzzing.json"

# A forge --json payload in the schema the Foundry adapter parses, reflecting a real
# 2-test / 1-failing fuzz campaign (testFuzz_SetNumber passes, testFuzz_NeverLarge
# fails) on the committed forge project under examples/contracts/fuzzing/. This is the
# SAME payload the committed fixture was machine-built from; the adapter's real parser
# derives the stats and the finding — nothing is hand-authored.
_FORGE_JSON_STDOUT = json.dumps(
    {
        "test_results": {
            "CounterTest": {
                "testFuzz_SetNumber(uint256)": {"success": True, "reason": None},
                "testFuzz_NeverLarge(uint256)": {
                    "success": False,
                    "reason": "number too large",
                    "counterexample": {"args": "271273108981186046160286067643997144095967533870"},
                    "decoded_logs": [],
                },
            }
        }
    }
)

# forge 1.3.5's ACTUAL ``--json`` layout: ``test_results`` is nested under the
# contract-path key and uses ``status: "Failure"`` strings, which the adapter's parser
# (expecting top-level ``test_results`` with ``success`` booleans) does not match. So a
# LIVE ``miesc audit single foundry`` today yields tests_run=0 and no findings — the
# production path §4.6 must handle honestly. Captured verbatim from a real forge run.
_FORGE_JSON_NESTED = json.dumps(
    {
        "test/Counter.t.sol:CounterTest": {
            "duration": "6ms",
            "test_results": {
                "testFuzz_NeverLarge(uint256)": {"status": "Failure", "reason": "number too large"},
                "testFuzz_SetNumber(uint256)": {"status": "Success", "reason": None},
            },
            "warnings": [],
        }
    }
)

_BANNED_WORDS = ["proven", "exhaustive", "verified", "confirmed"]
_BANNED_PHRASES = ["formally verified"]
# CUTS — never in §4.6, even when the adapter carries them.
_FORBIDDEN_METRICS = ["coverage", "covered", "gas"]


# ---------------------------------------------------------------------------
# Helpers: serialise an adapter result through the REAL run_tool CLI path.
# ---------------------------------------------------------------------------


def _serialize_through_run_tool(tool: str, analyze_return: dict) -> dict:
    """Run the real ``run_tool`` with a fake adapter returning ``analyze_return``.

    Exercises the exact serialisation point the CLI audit paths use, so what lands in
    ``metadata`` is what a live ``miesc audit`` would persist — only adapter loading and
    availability are stubbed."""

    class _FakeAdapter:
        def analyze(self, contract, timeout=0, **kwargs):
            return dict(analyze_return)

    with (
        mock.patch("miesc.cli.utils.AdapterLoader.get_adapter", return_value=_FakeAdapter()),
        mock.patch(
            "miesc.cli.utils.AdapterLoader.get_availability", return_value=ToolStatus.AVAILABLE
        ),
        mock.patch("miesc.core.tool_protocol.applies_to", return_value=True),
    ):
        return run_tool(tool, "/contracts/C.sol", timeout=120)


def _build_foundry_entry(stdout: str = _FORGE_JSON_STDOUT) -> dict:
    """Serialise a Foundry campaign through the REAL adapter parser + REAL run_tool,
    with only ``subprocess.run`` / availability mocked (the fixture's build path)."""
    import subprocess

    completed = subprocess.CompletedProcess(
        args=["forge", "test"], returncode=1, stdout=stdout, stderr=""
    )
    with (
        mock.patch("miesc.adapters.foundry_adapter.subprocess.run", return_value=completed),
        mock.patch(
            "miesc.adapters.foundry_adapter.FoundryAdapter.is_available",
            return_value=ToolStatus.AVAILABLE,
        ),
        mock.patch(
            "miesc.cli.utils.AdapterLoader.get_availability", return_value=ToolStatus.AVAILABLE
        ),
    ):
        return run_tool("foundry", "/contracts/Counter.sol", timeout=120)


def _render(results_path: Path, template: str, tmp_path: Path) -> str:
    out = tmp_path / f"{template}.md"
    result = CliRunner().invoke(
        report, [str(results_path), "-t", template, "-f", "markdown", "-o", str(out)]
    )
    assert result.exit_code == 0, result.output
    return out.read_text(encoding="utf-8")


def _render_doc(doc: dict, template: str, tmp_path: Path) -> str:
    path = tmp_path / "results.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return _render(path, template, tmp_path)


def _section_46(text: str) -> str:
    """Just the §4.6 block, so banned-word grepping never sees §4.4's legitimate
    'Execution-Verified' / 'Formal Verification' labels."""
    start = text.index("## 4.6 Dynamic Testing & Fuzzing")
    tail = text[start:]
    end = tail.find("# 5. Detailed Findings")
    return tail[:end] if end != -1 else tail


# ---------------------------------------------------------------------------
# Writer <-> reader contract (no drift between persisted key and consumed key).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool", sorted(FIELDS_BY_TOOL))
def test_collected_keys_are_within_allow_list(tool):
    """Whatever ``collect_fuzz_campaign`` emits is a subset of ``FIELDS_BY_TOOL[tool]``
    — the single source of truth the reader also uses, so they cannot drift."""
    sample = {
        "foundry": {"tests_run": 3, "tests_passed": 2, "tests_failed": 1, "fuzz_runs": 256},
        "echidna": {"test_limit": 50000, "findings": [{"x": 1}, {"x": 2}]},
        "medusa": {"metadata": {"test_sequences": 10000}, "findings": [{"x": 1}]},
    }[tool]
    campaign = collect_fuzz_campaign(tool, sample)
    assert campaign is not None
    assert set(campaign) <= set(FIELDS_BY_TOOL[tool])


def test_round_trip_writer_key_is_reader_key():
    """What the writer puts under ``metadata[KEY]`` is exactly what the reader reads."""
    entry = _serialize_through_run_tool(
        "echidna", {"tool": "echidna", "status": "success", "findings": [{}, {}], "test_limit": 42}
    )
    campaign = read_fuzz_campaign(entry)
    assert campaign == {"test_limit": 42, "property_violations": 2}


def test_collect_none_for_non_fuzzing_tool():
    assert collect_fuzz_campaign("slither", {"findings": [{}], "metadata": {}}) is None
    assert read_fuzz_campaign({"tool": "slither", "metadata": {}}) is None


# ---------------------------------------------------------------------------
# Writer: fuzz stats land in metadata; non-fuzzing entry is unchanged; medusa
# merges (never replaces) its pre-existing metadata.
# ---------------------------------------------------------------------------


def test_writer_lands_foundry_stats_in_metadata():
    entry = _build_foundry_entry()
    assert entry["tool"] == "foundry"
    assert entry["metadata"][FUZZ_CAMPAIGN_KEY] == {
        "tests_run": 2,
        "tests_passed": 1,
        "tests_failed": 1,
        "fuzz_runs": 256,
    }
    # The real adapter parser produced the failing-test finding (not hand-authored).
    assert any(f.get("type") == "test_failure" for f in entry["findings"])


def test_writer_inert_for_non_fuzzing_tool():
    """A slither entry is byte-identical to today: empty metadata, no fuzz key."""
    entry = _serialize_through_run_tool(
        "slither", {"tool": "slither", "status": "success", "findings": [], "metadata": {}}
    )
    assert entry["metadata"] == {}
    assert FUZZ_CAMPAIGN_KEY not in entry["metadata"]


def test_writer_merges_medusa_metadata_without_replacing():
    """Medusa already ships a ``metadata`` dict; the writer MERGES the campaign key and
    preserves the pre-existing keys (and never promotes coverage into the campaign)."""
    entry = _serialize_through_run_tool(
        "medusa",
        {
            "tool": "medusa",
            "status": "success",
            "findings": [{"x": 1}],
            "metadata": {
                "test_sequences": 10000,
                "coverage_achieved": 42,
                "contract_analyzed": "C.sol",
            },
        },
    )
    md = entry["metadata"]
    # Pre-existing keys preserved.
    assert md["test_sequences"] == 10000
    assert md["coverage_achieved"] == 42
    assert md["contract_analyzed"] == "C.sol"
    # Campaign namespaced under one key, with only the allow-listed fields.
    assert md[FUZZ_CAMPAIGN_KEY] == {"test_limit": 10000, "property_violations": 1}


# ---------------------------------------------------------------------------
# Fixture drift guard — the committed fixture is machine-built and stays in sync.
# ---------------------------------------------------------------------------


def test_fixture_is_machine_built_and_in_sync():
    assert FIXTURE.exists(), "committed fixture must exist"
    doc = json.loads(FIXTURE.read_text(encoding="utf-8"))
    entry = doc["results"][0]
    fresh = _build_foundry_entry()
    assert entry["metadata"][FUZZ_CAMPAIGN_KEY] == fresh["metadata"][FUZZ_CAMPAIGN_KEY]
    # The fixture's campaign carries exactly the Foundry allow-list, all ints.
    campaign = entry["metadata"][FUZZ_CAMPAIGN_KEY]
    assert set(campaign) == set(FIELDS_BY_TOOL["foundry"])
    assert all(isinstance(v, int) for v in campaign.values())


# ---------------------------------------------------------------------------
# Reader — three honest states, each tied to the §2.3 Layer-2 source of truth.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("template", ["premium", "profesional"])
def test_static_sample_says_not_performed(template, tmp_path):
    if not STATIC_SAMPLE.exists():  # pragma: no cover - sample ships with the repo
        pytest.skip("bundled sample results.json not found")
    section = _section_46(_render(STATIC_SAMPLE, template, tmp_path))
    assert "No dynamic or fuzzing testing was performed in this engagement." in section
    # Names the tools that would supply this layer.
    assert "Foundry" in section and "Echidna" in section and "Medusa" in section


@pytest.mark.parametrize("template", ["premium", "profesional"])
def test_counterexample_sample_ran_without_campaign_stats(template, tmp_path):
    """A Layer-2 tool ran (revert-invariant execution) but recorded no campaign stats:
    §4.6 must say so and point at §4.4 — never contradict it with 'not performed'."""
    if not COUNTEREXAMPLE_SAMPLE.exists():  # pragma: no cover
        pytest.skip("bundled counterexample sample not found")
    # Collapse source line wrapping so fragment checks are newline-insensitive.
    section = " ".join(_section_46(_render(COUNTEREXAMPLE_SAMPLE, template, tmp_path)).split())
    assert "Dynamic-testing tooling ran in this engagement" in section
    assert "recorded no fuzzing-campaign statistics" in section
    assert "§4.4" in section
    assert "No dynamic or fuzzing testing was performed" not in section


@pytest.mark.parametrize("template", ["premium", "profesional"])
def test_live_forge_json_unparsed_renders_honestly(template, tmp_path):
    """The production path today: forge 1.3.5's nested ``--json`` doesn't match the
    adapter parser, so tests_run=0. §4.6 must say the statistics could not be parsed —
    never print a fabricated "0 tests (0 passed / 0 failed)"."""
    entry = _build_foundry_entry(stdout=_FORGE_JSON_NESTED)
    campaign = entry["metadata"][FUZZ_CAMPAIGN_KEY]
    assert campaign["tests_run"] == 0 and campaign["fuzz_runs"] == 256
    doc = {"results": [entry], "summary": {}, "version": "t"}
    section = _section_46(_render_doc(doc, template, tmp_path))
    assert "campaign statistics could not be parsed from the tool output" in section
    assert "0 tests (0 passed / 0 failed)" not in section


@pytest.mark.parametrize("template", ["premium", "profesional"])
def test_fixture_renders_stats_with_tool_and_scope(template, tmp_path):
    section = _section_46(_render(FIXTURE, template, tmp_path))
    assert "Foundry test suite:" in section
    assert "2 tests (1 passed / 1 failed)" in section
    assert "configured 256 fuzz runs per test" in section
    # Cross-referenced by F-id, not re-counted.
    assert re.search(r"F-001", section)


def test_fixture_crossref_matches_real_fuzzer_findings(tmp_path):
    """The F-ids §4.6 lists equal the findings actually attributed to Foundry — the
    cross-reference is a view over existing findings, not a new count."""
    doc = json.loads(FIXTURE.read_text(encoding="utf-8"))
    foundry_findings = [
        f for e in doc["results"] for f in e.get("findings", []) if e.get("tool") == "foundry"
    ]
    section = _section_46(_render(FIXTURE, "premium", tmp_path))
    fids = re.findall(r"F-\d{3}", section)
    assert len(set(fids)) == len(foundry_findings) == 1


@pytest.mark.parametrize("template", ["premium", "profesional"])
def test_section_46_has_no_banned_overclaim(template, tmp_path):
    for sample in (STATIC_SAMPLE, COUNTEREXAMPLE_SAMPLE, FIXTURE):
        if not sample.exists():  # pragma: no cover
            continue
        section = _section_46(_render(sample, template, tmp_path))
        for word in _BANNED_WORDS:
            assert re.search(rf"\b{word}\b", section, re.IGNORECASE) is None, (word, sample.name)
        for phrase in _BANNED_PHRASES:
            assert phrase.lower() not in section.lower(), (phrase, sample.name)


# ---------------------------------------------------------------------------
# CUTS — coverage % and gas are overclaims/noise, never surfaced in §4.6.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("template", ["premium", "profesional"])
def test_coverage_and_gas_never_rendered(template, tmp_path):
    """Even when the adapter carries coverage / gas, §4.6 shows the configured limit and
    NOT coverage/gas (word-boundary, zero occurrences)."""
    medusa_entry = _serialize_through_run_tool(
        "medusa",
        {
            "tool": "medusa",
            "status": "success",
            "findings": [{"x": 1}, {"x": 2}],
            "metadata": {"test_sequences": 10000, "coverage_achieved": 88},
        },
    )
    foundry_entry = _build_foundry_entry()
    foundry_entry["findings"] = []  # drop findings; keep the gas-bearing stats path
    doc = {"results": [medusa_entry, foundry_entry], "summary": {}, "version": "t"}
    section = _section_46(_render_doc(doc, template, tmp_path))
    assert "configured test limit 10000" in section
    for metric in _FORBIDDEN_METRICS:
        assert re.search(rf"\b{metric}\b", section, re.IGNORECASE) is None, metric
    # The limit is framed as a configured cap, never as sequences actually executed.
    assert "a cap, not the number of sequences run" in section
    assert "sequences executed" not in section.lower()
    assert "property violations reported by the tool" in section


# ---------------------------------------------------------------------------
# A stat is not a finding — counts and risk score are unaffected.
# ---------------------------------------------------------------------------


def test_static_sample_counts_and_score_unchanged(tmp_path):
    """§1.3 severity table and risk score are byte-identical to Phase 3 locked values,
    and 'Manual Review' stays absent — §4.6 is additive only."""
    if not STATIC_SAMPLE.exists():  # pragma: no cover
        pytest.skip("bundled sample results.json not found")
    text = _render(STATIC_SAMPLE, "premium", tmp_path)
    assert "| **Critical** | 0 |" in text
    assert "| **High** | 8 |" in text
    assert "| **Medium** | 1 |" in text
    assert "| **Low** | 1 |" in text
    assert "| **Total** | **10** |" in text
    assert "| **Overall Risk Score** | 85/100 |" in text
    assert "Manual Review" not in text


def test_campaign_stat_removal_does_not_change_counts_or_score(tmp_path):
    """Stat != finding: deleting ``metadata[fuzz_campaign]`` changes no count, no score
    (only the §4.6 stat line)."""
    doc = json.loads(FIXTURE.read_text(encoding="utf-8"))
    without = json.loads(json.dumps(doc))
    without["results"][0]["metadata"].pop(FUZZ_CAMPAIGN_KEY)

    def _digest(d: dict) -> list[str]:
        text = _render_doc(d, "premium", tmp_path)
        return [
            ln
            for ln in text.splitlines()
            if "Overall Risk Score" in ln
            or re.match(r"\| \*\*(Critical|High|Medium|Low|Total)\*\* \|", ln)
        ]

    assert _digest(doc) == _digest(without)
