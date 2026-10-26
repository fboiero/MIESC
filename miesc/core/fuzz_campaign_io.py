"""Phase 4 — fuzzing-campaign statistics I/O for the audit report (§4.6).

Fuzzing adapters (Foundry / Echidna / Medusa) emit campaign statistics (test
counts, configured limits, property-violation counts) at the top level of their
``analyze()`` return dict, but the per-tool results entry that
``miesc.cli.utils.run_tool`` serialises only preserves the ``metadata`` dict, so
those statistics never reach ``results.json``. This module is the single source
of truth for (1) which fields are preserved, per tool, and (2) the one namespaced
key they live under inside ``metadata`` — so the §4.6 writer and reader can never
drift apart.

Design invariants:

* **Additive & inert.** Stats live under a single nested key
  (``metadata["fuzz_campaign"]``); a non-fuzzing tool gets nothing, so its entry
  is byte-identical to today. Existing ``metadata`` keys (e.g. Medusa's coverage
  block) are merged, never replaced.
* **Honest labels.** ``fuzz_runs`` (Foundry) and ``test_limit`` (Echidna/Medusa)
  are *configured* caps, not observed execution counts — the renderer must say so
  and must never present ``test_limit`` as "sequences run". ``coverage`` and
  ``gas_report`` are deliberately NOT carried (line coverage is not security
  coverage; gas is noise in a premium report).
* **A stat is not a finding.** ``property_violations`` records the count the tool
  reported; it never alters the §1/§4 finding totals or the risk score, and the
  renderer cross-references real findings by F-id instead of re-counting.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

# The single namespaced key the campaign stats live under, inside the entry's
# existing ``metadata`` dict.
FUZZ_CAMPAIGN_KEY = "fuzz_campaign"

# Explicit allow-list of the campaign fields carried per tool. The reader derives
# what it renders from these exact tuples, so the writer-emitted key set equals
# the reader-read key set by construction (this is the drift guard). ``coverage``
# and ``gas_report`` are intentionally absent.
FIELDS_BY_TOOL: Dict[str, tuple[str, ...]] = {
    "foundry": ("tests_run", "tests_passed", "tests_failed", "fuzz_runs"),
    "echidna": ("test_limit", "property_violations"),
    "medusa": ("test_limit", "property_violations"),
}

# Tools whose §4.6 campaign block this module knows how to preserve.
FUZZING_TOOLS = frozenset(FIELDS_BY_TOOL)


def _as_int(value: Any) -> Optional[int]:
    """Return ``value`` as an int when it already is a non-bool int, else ``None``."""
    if isinstance(value, bool):  # bool is an int subclass — reject it explicitly.
        return None
    if isinstance(value, int):
        return value
    return None


def collect_fuzz_campaign(tool: str, result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Extract the normalized fuzzing-campaign stats for ``tool`` from an adapter
    ``analyze()`` result, or ``None`` for a non-fuzzing tool / when no stat is present.

    Only the per-tool allow-listed fields are read, from the one place each adapter
    emits them:

    * Foundry — top-level ``tests_run`` / ``tests_passed`` / ``tests_failed`` (parsed
      from output) and ``fuzz_runs`` (the configured per-test cap).
    * Echidna — top-level ``test_limit`` (configured cap); ``property_violations`` =
      the number of findings the adapter produced (all are property/assertion
      violations).
    * Medusa — ``test_limit`` from its nested ``metadata['test_sequences']`` (the
      configured cap, despite the name); ``property_violations`` = findings count.

    Returns a dict holding exactly the subset of ``FIELDS_BY_TOOL[tool]`` that was
    present. Returns ``None`` when ``tool`` is not a fuzzer or no allow-listed stat
    could be read, so callers add nothing to ``metadata`` in that case.
    """
    key = (tool or "").lower().strip()
    if key not in FIELDS_BY_TOOL:
        return None

    stats: Dict[str, Any] = {}
    if key == "foundry":
        for field in FIELDS_BY_TOOL["foundry"]:
            val = _as_int(result.get(field))
            if val is not None:
                stats[field] = val
    else:  # echidna / medusa
        # Configured test limit: top-level for echidna, nested for medusa.
        limit = _as_int(result.get("test_limit"))
        if limit is None:
            nested = result.get("metadata")
            if isinstance(nested, dict):
                limit = _as_int(nested.get("test_sequences"))
        if limit is not None:
            stats["test_limit"] = limit
        findings = result.get("findings")
        if isinstance(findings, list):
            stats["property_violations"] = len(findings)

    if not stats:
        return None
    return stats


def read_fuzz_campaign(entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Read the campaign stats back from a per-tool results ``entry``.

    Looks ONLY at ``entry['metadata'][FUZZ_CAMPAIGN_KEY]`` — never at sibling
    ``metadata`` keys such as Medusa's ``coverage_achieved`` / ``test_sequences`` —
    so coverage can never leak into §4.6. Returns ``None`` when absent.
    """
    if not isinstance(entry, dict):
        return None
    metadata = entry.get("metadata")
    if not isinstance(metadata, dict):
        return None
    campaign = metadata.get(FUZZ_CAMPAIGN_KEY)
    if not isinstance(campaign, dict):
        return None
    return campaign
