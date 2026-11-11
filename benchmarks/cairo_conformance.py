#!/usr/bin/env python3
"""
Cairo / Starknet pipeline-conformance check (NOT a benchmark).

The ``vulnerable/`` fixtures under ``examples/contracts/cairo/caracal_poc/`` are
**reused from Caracal's own detector test suite** (see that directory's
``NOTICE.md``). Two consequences shape what can be measured honestly:

* Caracal recall on them is true by construction — this is why ``docs/guides/
  CAIRO.md`` says not to cite detection rates for this set, and why this script
  reports **no detection rate**.
* The ``good_*`` / ``safe_*`` functions in the fixtures are Caracal's own negative
  tests, so "Caracal raises no finding there" is also by construction, not a
  precision measurement. Function-level precision is therefore **not scored** here
  (it would need an independent, non-Caracal-authored corpus — the real M2).

What this script *does* measure — all about MIESC's own reconciliation layer, not
Caracal's detection:

1. **Dedup preservation** — of the findings Caracal actually produced for a
   fixture (read from the live per-tool result record), how many survive into the
   final merged output? The Cairo scan runs ``enhance_findings`` with
   ``source_code=""``, so the context-aware FP heuristics never fire on Cairo;
   only cross-tool **dedup** can drop a finding. This surfaces cases where dedup
   collapses two distinct Caracal detectors (e.g. ``reentrancy`` and
   ``reentrancy-benign``) into one representative.
2. **Conformance** — the clean fixture yields no finding, the uncompilable fixture
   makes Caracal report an **error** (never a false "clean"; derived from
   Caracal's own status record, not from the always-present pattern adapter), and
   how many fixtures gain cross-tool corroboration of their primary detector.

Requires a working Caracal (the primary analyzer). If Caracal never runs
successfully, the script emits an ``incomplete`` record and **no numbers**.

Exploratory / supporting run — backs no paper figure.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL-3.0
"""

from __future__ import annotations

import datetime as _dt
import json
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

_REPO = Path(__file__).resolve().parent.parent
_POC = _REPO / "examples" / "contracts" / "cairo" / "caracal_poc"
_RAW_FIXTURES = _REPO / "tests" / "fixtures" / "caracal"
_RESULTS_DIR = _REPO / "benchmarks" / "results"

sys.path.insert(0, str(_REPO))

from benchmarks.evaluate_exploits import wilson_ci  # noqa: E402

# Documented inert on Cairo 2.x (docs/guides/CAIRO.md) — kept out of scoring.
_INERT_ON_CAIRO2 = {"dead-code"}


def _load_ground_truth() -> Dict[str, Any]:
    data = json.loads((_POC / "expected_findings.json").read_text())
    return data.get("fixtures", {})


def _primary_impact(fixture_basename: str, primary_detector: Optional[str]) -> Optional[str]:
    """Caracal's own ``impact`` for the fixture's **primary** detector, matched on
    the raw ``detector`` slug (these fixtures run every detector, so the max impact
    across the file would mislabel the primary). The security/quality split is
    Caracal's, not a hand-written list."""
    raw_path = _RAW_FIXTURES / f"{Path(fixture_basename).stem}.json"
    if not raw_path.is_file() or not primary_detector:
        return None
    try:
        raw = json.loads(raw_path.read_text())
    except Exception:
        return None
    items = raw if isinstance(raw, list) else raw.get("results", raw.get("findings", []))
    for it in items:
        if isinstance(it, dict) and it.get("detector") == primary_detector:
            return str(it.get("impact", "")).lower() or None
    return None


def _is_security_impact(impact: Optional[str]) -> bool:
    return impact in {"high", "medium"}


def _run_scan(target: Path) -> Dict[str, Any]:
    """Run the real ``miesc scan`` over one Cairo file through the CLI, so the full
    pipeline (dedup, corroboration, gating) runs exactly as a user's would."""
    from click.testing import CliRunner

    from miesc.cli.commands.scan import scan

    out = Path(tempfile.mktemp(suffix=".json"))
    res = CliRunner().invoke(scan, [str(target), "-o", str(out), "--quiet"])
    parsed: Dict[str, Any] = {"exit_code": res.exit_code, "findings": [], "results": []}
    if out.is_file():
        try:
            data = json.loads(out.read_text())
            parsed["findings"] = data.get("findings", [])
            parsed["results"] = data.get("results", [])
            parsed["tools"] = data.get("tools", [])
        except Exception as exc:  # noqa: BLE001
            parsed["parse_error"] = str(exc)
        finally:
            out.unlink(missing_ok=True)
    return parsed


def _caracal_record(scan_out: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The per-tool result record for Caracal (carries its own status + raw
    findings), or ``None`` if the report has no Caracal record."""
    for rec in scan_out.get("results", []):
        if isinstance(rec, dict) and rec.get("tool") == "caracal":
            return rec
    return None


def _caracal_succeeded(scan_out: Dict[str, Any]) -> bool:
    rec = _caracal_record(scan_out)
    return bool(rec) and rec.get("status") == "success"


def main() -> int:
    gt = _load_ground_truth()
    vulnerable = {k: v for k, v in gt.items() if k.startswith("vulnerable/")}

    per_fixture: List[Dict[str, Any]] = []
    caracal_ever_ran = False

    for rel, meta in sorted(vulnerable.items()):
        path = _POC / rel
        if not path.is_file():
            continue
        primary = meta.get("primary_detector")
        impact = _primary_impact(Path(rel).name, primary)
        scan_out = _run_scan(path)
        ran = _caracal_succeeded(scan_out)
        caracal_ever_ran = caracal_ever_ran or ran

        rec = _caracal_record(scan_out) or {}
        caracal_raw_slugs = {str(f.get("type", "")) for f in rec.get("findings", [])}
        merged = scan_out.get("findings", [])
        merged_slugs = {str(f.get("type", "")) for f in merged}
        primary_preserved = (primary in merged_slugs) if (primary and ran) else None
        dropped_by_dedup = sorted(caracal_raw_slugs - merged_slugs) if ran else []
        corroborated_primary = any(
            str(f.get("type", "")) == primary and f.get("cross_tool_corroborated") for f in merged
        )

        per_fixture.append(
            {
                "fixture": rel,
                "primary_detector": primary,
                "impact": impact,
                "security": _is_security_impact(impact),
                "inert_on_cairo2": primary in _INERT_ON_CAIRO2,
                "caracal_succeeded": ran,
                "primary_preserved": primary_preserved,
                "caracal_raw_detectors": sorted(caracal_raw_slugs),
                "dropped_by_dedup": dropped_by_dedup,
                "primary_corroborated": corroborated_primary,
            }
        )

    if not caracal_ever_ran:
        _emit(
            {
                "status": "incomplete",
                "reason": "Caracal did not run successfully on any fixture — no numbers emitted.",
                "caracal_available": False,
            }
        )
        return 1

    scored = [f for f in per_fixture if not f["inert_on_cairo2"] and f["caracal_succeeded"]]
    sec = [f for f in scored if f["security"]]
    quality = [f for f in scored if not f["security"]]

    def _preservation(group: List[Dict[str, Any]]) -> Dict[str, Any]:
        n = len(group)
        k = sum(1 for f in group if f["primary_preserved"])
        lo, hi = wilson_ci(k, n) if n else (0.0, 0.0)
        return {
            "preserved": k,
            "n": n,
            "rate": round(k / n, 4) if n else None,
            "wilson_ci_95": [lo, hi] if n else None,
            "missed": [f["fixture"] for f in group if not f["primary_preserved"]],
        }

    # Conformance fixtures.
    clean_path = _POC / "clean" / "counter_clean.cairo"
    clean_out = _run_scan(clean_path) if clean_path.is_file() else {}
    uncompilable_path = _POC / "error_cases" / "uncompilable.cairo"
    uncompilable_out = _run_scan(uncompilable_path) if uncompilable_path.is_file() else {}

    all_dropped = sorted({d for f in per_fixture for d in f["dropped_by_dedup"]})

    report = {
        "status": "ok",
        "kind": "pipeline_conformance",
        "not_a_benchmark": (
            "The vulnerable fixtures are Caracal's own detector tests (caracal_poc/"
            "NOTICE.md), so detection rate and function-level precision are true by "
            "construction and are NOT reported. This measures only MIESC's "
            "reconciliation layer: dedup preservation of Caracal's findings and "
            "honest handling of the clean / uncompilable fixtures."
        ),
        "generated": _dt.date.today().isoformat(),
        "caracal_version": "0.3.0-fork-adrienlacombe (Cairo 2.20.0)",
        "fixtures_total": len(per_fixture),
        "dedup_preservation_of_primary": {
            "security_impact": _preservation(sec),
            "code_quality_impact": _preservation(quality),
            "note": (
                "dead-code excluded (inert on Cairo 2.x); split by Caracal's own "
                "impact field; source_code='' on the Cairo path, so only dedup "
                "(not FP heuristics) can drop a finding."
            ),
            "detectors_dropped_by_dedup_anywhere": all_dropped,
        },
        "conformance": {
            "clean_fixture_total_findings": len(clean_out.get("findings", [])),
            "clean_is_clean": len(clean_out.get("findings", [])) == 0,
            "uncompilable_caracal_errored": (
                _caracal_record(uncompilable_out) is not None
                and not _caracal_succeeded(uncompilable_out)
            ),
            "primary_corroboration_coverage": {
                "fixtures_with_primary_corroborated": sum(
                    1 for f in per_fixture if f["primary_corroborated"]
                ),
                "n": len(per_fixture),
            },
        },
        "per_fixture": per_fixture,
    }
    _emit(report)
    return 0


def _emit(report: Dict[str, Any]) -> None:
    _RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = _dt.date.today().strftime("%Y%m%d")
    out_path = _RESULTS_DIR / f"cairo_conformance_{stamp}.json"
    out_path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    print(f"\nWritten: {out_path}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
