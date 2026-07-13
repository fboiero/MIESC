"""
MIESC CLI - Baseline Commands

Record already-known findings ("the baseline") and, on later runs, suppress
them so CI fails only on *new* findings. This is the enterprise-adoption path:
point MIESC at an existing codebase, capture the current findings once, then
gate every pull request on *newly introduced* issues only.

    miesc scan contracts/ -o results.json
    miesc baseline generate results.json          # writes .miesc-baseline.json
    # ... later, on a PR ...
    miesc scan contracts/ -o pr.json
    miesc baseline diff pr.json --fail-on-new      # exit 1 only if new findings

Author: Fernando Boiero
License: AGPL-3.0
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Iterable, List

import click

from miesc.cli.utils import error, info, success
from miesc.core.baseline import (
    DEFAULT_BASELINE_FILENAME,
    Baseline,
    diff_against_baseline,
    generate_baseline,
    load_baseline,
)

# =============================================================================
# Shared helpers
# =============================================================================


def load_findings_from_results(path: str) -> List[dict[str, Any]]:
    """Extract a flat list of finding dicts from a saved MIESC results JSON.

    Handles both the top-level ``findings`` list and the per-tool ``results``
    shape produced by ``scan`` / ``audit``.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))

    if isinstance(data, list):
        return [f for f in data if isinstance(f, dict)]

    findings = data.get("findings")
    if isinstance(findings, list) and findings:
        return [f for f in findings if isinstance(f, dict)]

    flattened: List[dict[str, Any]] = []
    for result in data.get("results", []):
        if not isinstance(result, dict):
            continue
        for finding in result.get("findings", []):
            if isinstance(finding, dict):
                finding.setdefault("tool", result.get("tool", "unknown"))
                flattened.append(finding)
    return flattened


def apply_baseline_gate(
    findings: Iterable[Any],
    baseline_path: str,
    *,
    fail_on_new: bool,
    quiet: bool = False,
) -> dict[str, list[Any]]:
    """Diff ``findings`` against the baseline at ``baseline_path``.

    Prints a one-line new/known/fixed summary and, when ``fail_on_new`` is set
    and there is at least one new finding, exits the process with status 1.

    Reused by ``scan`` and ``audit`` to gate CI on newly introduced findings.
    """
    findings = list(findings)
    try:
        baseline = load_baseline(baseline_path)
    except FileNotFoundError:
        error(f"Baseline not found: {baseline_path}")
        sys.exit(2)
    except (ValueError, json.JSONDecodeError) as exc:
        error(f"Invalid baseline file {baseline_path}: {exc}")
        sys.exit(2)

    result = diff_against_baseline(findings, baseline)
    n_new, n_known, n_fixed = (
        len(result["new"]),
        len(result["known"]),
        len(result["fixed"]),
    )

    if not quiet:
        info(
            f"Baseline: {n_new} new, {n_known} known/suppressed, "
            f"{n_fixed} fixed (baseline of {len(baseline)})"
        )

    if fail_on_new and n_new > 0:
        error(f"Baseline check failed: {n_new} new finding(s) not in baseline")
        sys.exit(1)

    return result


# =============================================================================
# Command group
# =============================================================================


@click.group()
def baseline() -> None:
    """Manage a finding baseline to suppress already-known issues in CI."""


@baseline.command("generate")
@click.argument("results", type=click.Path(exists=True))
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default=DEFAULT_BASELINE_FILENAME,
    show_default=True,
    help="Path to write the baseline file.",
)
@click.option("--quiet", "-q", is_flag=True, help="Only print the output path.")
def baseline_generate(results: str, output: str, quiet: bool) -> None:
    """Generate a baseline from a saved MIESC results JSON.

    RESULTS is a JSON report produced by ``miesc scan -o`` or ``miesc audit``.
    The baseline records a content-based fingerprint per finding so line shifts
    do not spuriously re-flag known issues.

    \b
    Examples:
        miesc scan contracts/ -o results.json
        miesc baseline generate results.json
        miesc baseline generate results.json -o .miesc-baseline.json
    """
    findings = load_findings_from_results(results)
    baseline_obj: Baseline = generate_baseline(findings)
    out_path = baseline_obj.save(output)

    if quiet:
        click.echo(str(out_path))
        return

    success(f"Baseline written to {out_path}")
    info(f"Recorded {len(baseline_obj)} unique finding fingerprint(s).")


@baseline.command("diff")
@click.argument("results", type=click.Path(exists=True))
@click.option(
    "--baseline",
    "baseline_path",
    type=click.Path(),
    default=DEFAULT_BASELINE_FILENAME,
    show_default=True,
    help="Path to the baseline file to diff against.",
)
@click.option(
    "--fail-on-new",
    is_flag=True,
    help="Exit non-zero if any finding is not present in the baseline (CI gate).",
)
@click.option("--quiet", "-q", is_flag=True, help="Suppress per-finding detail.")
def baseline_diff(results: str, baseline_path: str, fail_on_new: bool, quiet: bool) -> None:
    """Diff current results against a baseline: new / known / fixed.

    RESULTS is a JSON report produced by ``miesc scan -o`` or ``miesc audit``.

    \b
    Exit codes:
        0 - No new findings (or --fail-on-new not set)
        1 - New findings found and --fail-on-new set
        2 - Baseline file missing or invalid
    """
    findings = load_findings_from_results(results)
    result = apply_baseline_gate(findings, baseline_path, fail_on_new=fail_on_new, quiet=True)

    n_new = len(result["new"])
    n_known = len(result["known"])
    n_fixed = len(result["fixed"])

    info(f"New:   {n_new}")
    info(f"Known: {n_known} (suppressed)")
    info(f"Fixed: {n_fixed}")

    if not quiet and n_new:
        info("")
        info("New findings:")
        for finding in result["new"]:
            rule = (
                finding.get("type") or finding.get("rule_id") or finding.get("title") or "unknown"
            )
            sev = str(finding.get("severity", "")).upper()
            loc = finding.get("location")
            file = ""
            if isinstance(loc, dict):
                file = loc.get("file", "")
            file = file or finding.get("file", "") or finding.get("file_path", "")
            info(f"  [{sev}] {rule} — {file}")

    if fail_on_new and n_new > 0:
        error(f"Baseline check failed: {n_new} new finding(s) not in baseline")
        sys.exit(1)
