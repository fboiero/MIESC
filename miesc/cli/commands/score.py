"""
MIESC CLI - Score Command

Turn a scan/audit's findings into a single composite security score (0-100 and an
A-F grade) plus an optional shields.io-style badge, so a project can display and
CI-gate its security posture at a glance.

Author: Fernando Boiero
License: AGPL-3.0
"""

import base64
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

import click

from miesc.cli.utils import (
    RICH_AVAILABLE,
    console,
    error,
    info,
    success,
)
from miesc.core.confidence import filter_by_min_confidence
from miesc.core.scoring import (
    SecurityScore,
    badge_endpoint,
    badge_svg,
    compute_score,
    extract_findings,
)

# =============================================================================
# Score Command
# =============================================================================


@click.command()
@click.argument("input_path", type=click.Path(exists=True), default=".")
@click.option(
    "--badge",
    type=click.Choice(["svg", "json", "markdown"]),
    default=None,
    help="Emit a badge instead of the human summary: svg=self-contained SVG, "
    "json=shields.io endpoint JSON, markdown=an embeddable ![...] snippet.",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Write the badge (with --badge) or the JSON score result to this file.",
)
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Print the machine-readable score result (JSON) to stdout.",
)
@click.option(
    "--fail-under",
    type=int,
    default=0,
    help="CI gate: exit 1 if the computed score is below this value (default 0, never fails).",
)
@click.option(
    "--min-confidence",
    "min_confidence",
    type=float,
    default=0.0,
    help="Drop findings whose calibrated confidence is below this threshold (0.0-1.0) "
    "before scoring, so low-confidence noise does not drag the score down. Findings "
    "without a confidence score are always kept. Default 0.0 keeps everything.",
)
def score(
    input_path: str,
    badge: str | None,
    output: str | None,
    as_json: bool,
    fail_under: int,
    min_confidence: float,
) -> None:
    """Composite security score (0-100 / A-F) and badge for a scan's findings.

    INPUT_PATH may be:

    \b
      - a MIESC results JSON (from 'miesc scan -o report.json'): scored directly;
      - a .sol file or a directory: scanned first, then scored.

    \b
    Examples:
      miesc score report.json
      miesc score report.json --json
      miesc score report.json --badge svg -o security.svg
      miesc score report.json --badge markdown
      miesc score contracts/ --fail-under 70          # CI gate
      miesc score report.json --min-confidence 0.4     # drop low-confidence noise
    """
    results = _load_results(input_path)
    findings = extract_findings(results)

    if min_confidence and min_confidence > 0.0:
        findings, dropped = filter_by_min_confidence(findings, min_confidence)
        if dropped and not as_json and badge is None:
            info(f"min-confidence {min_confidence}: dropped {dropped} low-confidence finding(s)")

    result = compute_score(findings)

    # ------------------------------------------------------------------ badge
    if badge is not None:
        payload = _render_badge(badge, result)
        if output:
            Path(output).write_text(payload, encoding="utf-8")
            success(f"Badge written to {output}")
        else:
            click.echo(payload)
        _apply_gate(result, fail_under)
        return

    # -------------------------------------------------------------- JSON result
    if as_json:
        payload = json.dumps(result.to_dict(), indent=2)
        if output:
            Path(output).write_text(payload + "\n", encoding="utf-8")
        click.echo(payload)
        _apply_gate(result, fail_under)
        return

    # ---------------------------------------------------------- human summary
    _print_human(result)
    if output:
        Path(output).write_text(json.dumps(result.to_dict(), indent=2) + "\n", encoding="utf-8")
        success(f"Score written to {output}")

    _apply_gate(result, fail_under)


# =============================================================================
# Private helpers
# =============================================================================


def _load_results(input_path: str) -> list[dict[str, Any]]:
    """Resolve INPUT_PATH to a MIESC results structure (list of per-tool dicts).

    A ``.json`` file (or any file that parses as JSON) is loaded directly. A
    ``.sol`` file or a directory is scanned first via ``miesc scan -o <tmp>.json``
    and the resulting report is loaded. JSON input is the must-have path; scanning
    is the convenience path.
    """
    path = Path(input_path)

    if path.is_file():
        data = _try_load_json(path)
        if data is not None:
            return _results_from_data(data)

    # .sol file or directory -> scan into a temp report, then load it.
    return _scan_to_results(input_path)


def _try_load_json(path: Path) -> Any | None:
    """Return parsed JSON if ``path`` is a JSON document, else ``None``."""
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError, OSError):
        return None


def _results_from_data(data: Any) -> list[dict[str, Any]]:
    """Mirror the export command's result extraction: ``data.get('results', [data])``."""
    if isinstance(data, dict):
        return data.get("results", [data])
    if isinstance(data, list):
        return data
    return [data]


def _scan_to_results(input_path: str) -> list[dict[str, Any]]:
    """Run ``miesc scan <input_path> -o <tmp>.json --quiet`` and load the report."""
    info(f"Scanning {input_path} to compute a score...")
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        tmp_path = tmp.name
    try:
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "miesc.cli.main",
                "scan",
                input_path,
                "-o",
                tmp_path,
                "--quiet",
            ],
            capture_output=True,
            text=True,
        )
        data = _try_load_json(Path(tmp_path))
        if data is None:
            error(
                "Scan did not produce a readable report "
                f"(exit {proc.returncode}). {proc.stderr.strip()[:200]}"
            )
            raise click.Abort()
        return _results_from_data(data)
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def _render_badge(kind: str, result: SecurityScore) -> str:
    """Render the requested badge representation as a string."""
    if kind == "svg":
        return badge_svg(result)
    if kind == "json":
        return json.dumps(badge_endpoint(result), indent=2)
    # markdown: an embeddable snippet with the SVG inlined as a self-contained data URI.
    svg_b64 = base64.b64encode(badge_svg(result).encode("utf-8")).decode("ascii")
    return f"![MIESC security](data:image/svg+xml;base64,{svg_b64})"


def _severity_line(result: SecurityScore) -> str:
    """One-line severity breakdown, e.g. '0 critical · 1 high · 3 medium · 0 low'."""
    counts = result.severity_counts
    always = ["critical", "high", "medium", "low"]
    parts = [f"{counts.get(sev, 0)} {sev}" for sev in always]
    # Append any other severities actually present (e.g. "info", "optimization").
    for sev, count in counts.items():
        if sev not in always:
            parts.append(f"{count} {sev}")
    return " · ".join(parts)


def _print_human(result: SecurityScore) -> None:
    """Print the score, grade and severity breakdown for a human reader."""
    sev_line = _severity_line(result)
    if RICH_AVAILABLE:
        grade_color = {
            "A": "green",
            "B": "green",
            "C": "yellow",
            "D": "red",
            "F": "red",
        }.get(result.grade, "white")
        console.print(
            f"[bold]MIESC Security Score:[/bold] "
            f"[bold {grade_color}]{result.score}/100[/bold {grade_color}]  ({result.grade})"
        )
        console.print(f"[dim]{sev_line}[/dim]")
        if result.weighted_by_confidence:
            console.print("[dim]score weighted by per-finding confidence[/dim]")
    else:
        print(f"MIESC Security Score: {result.score}/100  ({result.grade})")  # noqa: T201
        print(sev_line)  # noqa: T201
        if result.weighted_by_confidence:
            print("score weighted by per-finding confidence")  # noqa: T201


def _apply_gate(result: SecurityScore, fail_under: int) -> None:
    """CI gate: exit 1 when the score is below ``fail_under``."""
    if fail_under and result.score < fail_under:
        error(f"Security score {result.score} is below the required {fail_under} (--fail-under).")
        sys.exit(1)
