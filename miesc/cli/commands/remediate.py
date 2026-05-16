"""`miesc remediate` - apply fixes and emit verification evidence."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from miesc.cli.utils import error, info, success, warning
from src.security.remediation_pipeline import remediate_contract


def _resolve_output_path(contract_path: Path, output: str | None) -> Path:
    """Resolve output as either a directory or explicit Solidity file path."""
    if output is None:
        return contract_path.with_name(f"{contract_path.stem}.fixed.sol")

    output_path = Path(output)
    if output_path.suffix == ".sol":
        return output_path
    return output_path / f"{contract_path.stem}.fixed.sol"


@click.command()
@click.argument("results_file", type=click.Path(exists=True))
@click.option(
    "--contract",
    "-c",
    "contract_path",
    type=click.Path(exists=True),
    required=True,
    help="Original Solidity file to remediate.",
)
@click.option(
    "--output",
    "-o",
    default=None,
    type=click.Path(),
    help="Patched .sol file or output directory. Defaults to <contract>.fixed.sol.",
)
@click.option(
    "--evidence-output",
    type=click.Path(),
    default=None,
    help="Evidence JSON path. Defaults to <patched>.evidence.json.",
)
@click.option(
    "--compile",
    "compile_check",
    is_flag=True,
    help="Compile the patched contract standalone with selected solc.",
)
@click.option(
    "--rescan",
    "rescan_check",
    is_flag=True,
    help="Re-scan the patched contract and compare findings.",
)
@click.option(
    "--no-regression-bound",
    type=int,
    default=2,
    show_default=True,
    help="Allowed finding-count increase for bounded no-regression.",
)
@click.option("--quiet", "-q", is_flag=True, help="Minimal output.")
def remediate(
    results_file: str,
    contract_path: str,
    output: str | None,
    evidence_output: str | None,
    compile_check: bool,
    rescan_check: bool,
    no_regression_bound: int,
    quiet: bool,
) -> None:
    """Apply MIESC fixes and write a Paper 2-style evidence bundle.

    This command is the evidence-producing counterpart to `miesc fix`. It
    generates the patched Solidity artifact and records the remediation state:
    patch application, optional standalone compilation, optional re-scan, and
    bounded no-regression.

    \b
    Examples:
      miesc remediate results.json -c Contract.sol
      miesc remediate results.json -c Contract.sol -o out/ --compile --rescan
      miesc remediate results.json -c Contract.sol -o Contract.fixed.sol --evidence-output evidence.json
    """
    contract = Path(contract_path)
    patched_path = _resolve_output_path(contract, output)
    evidence_path = (
        Path(evidence_output) if evidence_output else patched_path.with_suffix(".evidence.json")
    )

    try:
        results = json.loads(Path(results_file).read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        error(f"Cannot read results file: {exc}")
        sys.exit(1)

    if not quiet:
        info(f"Remediating {contract}")
        info(f"Patched artifact: {patched_path}")

    try:
        evidence = remediate_contract(
            contract_path=contract,
            results=results,
            output_path=patched_path,
            compile_check=compile_check,
            rescan_check=rescan_check,
            no_regression_bound=no_regression_bound,
        )
    except OSError as exc:
        error(f"Remediation failed: {exc}")
        sys.exit(1)

    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.write_text(json.dumps(evidence.to_dict(), indent=2) + "\n", encoding="utf-8")

    if evidence.status == "no_fixable_findings":
        warning(f"No fixable findings found. Evidence written to {evidence_path}")
        sys.exit(0)

    if not quiet:
        if evidence.compile.checked:
            compile_status = "passed" if evidence.compile.compiles else "failed"
            info(f"Compile check: {compile_status}")
        if evidence.rescan.checked:
            eliminated = "yes" if evidence.rescan.eliminated else "no"
            no_regression = "yes" if evidence.rescan.no_regression else "no"
            info(f"Re-scan eliminated original high findings: {eliminated}")
            info(f"Bounded no-regression: {no_regression}")

    success(f"Applied {evidence.fixes_applied} fix(es); evidence written to {evidence_path}")
