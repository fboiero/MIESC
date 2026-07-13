"""
`miesc verify` — run generated formal-verification specs against installed provers.

Closes the loop: `miesc specs` generates CVL/Scribble/SMTChecker specs,
`miesc verify` actually invokes the installed provers and reports pass/fail.
"""

import sys
from pathlib import Path
from typing import Any, Dict, Optional

import click

from miesc.cli.utils import console, error, info, print_banner, success, warning


def _find_foundry_root(start: Path) -> Optional[Path]:
    """Walk up from `start` looking for foundry.toml. Returns project root or None."""
    p = start.resolve()
    if p.is_file():
        p = p.parent
    for candidate in [p, *p.parents]:
        if (candidate / "foundry.toml").exists():
            return candidate
    return None


@click.command()
@click.argument("contract_path", type=click.Path(exists=True))
@click.option(
    "--spec",
    "-s",
    type=click.Path(exists=True),
    default=None,
    help="Path to .spec file (required for Certora).",
)
@click.option(
    "--tool",
    "-t",
    type=click.Choice(
        ["all", "certora", "halmos", "smtchecker", "scribble", "kontrol"],
        case_sensitive=False,
    ),
    default="all",
    help="Which prover to run (default: all available).",
)
@click.option(
    "--contract-name",
    default="MyContract",
    help="Contract name for Certora --verify.",
)
@click.option(
    "--timeout",
    type=int,
    default=300,
    help="Per-tool timeout in seconds (default: 300).",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default=None,
    help="Write the unified verification report to JSON (default: stdout summary only).",
)
@click.option(
    "--sarif",
    type=click.Path(),
    default=None,
    help="Write the unified verification report as SARIF 2.1.0 (GitHub code scanning).",
)
@click.option("--quiet", "-q", is_flag=True, help="Minimal output")
def verify(
    contract_path: str,
    spec: str | None,
    tool: str,
    contract_name: str,
    timeout: int,
    output: str | None,
    sarif: str | None,
    quiet: bool,
) -> None:
    """Run formal-verification provers against a contract.

    \b
    Workflow:
      1. miesc audit full contract.sol -o results.json
      2. miesc specs results.json -f cvl -o rules.spec
      3. miesc verify contract.sol --spec rules.spec

    \b
    Examples:
      miesc verify contract.sol                          # all available provers
      miesc verify contract.sol --tool smtchecker        # only SMTChecker
      miesc verify contract.sol --spec rules.spec -t certora
    """
    if not quiet:
        print_banner()

    try:
        from miesc.formal import SpecRunner
    except ImportError as e:
        error(f"Cannot import SpecRunner: {e}")
        sys.exit(1)

    runner = SpecRunner()
    availability = runner.availability_report()

    if not quiet:
        info("Prover availability:")
        for name, avail in availability.items():
            marker = "✓" if avail else "✗"
            console.print(f"  {marker} {name}")
        console.print()

    results: Dict[str, Any] = {}
    tool_lower = tool.lower()

    # SMTChecker — works out-of-the-box with solc
    if tool_lower in ("all", "smtchecker"):
        if availability["smtchecker"]:
            info("Running SMTChecker...") if not quiet else None
            results["smtchecker"] = runner.run_smtchecker(contract_path, timeout=timeout)
        elif tool_lower == "smtchecker":
            error("solc not installed; cannot run SMTChecker")
            sys.exit(1)

    # Certora — requires spec file
    if tool_lower in ("all", "certora"):
        if availability["certora"]:
            if not spec:
                if tool_lower == "certora":
                    error("--spec is required for Certora")
                    sys.exit(1)
                warning("Skipping Certora: no --spec provided")
            else:
                info("Running Certora Prover...") if not quiet else None
                results["certora"] = runner.run_certora(
                    contract_path, spec, contract_name=contract_name, timeout=timeout
                )
        elif tool_lower == "certora":
            error("certoraRun not installed; install from https://docs.certora.com/")
            sys.exit(1)

    # Halmos — operates on the Foundry project dir (where foundry.toml lives)
    if tool_lower in ("all", "halmos"):
        if availability["halmos"]:
            foundry_root = _find_foundry_root(Path(contract_path))
            if foundry_root is None:
                if tool_lower == "halmos":
                    error(
                        f"No foundry.toml found above {contract_path}. "
                        "Halmos requires a Foundry project layout."
                    )
                    sys.exit(1)
                warning("Skipping Halmos: no foundry.toml found upstream of contract.")
            else:
                info(f"Running Halmos on {foundry_root}...") if not quiet else None
                results["halmos"] = runner.run_halmos(str(foundry_root), timeout=timeout)
        elif tool_lower == "halmos":
            error("halmos not installed; pip install halmos")
            sys.exit(1)

    # Scribble — annotation instrumentation, operates on the contract file
    if tool_lower in ("all", "scribble"):
        if availability.get("scribble"):
            info("Running Scribble...") if not quiet else None
            results["scribble"] = runner.run_scribble(contract_path, timeout=timeout)
        elif tool_lower == "scribble":
            error("scribble not installed; npm install -g eth-scribble")
            sys.exit(1)

    # Kontrol — KEVM symbolic proving on the Foundry project dir
    if tool_lower in ("all", "kontrol"):
        if availability.get("kontrol"):
            foundry_root = _find_foundry_root(Path(contract_path))
            if foundry_root is None:
                if tool_lower == "kontrol":
                    error(
                        f"No foundry.toml found above {contract_path}. "
                        "Kontrol requires a Foundry project layout."
                    )
                    sys.exit(1)
                warning("Skipping Kontrol: no foundry.toml found upstream of contract.")
            else:
                info(f"Running Kontrol on {foundry_root}...") if not quiet else None
                results["kontrol"] = runner.run_kontrol(str(foundry_root), timeout=timeout)
        elif tool_lower == "kontrol":
            error(
                "kontrol not installed; "
                "see https://docs.runtimeverification.com/kontrol"
            )
            sys.exit(1)

    if not results:
        warning("No provers were run (none installed for selected --tool).")
        sys.exit(0)

    # Summary
    if not quiet:
        console.print("\n[bold]Verification Results[/bold]")
        for name, r in results.items():
            status_color = {
                "passed": "green",
                "failed": "red",
                "timeout": "yellow",
                "error": "dim",
                "no_tests": "yellow",
            }.get(r.status, "white")
            console.print(
                f"  [{status_color}]{name}[/{status_color}]: {r.status} "
                f"({r.rules_passed}/{r.rules_total} rules, {r.elapsed_seconds:.2f}s)"
            )
            if r.counterexamples:
                console.print(f"    counterexamples: {len(r.counterexamples)}")

    # Aggregate all per-prover results into one first-class report.
    from miesc.formal.unified_report import UnifiedVerificationReport

    report = UnifiedVerificationReport.from_runner_results(
        contract_path, results, availability=availability
    )

    if not quiet:
        verdict_color = {
            "verified": "green",
            "violated": "red",
            "inconclusive": "yellow",
            "no_provers": "dim",
        }.get(report.overall_verdict, "white")
        console.print(
            f"\n[bold]Overall verdict:[/bold] "
            f"[{verdict_color}]{report.overall_verdict}[/{verdict_color}]"
        )

    # Write unified JSON report
    if output:
        report.to_json(output)
        success(f"Unified report written to {output}")

    # Write unified SARIF report
    if sarif:
        report.to_sarif(sarif)
        success(f"SARIF report written to {sarif}")

    # Exit code: 1 if any prover reported failures
    any_failed = any(r.status == "failed" for r in results.values())
    sys.exit(1 if any_failed else 0)
