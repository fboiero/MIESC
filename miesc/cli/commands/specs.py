"""
`miesc specs` — auto-generate formal verification specs from findings.
"""

import json
import sys
from pathlib import Path

import click

from miesc.cli.utils import console, error, info, print_banner, success


@click.command()
@click.argument("results_file", type=click.Path(exists=True))
@click.option(
    "--format",
    "-f",
    type=click.Choice(["cvl", "scribble", "smtchecker"], case_sensitive=False),
    default="cvl",
    help="Specification format (default: cvl for Certora)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default=None,
    help="Output file (default: specs.<format>)",
)
@click.option(
    "--contract-name",
    default="MyContract",
    help="Contract name for spec headers",
)
@click.option("--quiet", "-q", is_flag=True, help="Minimal output")
def specs(results_file, format, output, contract_name, quiet):
    """Generate formal verification specs (CVL, Scribble, SMTChecker) from findings.

    \b
    Examples:
      miesc specs results.json                       # Default: CVL
      miesc specs results.json -f scribble -o anns.sol
      miesc specs results.json -f smtchecker -o asserts.sol

    \b
    After generation:
      certoraRun contract.sol --verify MyContract:specs.spec
      scribble contract.sol --arm  # If using Scribble annotations
    """
    if not quiet:
        print_banner()

    # Load findings
    try:
        with open(results_file) as f:
            data = json.load(f)
    except Exception as e:
        error(f"Failed to load {results_file}: {e}")
        sys.exit(1)

    findings = data.get("findings", [])
    if not findings:
        info("No findings in results file — nothing to generate")
        sys.exit(0)

    # Default output path
    if output is None:
        ext = {"cvl": "spec", "scribble": "annotations.sol", "smtchecker": "asserts.sol"}
        output = f"specs.{ext[format.lower()]}"

    # Generate
    try:
        from src.formal import SpecFormat, SpecGenerator

        gen = SpecGenerator()
        fmt = SpecFormat(format.lower())
        count = gen.generate_spec_file(
            findings=findings,
            output_path=Path(output),
            contract_name=contract_name,
            format=fmt,
        )
    except Exception as e:
        error(f"Spec generation failed: {e}")
        sys.exit(1)

    if count == 0:
        info(f"No specs generated — no findings match {format.upper()} templates")
        info("Supported types per format:")
        info("  CVL:        reentrancy, access-control, overflow, unchecked-call, timestamp, weak-randomness")
        info("  Scribble:   reentrancy, access-control, overflow, unchecked-call")
        info("  SMTChecker: overflow, underflow, unchecked-call")
        sys.exit(0)

    success(f"Generated {count} {format.upper()} spec(s) → {output}")

    # Next-steps hint
    if format.lower() == "cvl":
        info(f"Run: certoraRun yourcontract.sol --verify {contract_name}:{output}")
    elif format.lower() == "scribble":
        info("Insert annotations into Solidity, then: scribble contract.sol --arm")
    else:
        info("Insert SMTChecker asserts into contract, then: solc --model-checker-engine chc")
