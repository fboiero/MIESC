"""
`miesc analyze` — multi-chain analysis (Solidity, Move, Cairo, Solana).

Auto-detects the chain from file extension and routes to the right analyzer.
"""

import json
import sys
from pathlib import Path

import click

from miesc.cli.utils import console, error, info, print_banner, success


# File extension → chain mapping
CHAIN_BY_EXTENSION = {
    ".sol": "ethereum",
    ".vy": "ethereum",        # Vyper (EVM)
    ".move": "move",          # Sui, Aptos
    ".cairo": "starknet",     # Starknet
    ".rs": "solana",          # Anchor/native Solana
}

SUPPORTED_CHAINS = ["ethereum", "move", "starknet", "solana"]


def detect_chain(contract_path: str) -> str:
    """Detect chain from file extension."""
    ext = Path(contract_path).suffix.lower()
    return CHAIN_BY_EXTENSION.get(ext, "unknown")


@click.command()
@click.argument("contract", type=click.Path(exists=True))
@click.option(
    "--chain",
    type=click.Choice(SUPPORTED_CHAINS, case_sensitive=False),
    default=None,
    help="Override chain detection (auto-detected from file extension)",
)
@click.option(
    "--output", "-o", type=click.Path(), help="Output JSON file for findings"
)
@click.option("--quiet", "-q", is_flag=True, help="Minimal output")
def analyze(contract, chain, output, quiet):
    """Analyze smart contracts across multiple chains.

    \b
    Supported:
      Ethereum/EVM     .sol, .vy     (routed to Slither, Aderyn, etc.)
      Starknet         .cairo         (Cairo analyzer)
      Move (Sui/Aptos) .move          (Move analyzer)
      Solana/Anchor    .rs            (Anchor analyzer)

    \b
    Examples:
      miesc analyze Token.sol           # Auto-detects EVM
      miesc analyze Vault.cairo         # Auto-detects Starknet
      miesc analyze program.rs --chain solana
      miesc analyze MyModule.move
    """
    if not quiet:
        print_banner()

    # Detect chain
    if chain is None:
        chain = detect_chain(contract)

    if chain == "unknown":
        error(f"Cannot determine chain for file: {contract}")
        error(f"Use --chain {{{', '.join(SUPPORTED_CHAINS)}}} to specify manually")
        sys.exit(1)

    if not quiet:
        info(f"Analyzing {contract} as {chain.upper()} contract")

    # Route to appropriate analyzer
    try:
        if chain == "ethereum":
            # Delegate to scan command
            from miesc.cli.commands.scan import scan
            ctx = click.get_current_context()
            ctx.invoke(scan, contract=contract, output=output, ci=False, quiet=quiet,
                       fp_strictness="medium", llm_enhance=False)
            return

        elif chain == "starknet":
            from src.adapters.cairo_adapter import CairoAnalyzer
            result = CairoAnalyzer().analyze(contract)

        elif chain == "move":
            from src.adapters.move_adapter import MoveAnalyzer
            analyzer = MoveAnalyzer()
            # MoveAnalyzer is AbstractChainAnalyzer — use parse + detect
            contract_obj = analyzer.parse_contract(Path(contract))
            findings = analyzer.detect_vulnerabilities(contract_obj)
            result = {
                "success": True,
                "tool": "miesc-move",
                "chain": "move",
                "file": contract,
                "findings": [_normalize_finding(f, "move") for f in findings],
                "summary": _summarize(findings),
            }

        elif chain == "solana":
            from src.adapters.solana_adapter import SolanaAnalyzer
            analyzer = SolanaAnalyzer()
            contract_obj = analyzer.parse_contract(Path(contract))
            findings = analyzer.detect_vulnerabilities(contract_obj)
            result = {
                "success": True,
                "tool": "miesc-solana",
                "chain": "solana",
                "file": contract,
                "findings": [_normalize_finding(f, "solana") for f in findings],
                "summary": _summarize(findings),
            }

    except Exception as e:
        error(f"Analysis failed: {e}")
        sys.exit(1)

    # Show summary
    findings = result.get("findings", [])
    summary = result.get("summary", {})
    total = len(findings)

    if not quiet:
        console.print(f"\n  [bold]{chain.upper()} Analysis Complete[/bold]")
        console.print(f"  Total findings: {total}")
        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            count = summary.get(sev, 0)
            if count > 0:
                color = "red" if sev in ("Critical", "High") else "yellow" if sev == "Medium" else "cyan"
                console.print(f"    [{color}]{sev:10s}[/{color}] {count}")

        # Show top findings
        for f in findings[:5]:
            sev = f.get("severity", "?")
            title = f.get("title", f.get("type", "?"))
            loc = f.get("location", {})
            line = loc.get("line", "?") if isinstance(loc, dict) else "?"
            console.print(f"    [{sev}] line {line}: {title}")

    if output:
        Path(output).write_text(json.dumps(result, indent=2, default=str))
        success(f"Report saved to {output}")


def _normalize_finding(f, chain: str) -> dict:
    """Convert AbstractFinding to MIESC finding dict."""
    if hasattr(f, "to_dict"):
        return f.to_dict()
    if hasattr(f, "__dict__"):
        d = dict(f.__dict__)
        d["chain"] = chain
        return d
    return {"chain": chain, "raw": str(f)}


def _summarize(findings) -> dict:
    """Count by severity."""
    summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        sev = getattr(f, "severity", None) or (f.get("severity") if isinstance(f, dict) else "Low")
        if hasattr(sev, "value"):
            sev = sev.value
        sev = str(sev).title()
        if sev in summary:
            summary[sev] += 1
    return summary
