"""
MIESC CLI - PoC Commands

Commands for generating and running Proof-of-Concept exploits from findings.

Author: Fernando Boiero
License: AGPL-3.0
"""

import json
import logging
import sys
from pathlib import Path

import click

from miesc.cli.utils import (
    RICH_AVAILABLE,
    console,
    error,
    info,
    print_banner,
    success,
    warning,
)

# Import Rich components if available
if RICH_AVAILABLE:
    from rich import box
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.table import Table

logger = logging.getLogger(__name__)

# Lazy loading globals
POC_AVAILABLE = None
_PoCGenerator = None
_FoundryRunner = None


def get_poc_generator():
    """Lazy load PoCGenerator."""
    global POC_AVAILABLE, _PoCGenerator

    if POC_AVAILABLE is None:
        try:
            from src.poc import PoCGenerator

            _PoCGenerator = PoCGenerator
            POC_AVAILABLE = True
            logger.debug("PoCGenerator loaded successfully")
        except ImportError as e:
            logger.debug(f"PoCGenerator not available: {e}")
            POC_AVAILABLE = False

    if POC_AVAILABLE and _PoCGenerator:
        return _PoCGenerator()
    return None


def get_foundry_runner(project_dir: str):
    """Lazy load FoundryRunner."""
    global _FoundryRunner

    if _FoundryRunner is None:
        try:
            from src.poc.validators import FoundryRunner

            _FoundryRunner = FoundryRunner
            logger.debug("FoundryRunner loaded successfully")
        except ImportError as e:
            logger.debug(f"FoundryRunner not available: {e}")
            return None

    if _FoundryRunner:
        return _FoundryRunner(project_dir)
    return None


@click.group()
def poc():
    """Generate and run Proof-of-Concept exploits from findings."""
    pass


@poc.command("generate")
@click.argument("finding_file", type=click.Path(exists=True), required=False)
@click.option("--type", "-t", "vuln_type", help="Vulnerability type (e.g., reentrancy, flash_loan)")
@click.option(
    "--contract", "-c", "target_contract", required=True, help="Target contract name or path"
)
@click.option("--function", "-f", "target_function", help="Target function name")
@click.option("--output", "-o", type=click.Path(), default="test/exploits", help="Output directory")
@click.option("--json-input", "-j", "json_input", help="Inline JSON finding (instead of file)")
@click.option("--fork-url", help="RPC URL for forking mainnet state")
@click.option("--fork-block", type=int, help="Block number for forking")
@click.option("--attacker-balance", default="100 ether", help="Attacker initial balance")
def poc_generate(
    finding_file,
    vuln_type,
    target_contract,
    target_function,
    output,
    json_input,
    fork_url,
    fork_block,
    attacker_balance,
):
    """Generate a PoC exploit from a vulnerability finding.

    Can read from a finding JSON file or inline JSON.

    \b
    Examples:
        miesc poc generate finding.json -c VulnerableToken.sol
        miesc poc generate -t reentrancy -c Token.sol -f withdraw
        miesc poc generate -j '{"type":"flash_loan"}' -c LendingPool.sol
    """
    print_banner()

    generator = get_poc_generator()
    if not generator:
        error("PoC Generator not available. Check installation.")
        sys.exit(1)

    # Build finding dict
    if finding_file:
        info(f"Loading finding from {finding_file}")
        with open(finding_file, "r") as f:
            finding = json.load(f)
    elif json_input:
        info("Parsing inline JSON finding")
        finding = json.loads(json_input)
    elif vuln_type:
        info(f"Creating finding for type: {vuln_type}")
        finding = {
            "type": vuln_type,
            "function": target_function,
            "id": f"manual-{vuln_type}",
        }
    else:
        error("Provide a finding file, --json-input, or --type")
        sys.exit(1)

    # Add function if specified
    if target_function and "function" not in finding:
        finding["function"] = target_function

    # Configure options
    from src.poc import GenerationOptions

    options = GenerationOptions(
        fork_url=fork_url,
        fork_block=fork_block,
        attacker_balance=attacker_balance,
    )

    try:
        poc_template = generator.generate(
            finding=finding,
            target_contract=target_contract,
            options=options,
        )

        # Save PoC
        saved_path = poc_template.save(output)

        success(f"PoC generated: {saved_path}")

        if RICH_AVAILABLE:
            table = Table(title="PoC Details", box=box.ROUNDED)
            table.add_column("Property", style="bold")
            table.add_column("Value")

            table.add_row("Name", poc_template.name)
            table.add_row("Type", poc_template.vulnerability_type.value)
            table.add_row("Target", target_contract)
            if target_function:
                table.add_row("Function", target_function)
            table.add_row("Output", str(saved_path))

            console.print(table)
        else:
            print(f"\nName: {poc_template.name}")  # noqa: T201
            print(f"Type: {poc_template.vulnerability_type.value}")  # noqa: T201
            print(f"Target: {target_contract}")  # noqa: T201
            print(f"Output: {saved_path}")  # noqa: T201

        print("")  # noqa: T201
        info("Run the PoC with:")
        print(f"  miesc poc run {saved_path}")  # noqa: T201
        print(f"  # or: forge test --match-path {saved_path} -vvv")  # noqa: T201

    except Exception as e:
        error(f"Failed to generate PoC: {e}")
        logger.exception("PoC generation error")
        sys.exit(1)


@poc.command("run")
@click.argument("poc_path", type=click.Path(exists=True))
@click.option(
    "--project", "-p", type=click.Path(exists=True), default=".", help="Foundry project directory"
)
@click.option("--verbosity", "-v", type=int, default=3, help="Verbosity level (1-5)")
@click.option("--gas-report", is_flag=True, default=True, help="Include gas report")
@click.option("--fork-url", help="RPC URL for forking")
@click.option("--fork-block", type=int, help="Block number for fork")
@click.option("--timeout", "-t", type=int, default=300, help="Timeout in seconds")
def poc_run(poc_path, project, verbosity, gas_report, fork_url, fork_block, timeout):
    """Run a PoC test and validate the exploit.

    \b
    Examples:
        miesc poc run test/exploits/PoC_reentrancy_test.t.sol
        miesc poc run poc.t.sol --fork-url https://eth-mainnet.alchemyapi.io/v2/KEY
        miesc poc run poc.t.sol -v 5 --gas-report
    """
    print_banner()

    try:
        runner = get_foundry_runner(project)
    except RuntimeError as e:
        error(str(e))
        sys.exit(1)

    if not runner:
        error(
            "Foundry Runner not available. Install Foundry: curl -L https://foundry.paradigm.xyz | bash"
        )
        sys.exit(1)

    # Override runner settings
    runner.verbosity = verbosity
    runner.gas_report = gas_report
    if fork_url:
        runner.fork_url = fork_url
    if fork_block:
        runner.fork_block = fork_block

    info(f"Running PoC: {poc_path}")

    if RICH_AVAILABLE:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
        ) as progress:
            task = progress.add_task("Executing exploit...", total=None)
            result = runner.run_test(poc_path, timeout=timeout)
            progress.update(task, completed=True)
    else:
        print("Executing exploit...")  # noqa: T201
        result = runner.run_test(poc_path, timeout=timeout)

    # Display results
    if result.success:
        success("PoC executed successfully!")
    else:
        if result.error:
            error(f"PoC failed: {result.error}")
        else:
            warning("PoC completed with failures")

    if RICH_AVAILABLE:
        table = Table(title="Execution Results", box=box.ROUNDED)
        table.add_column("Metric", style="bold")
        table.add_column("Value", justify="right")

        table.add_row("Total Tests", str(result.total_tests))
        table.add_row("Passed", str(result.passed), style="green" if result.passed > 0 else "dim")
        table.add_row("Failed", str(result.failed), style="red" if result.failed > 0 else "dim")
        table.add_row("Skipped", str(result.skipped))
        table.add_row("Total Gas", f"{result.total_gas:,}")
        table.add_row("Time (ms)", f"{result.execution_time_ms:.1f}")

        console.print(table)

        # Show individual test results
        if result.tests:
            test_table = Table(title="Test Details", box=box.SIMPLE)
            test_table.add_column("Test")
            test_table.add_column("Status")
            test_table.add_column("Gas", justify="right")

            for test in result.tests:
                status_style = "green" if test.status.value == "passed" else "red"
                gas_str = f"{test.gas_used:,}" if test.gas_used else "-"
                test_table.add_row(
                    test.name, test.status.value.upper(), gas_str, style=status_style
                )
            console.print(test_table)
    else:
        print("\n=== Results ===")  # noqa: T201
        print(f"Tests: {result.passed}/{result.total_tests} passed")  # noqa: T201
        print(f"Gas: {result.total_gas:,}")  # noqa: T201
        print(f"Time: {result.execution_time_ms:.1f}ms")  # noqa: T201

    # Validate exploit success
    validation = runner.validate_poc(poc_path)
    if validation.get("exploit_demonstrated"):
        success("Exploit successfully demonstrated!")
    elif validation.get("exploit_demonstrated") is False:
        warning("Exploit may not have succeeded - review output")

    if validation.get("warnings"):
        for warn in validation["warnings"]:
            warning(warn)

    if not result.success:
        sys.exit(1)


@poc.command("list")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed template info")
def poc_list(verbose):
    """List available PoC templates and supported vulnerability types.

    \b
    Examples:
        miesc poc list
        miesc poc list -v
    """
    print_banner()

    generator = get_poc_generator()
    if not generator:
        error("PoC Generator not available")
        sys.exit(1)

    info("Available vulnerability types for PoC generation:\n")

    # Get vulnerability types from the generator
    from src.poc import VulnerabilityType

    if RICH_AVAILABLE:
        table = Table(title="Supported Vulnerability Types", box=box.ROUNDED)
        table.add_column("Type", style="bold cyan")
        table.add_column("Template", style="dim")
        table.add_column("Description")

        descriptions = {
            "reentrancy": "Re-entrancy attack via external calls",
            "flash_loan": "Flash loan exploit for price manipulation",
            "oracle_manipulation": "Oracle/price feed manipulation",
            "access_control": "Access control bypass or privilege escalation",
            "integer_overflow": "Integer overflow arithmetic error",
            "integer_underflow": "Integer underflow arithmetic error",
            "unchecked_call": "Unchecked low-level call return value",
            "front_running": "Transaction front-running / MEV",
            "dos": "Denial of Service attack",
            "timestamp_dependence": "Block timestamp manipulation",
            "tx_origin": "tx.origin authentication bypass",
            "selfdestruct": "Selfdestruct abuse",
            "delegatecall": "Delegatecall to untrusted contract",
            "signature_replay": "Signature replay attack",
            "erc4626_inflation": "ERC4626 vault inflation attack",
            "price_manipulation": "DeFi price manipulation",
        }

        for vuln_type in VulnerabilityType:
            template = generator.TEMPLATE_MAP.get(vuln_type, "generic.t.sol")
            desc = descriptions.get(vuln_type.value, "")
            table.add_row(vuln_type.value, template, desc)

        console.print(table)

        if verbose:
            print("")  # noqa: T201
            info("Type aliases (alternative names):")
            alias_table = Table(box=box.SIMPLE)
            alias_table.add_column("Alias", style="cyan")
            alias_table.add_column("Maps To", style="bold")

            for alias, vuln_type in sorted(generator.TYPE_ALIASES.items()):
                if alias != vuln_type.value:  # Only show actual aliases
                    alias_table.add_row(alias, vuln_type.value)

            console.print(alias_table)
    else:
        for vuln_type in VulnerabilityType:
            template = generator.TEMPLATE_MAP.get(vuln_type, "generic.t.sol")
            print(f"  {vuln_type.value:25} -> {template}")  # noqa: T201

    print("")  # noqa: T201
    info("Generate a PoC:")
    print("  miesc poc generate -t reentrancy -c VulnerableContract.sol")  # noqa: T201


@poc.command("validate")
@click.argument("poc_path", type=click.Path(exists=True))
@click.option(
    "--project", "-p", type=click.Path(exists=True), default=".", help="Foundry project directory"
)
@click.option("--expected-profit", is_flag=True, default=True, help="Expect profit demonstration")
def poc_validate(poc_path, project, expected_profit):
    """Validate a PoC without full execution output.

    Quick validation check for CI/CD pipelines.

    \b
    Examples:
        miesc poc validate test/exploits/poc.t.sol
        miesc poc validate poc.t.sol --no-expected-profit
    """
    try:
        runner = get_foundry_runner(project)
    except RuntimeError as e:
        error(str(e))
        sys.exit(1)

    if not runner:
        error("Foundry Runner not available")
        sys.exit(1)

    info(f"Validating PoC: {poc_path}")

    validation = runner.validate_poc(poc_path, expected_profit=expected_profit)

    if validation["valid"]:
        success("PoC validation passed")
        print(f"  Tests passed: {validation['tests_passed']}")  # noqa: T201
        print(f"  Gas used: {validation['total_gas']:,}")  # noqa: T201

        if validation.get("exploit_demonstrated"):
            success("Exploit demonstrated successfully")
    else:
        error("PoC validation failed")
        for err in validation.get("errors", []):
            error(f"  {err}")

        sys.exit(1)

    for warn in validation.get("warnings", []):
        warning(f"  {warn}")
