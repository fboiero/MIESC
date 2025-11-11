#!/usr/bin/env python3
"""
Organize Vulnerable Smart Contracts from Examples
For demonstration and testing purposes
"""

import os
import sys
import shutil
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False

# Vulnerable contracts from examples folder
VULNERABLE_CONTRACTS = {
    "reentrancy": {
        "name": "Reentrancy (DAO Hack)",
        "source_file": "reentrancy_simple.sol",
        "description": "Classic reentrancy vulnerability similar to The DAO hack",
        "cwe": "CWE-841",
        "swc": "SWC-107"
    },
    "integer_overflow": {
        "name": "Integer Overflow",
        "source_file": "integer_overflow.sol",
        "description": "Integer overflow vulnerability in arithmetic operations",
        "cwe": "CWE-190",
        "swc": "SWC-101"
    },
    "unchecked_send": {
        "name": "Unchecked Low-Level Call",
        "source_file": "unchecked_send.sol",
        "description": "Unchecked return value from send()",
        "cwe": "CWE-252",
        "swc": "SWC-104"
    },
    "tx_origin": {
        "name": "tx.origin Authentication",
        "source_file": "tx_origin.sol",
        "description": "Using tx.origin for authentication",
        "cwe": "CWE-346",
        "swc": "SWC-115"
    },
    "delegatecall_injection": {
        "name": "Delegatecall Injection",
        "source_file": "delegatecall_injection.sol",
        "description": "Unsafe use of delegatecall",
        "cwe": "CWE-829",
        "swc": "SWC-112"
    },
    "vulnerable_bank": {
        "name": "Vulnerable Bank",
        "source_file": "vulnerable_bank.sol",
        "description": "Multiple vulnerabilities in bank contract",
        "cwe": "CWE-682",
        "swc": "SWC-101"
    }
}

def organize_contract(name, info, output_dir, examples_dir):
    """Organize a single contract from examples"""
    try:
        source_path = Path(examples_dir) / info['source_file']

        if not source_path.exists():
            return False, f"Source file not found: {source_path}"

        # Create output directory
        contract_dir = Path(output_dir) / name
        contract_dir.mkdir(parents=True, exist_ok=True)

        # Copy contract file
        contract_file = contract_dir / f"{name}.sol"
        shutil.copy2(source_path, contract_file)

        # Create metadata file
        metadata_file = contract_dir / "metadata.txt"
        metadata = f"""Contract: {info['name']}
Description: {info['description']}
Vulnerability: {info['swc']} / {info['cwe']}
Source: MIESC Examples
File: {name}.sol
Original: {info['source_file']}
"""
        metadata_file.write_text(metadata)

        return True, str(contract_file)
    except Exception as e:
        return False, str(e)

def main():
    """Organize vulnerable contracts from examples"""
    output_dir = Path("vulnerable_contracts")
    examples_dir = Path("examples")

    # Check if examples directory exists
    if not examples_dir.exists():
        print(f"❌ Error: Examples directory not found: {examples_dir.absolute()}")
        print("Please run this script from the project root directory.")
        return 1

    if RICH_AVAILABLE:
        console.print("[bold cyan]📥 Organizing Vulnerable Smart Contracts[/bold cyan]")
        console.print(f"Source: {examples_dir.absolute()}")
        console.print(f"Output: {output_dir.absolute()}\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task(
                "[cyan]Organizing contracts...",
                total=len(VULNERABLE_CONTRACTS)
            )

            success_count = 0
            for name, info in VULNERABLE_CONTRACTS.items():
                progress.update(task, description=f"[cyan]Organizing {info['name']}...")

                success, result = organize_contract(name, info, output_dir, examples_dir)

                if success:
                    console.print(f"[green]✓[/green] {info['name']}: {result}")
                    success_count += 1
                else:
                    console.print(f"[yellow]⚠[/yellow] {info['name']}: {result}")

                progress.advance(task)

        console.print(f"\n[bold green]✓ Organized {success_count}/{len(VULNERABLE_CONTRACTS)} contracts[/bold green]")
        console.print(f"[cyan]Location:[/cyan] {output_dir.absolute()}\n")

        # Print summary
        console.print("[bold]Summary of Vulnerabilities:[/bold]")
        for name, info in VULNERABLE_CONTRACTS.items():
            console.print(f"  • {info['name']}: {info['swc']}")
    else:
        print("📥 Organizing Vulnerable Smart Contracts")
        print(f"Source: {examples_dir.absolute()}")
        print(f"Output: {output_dir.absolute()}\n")

        success_count = 0
        for name, info in VULNERABLE_CONTRACTS.items():
            print(f"Organizing {info['name']}...", end=" ")
            success, result = organize_contract(name, info, output_dir, examples_dir)

            if success:
                print(f"✓ {result}")
                success_count += 1
            else:
                print(f"⚠ {result}")

        print(f"\n✓ Organized {success_count}/{len(VULNERABLE_CONTRACTS)} contracts")
        print(f"Location: {output_dir.absolute()}")

if __name__ == "__main__":
    main()
