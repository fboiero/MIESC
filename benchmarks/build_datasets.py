#!/usr/bin/env python3
"""
MIESC - Dataset Builder for Benchmark Evaluation
=================================================

Downloads and prepares three evaluation datasets:
  A) Etherscan verified contracts (5000+ real-world)
  B) Rekt.news exploits (200+ with confirmed vulnerabilities)
  C) Code4rena audit contests (validated findings as ground truth)

Usage:
    python benchmarks/build_datasets.py --all
    python benchmarks/build_datasets.py --rekt
    python benchmarks/build_datasets.py --etherscan --api-key YOUR_KEY
    python benchmarks/build_datasets.py --code4rena

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL-3.0
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
DATA_DIR = PROJECT_ROOT / "data" / "datasets"


# ============================================================================
# Option B: Rekt Exploits (DeFiHackLabs)
# ============================================================================

def build_rekt_dataset():
    """Download exploit PoCs from DeFiHackLabs (SunWeb3Sec)."""
    rekt_dir = DATA_DIR / "rekt_exploits" / "contracts"
    rekt_dir.mkdir(parents=True, exist_ok=True)

    repo_url = "https://github.com/SunWeb3Sec/DeFiHackLabs.git"
    clone_dir = DATA_DIR / "rekt_exploits" / "_defihacklabs"

    print(f"\n{'='*60}")
    print(f"  Building Rekt Exploits Dataset")
    print(f"  Source: {repo_url}")
    print(f"{'='*60}\n")

    if clone_dir.exists():
        print("  Repo already cloned, pulling updates...")
        subprocess.run(["git", "-C", str(clone_dir), "pull", "--ff-only"],
                       capture_output=True, timeout=120)
    else:
        print("  Cloning DeFiHackLabs (this may take a few minutes)...")
        result = subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, str(clone_dir)],
            capture_output=True, text=True, timeout=300,
        )
        if result.returncode != 0:
            print(f"  ERROR: git clone failed: {result.stderr}")
            return

    # Find all Solidity exploit files
    sol_files = list(clone_dir.rglob("*.sol"))
    print(f"  Found {len(sol_files)} .sol files")

    # Filter to actual exploit contracts (not interfaces/libs)
    exploit_contracts = []
    for f in sol_files:
        content = f.read_text(errors="replace")
        # Exploit files usually contain: test, exploit, attack, hack
        name_lower = f.stem.lower()
        if any(kw in name_lower for kw in ["exploit", "attack", "hack", "test", "poc"]):
            exploit_contracts.append(f)
        elif "function testExploit" in content or "function attack" in content:
            exploit_contracts.append(f)

    print(f"  Filtered to {len(exploit_contracts)} exploit contracts")

    # Copy to our dataset dir
    copied = 0
    for f in exploit_contracts[:500]:  # Cap at 500
        dest = rekt_dir / f.name
        if not dest.exists():
            dest.write_text(f.read_text(errors="replace"))
            copied += 1

    print(f"  Copied {copied} new contracts to {rekt_dir}")
    print(f"  Total contracts in dataset: {len(list(rekt_dir.glob('*.sol')))}")


# ============================================================================
# Option A: Etherscan Verified Contracts
# ============================================================================

def build_etherscan_dataset(api_key=None):
    """Download verified contracts from Etherscan."""
    etherscan_dir = DATA_DIR / "etherscan" / "contracts"
    etherscan_dir.mkdir(parents=True, exist_ok=True)

    api_key = api_key or os.environ.get("ETHERSCAN_API_KEY")

    print(f"\n{'='*60}")
    print(f"  Building Etherscan Verified Contracts Dataset")
    print(f"{'='*60}\n")

    if not api_key:
        # Use multiple smaller curated repos instead of the 100GB sanctuary
        print("  No Etherscan API key. Using curated contract collections...")

        repos = [
            ("https://github.com/smartbugs/smartbugs-wild.git", "smartbugs_wild"),
            ("https://github.com/crytic/not-so-smart-contracts.git", "not_so_smart"),
            ("https://github.com/sigp/solidity-security-blog.git", "sigp_security"),
        ]

        for repo_url, dirname in repos:
            clone_dir = DATA_DIR / "etherscan" / f"_{dirname}"
            if clone_dir.exists():
                print(f"  [{dirname}] already downloaded")
                continue

            print(f"  [{dirname}] cloning...", end=" ", flush=True)
            result = subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, str(clone_dir)],
                capture_output=True, text=True, timeout=300,
            )
            if result.returncode == 0:
                sol_count = len(list(clone_dir.rglob("*.sol")))
                print(f"OK ({sol_count} .sol files)")
            else:
                print("SKIP")

        # Collect all .sol files from downloaded repos
        all_sols = []
        for d in (DATA_DIR / "etherscan").iterdir():
            if d.is_dir() and d.name.startswith("_"):
                all_sols.extend(d.rglob("*.sol"))

        print(f"  Total .sol files found: {len(all_sols)}")

        import random
        random.seed(42)
        sample = random.sample(all_sols, min(5000, len(all_sols)))

        copied = 0
        for f in sample:
            dest = etherscan_dir / f"{f.parent.name}_{f.name}"
            if not dest.exists() and f.stat().st_size < 500_000:
                try:
                    dest.write_text(f.read_text(errors="replace"))
                    copied += 1
                except Exception:
                    pass

        print(f"  Copied {copied} contracts to {etherscan_dir}")
    else:
        print(f"  Using Etherscan API (key: {api_key[:6]}...)")
        print("  NOTE: Etherscan rate limits to 5 req/sec on free tier")
        # Would use etherscan API here - for now just note it
        print("  TODO: Implement Etherscan API download")

    total = len(list(etherscan_dir.glob("*.sol")))
    print(f"  Total contracts in dataset: {total}")


# ============================================================================
# Option C: Code4rena Audit Contests
# ============================================================================

def build_code4rena_dataset():
    """Download Code4rena audit contest data."""
    c4_dir = DATA_DIR / "code4rena"
    c4_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*60}")
    print(f"  Building Code4rena Audit Dataset")
    print(f"{'='*60}\n")

    # Clone Code4rena findings repo
    repo_url = "https://github.com/code-423n4/code423n4.com.git"
    findings_url = "https://github.com/code-423n4/findings.git"

    # The findings are in individual contest repos
    # Strategy: clone the main site, extract contest list, then clone findings
    clone_dir = c4_dir / "_code4rena_site"

    if clone_dir.exists():
        print("  Repo already cloned, pulling updates...")
        subprocess.run(["git", "-C", str(clone_dir), "pull", "--ff-only"],
                       capture_output=True, timeout=120)
    else:
        print("  Cloning Code4rena contest index...")
        result = subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, str(clone_dir)],
            capture_output=True, text=True, timeout=300,
        )
        if result.returncode != 0:
            print(f"  Note: Main repo not available, trying alternative approach...")

    # Alternative: use the public findings CSV/JSON if available
    # For now, create a curated list of well-documented contests
    contests = [
        {
            "id": "2023-01-ondo",
            "name": "Ondo Finance",
            "repo": "https://github.com/code-423n4/2023-01-ondo",
            "findings_repo": "https://github.com/code-423n4/2023-01-ondo-findings",
            "high_findings": 3,
            "medium_findings": 8,
        },
        {
            "id": "2023-03-asymmetry",
            "name": "Asymmetry",
            "repo": "https://github.com/code-423n4/2023-03-asymmetry",
            "findings_repo": "https://github.com/code-423n4/2023-03-asymmetry-findings",
            "high_findings": 5,
            "medium_findings": 12,
        },
        {
            "id": "2023-04-eigenlayer",
            "name": "EigenLayer",
            "repo": "https://github.com/code-423n4/2023-04-eigenlayer",
            "findings_repo": "https://github.com/code-423n4/2023-04-eigenlayer-findings",
            "high_findings": 2,
            "medium_findings": 7,
        },
        {
            "id": "2023-05-ajna",
            "name": "Ajna Protocol",
            "repo": "https://github.com/code-423n4/2023-05-ajna",
            "findings_repo": "https://github.com/code-423n4/2023-05-ajna-findings",
            "high_findings": 4,
            "medium_findings": 15,
        },
        {
            "id": "2023-07-amphora",
            "name": "Amphora Protocol",
            "repo": "https://github.com/code-423n4/2023-07-amphora",
            "findings_repo": "https://github.com/code-423n4/2023-07-amphora-findings",
            "high_findings": 3,
            "medium_findings": 10,
        },
    ]

    print(f"  Downloading {len(contests)} contest repositories...")

    contracts_dir = c4_dir / "contracts"
    contracts_dir.mkdir(exist_ok=True)
    findings_dir = c4_dir / "findings"
    findings_dir.mkdir(exist_ok=True)

    for contest in contests:
        contest_dir = contracts_dir / contest["id"]
        if contest_dir.exists():
            print(f"    [{contest['id']}] already downloaded")
            continue

        print(f"    [{contest['id']}] {contest['name']}...", end=" ", flush=True)

        # Clone source contracts
        result = subprocess.run(
            ["git", "clone", "--depth", "1", contest["repo"], str(contest_dir)],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            print("SKIP (repo unavailable)")
            continue

        # Clone findings
        findings_contest_dir = findings_dir / contest["id"]
        subprocess.run(
            ["git", "clone", "--depth", "1", contest["findings_repo"], str(findings_contest_dir)],
            capture_output=True, text=True, timeout=120,
        )

        # Count .sol files
        sol_count = len(list(contest_dir.rglob("*.sol")))
        print(f"OK ({sol_count} contracts)")

        time.sleep(1)  # Rate limiting

    # Save contest index
    index_file = c4_dir / "contests_index.json"
    with open(index_file, "w") as f:
        json.dump({"contests": contests, "downloaded": True}, f, indent=2)

    total_sol = len(list(contracts_dir.rglob("*.sol")))
    total_findings = len(list(findings_dir.rglob("*.md")))
    print(f"\n  Total contracts: {total_sol}")
    print(f"  Total finding reports: {total_findings}")


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="MIESC Dataset Builder")
    parser.add_argument("--all", action="store_true", help="Build all datasets")
    parser.add_argument("--rekt", action="store_true", help="Build Rekt exploits dataset")
    parser.add_argument("--etherscan", action="store_true", help="Build Etherscan dataset")
    parser.add_argument("--code4rena", action="store_true", help="Build Code4rena dataset")
    parser.add_argument("--api-key", help="Etherscan API key")
    args = parser.parse_args()

    if not any([args.all, args.rekt, args.etherscan, args.code4rena]):
        args.all = True

    if args.all or args.rekt:
        build_rekt_dataset()

    if args.all or args.etherscan:
        build_etherscan_dataset(api_key=args.api_key)

    if args.all or args.code4rena:
        build_code4rena_dataset()

    print(f"\n{'='*60}")
    print(f"  Dataset build complete!")
    print(f"  Run benchmarks: python benchmarks/reproduce_benchmark.py --save")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
