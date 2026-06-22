#!/usr/bin/env python3
"""
MIESC - Dataset Builder for Benchmark Evaluation
=================================================

Downloads and prepares four evaluation datasets:
  A) Etherscan verified contracts (5000+ real-world)
  B) Rekt.news exploits (200+ with confirmed vulnerabilities)
  C) Code4rena audit contests (validated findings as ground truth)
  D) SmartBugs-curated (143 contracts with line-level ground truth) — the labeled
     corpus used by benchmarks/smartbugs_evaluation.py and the wild benign-context
     verifier eval (scripts/wild_benign_context_eval.py --ground-truth).

Usage:
    python benchmarks/build_datasets.py --all
    python benchmarks/build_datasets.py --rekt
    python benchmarks/build_datasets.py --etherscan --api-key YOUR_KEY
    python benchmarks/build_datasets.py --code4rena
    python benchmarks/build_datasets.py --smartbugs

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
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
DATA_DIR = PROJECT_ROOT / "data" / "datasets"
# External labeled corpora live here (gitignored — fetched, never committed).
DATASETS_DIR = PROJECT_ROOT / "benchmarks" / "datasets"


def _clone_shallow(repo_url: str, dest: Path, timeout: int = 600) -> bool:
    """Shallow-clone repo_url into dest (pull if it's already a git checkout). Returns ok."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    if (dest / ".git").exists():
        print("  already cloned, pulling updates...")
        subprocess.run(["git", "-C", str(dest), "pull", "--ff-only"],
                       capture_output=True, timeout=120)
        return True
    if dest.exists() and any(dest.iterdir()):
        print(f"  {dest} exists but is not a git checkout — leaving contents in place")
        return True
    print(f"  cloning {repo_url} (shallow)...")
    r = subprocess.run(["git", "clone", "--depth", "1", repo_url, str(dest)],
                       capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        print(f"  ERROR: git clone failed: {r.stderr.strip()[:300]}")
        return False
    return True


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
# Option D: SmartBugs-curated (labeled ground-truth corpus)
# ============================================================================

def build_smartbugs_curated():
    """Clone SmartBugs-curated — 143 contracts with line-level vulnerability labels.

    This is the labeled corpus the rest of the toolchain expects:
      - benchmarks/smartbugs_evaluation.py reads <dest>/vulnerabilities.json
      - scripts/wild_benign_context_eval.py --ground-truth uses the same file to anchor
        the recall-critical REAL label (no LLM, no circularity).

    Cloned into benchmarks/datasets/smartbugs-curated (where smartbugs_evaluation.py:33
    looks), NOT data/datasets — the two paths differ in this repo by design.
    """
    repo_url = "https://github.com/smartbugs/smartbugs-curated.git"
    dest = DATASETS_DIR / "smartbugs-curated"

    print(f"\n{'='*60}")
    print(f"  Building SmartBugs-curated Dataset (labeled ground truth)")
    print(f"  Source: {repo_url}")
    print(f"{'='*60}\n")

    _clone_shallow(repo_url, dest)

    # The repo vendors only dataset/*.sol; the labels file may be missing. Fetch it directly
    # so --ground-truth works (smartbugs_evaluation.py:104 also reads this exact path).
    vuln_file = dest / "vulnerabilities.json"
    if not vuln_file.exists():
        raw = "https://raw.githubusercontent.com/smartbugs/smartbugs-curated/main/vulnerabilities.json"
        print("  vulnerabilities.json missing — fetching labels directly...")
        try:
            dest.mkdir(parents=True, exist_ok=True)
            urllib.request.urlretrieve(raw, vuln_file)
        except Exception as e:  # noqa: BLE001
            print(f"  WARNING: could not fetch vulnerabilities.json: {e}")

    sol_count = len(list(dest.rglob("*.sol")))
    if vuln_file.exists():
        try:
            labeled = len(json.load(open(vuln_file)))
        except Exception:
            labeled = "?"
        print(f"  Ground truth: {vuln_file} ({labeled} labeled contracts)")
    else:
        print("  WARNING: vulnerabilities.json unavailable — ground-truth anchoring disabled")
    print(f"  Total contracts in dataset: {sol_count}")
    print(f"  Ready for: scripts/wild_benign_context_eval.py collect "
          f"{dest / 'dataset'} --ground-truth {vuln_file}")


# ============================================================================
# Options E-G: line-level labeled corpora for the wild benign-context eval
# (consumed via scripts/dataset_adapters.py — see docs/research/DATASET_SOURCE_CLASSIFICATION.md)
# ============================================================================

def _build_labeled(name: str, repo_url: str, dest_name: str, adapter: str, sub: str = "") -> None:
    """Clone a line-level labeled corpus and print the adapter command to convert it."""
    dest = DATASETS_DIR / dest_name
    print(f"\n{'='*60}")
    print(f"  Building {name} (line-level labeled corpus)")
    print(f"  Source: {repo_url}")
    print(f"{'='*60}\n")
    if not _clone_shallow(repo_url, dest):
        return
    sol_count = len(list(dest.rglob("*.sol")))
    print(f"  Cloned to: {dest} ({sol_count} .sol files)")
    src = dest / sub if sub else dest
    out_corpus = DATASETS_DIR / "_adapted" / f"{dest_name}_corpus"
    out_gt = DATASETS_DIR / "_adapted" / f"{dest_name}_gt.json"
    print(f"  Convert to ground truth with:\n"
          f"    python3 scripts/dataset_adapters.py {adapter} {src} \\\n"
          f"      --out-corpus {out_corpus} --out-gt {out_gt}")


def build_fsalzano_dataset() -> None:
    _build_labeled(
        "fsalzano line-level (real, manual human labels + clean negatives)",
        "https://github.com/fsalzano/Empirical-Analysis-of-Vulnerability-Detection-Tools-for-Solidity-Smart-Contracts.git",
        "fsalzano", "fsalzano")


def build_solidifi_dataset() -> None:
    _build_labeled(
        "SolidiFI-benchmark (injected bugs, exact location logs)",
        "https://github.com/DependableSystemsLab/SolidiFI-benchmark.git",
        "solidifi-benchmark", "solidifi")


def build_dappscan_dataset() -> None:
    _build_labeled(
        "DAppSCAN (real audit reports, SWC line-level)",
        "https://github.com/InPlusLab/DAppSCAN.git",
        "dappscan", "dappscan")


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="MIESC Dataset Builder")
    parser.add_argument("--all", action="store_true", help="Build all datasets")
    parser.add_argument("--rekt", action="store_true", help="Build Rekt exploits dataset")
    parser.add_argument("--etherscan", action="store_true", help="Build Etherscan dataset")
    parser.add_argument("--code4rena", action="store_true", help="Build Code4rena dataset")
    parser.add_argument("--smartbugs", action="store_true",
                        help="Build SmartBugs-curated (labeled ground-truth corpus)")
    parser.add_argument("--fsalzano", action="store_true",
                        help="Build fsalzano line-level dataset (real, manual human labels)")
    parser.add_argument("--solidifi", action="store_true",
                        help="Build SolidiFI-benchmark (injected bugs, exact locations)")
    parser.add_argument("--dappscan", action="store_true",
                        help="Build DAppSCAN (real audit reports, SWC line-level)")
    parser.add_argument("--labeled", action="store_true",
                        help="Build all line-level labeled corpora (smartbugs+fsalzano+solidifi+dappscan)")
    parser.add_argument("--api-key", help="Etherscan API key")
    args = parser.parse_args()

    if not any([args.all, args.rekt, args.etherscan, args.code4rena, args.smartbugs,
                args.fsalzano, args.solidifi, args.dappscan, args.labeled]):
        args.all = True

    if args.all or args.rekt:
        build_rekt_dataset()

    if args.all or args.etherscan:
        build_etherscan_dataset(api_key=args.api_key)

    if args.all or args.code4rena:
        build_code4rena_dataset()

    if args.all or args.labeled or args.smartbugs:
        build_smartbugs_curated()

    if args.all or args.labeled or args.fsalzano:
        build_fsalzano_dataset()

    if args.all or args.labeled or args.solidifi:
        build_solidifi_dataset()

    if args.all or args.labeled or args.dappscan:
        build_dappscan_dataset()

    print(f"\n{'='*60}")
    print(f"  Dataset build complete!")
    print(f"  Run benchmarks: python benchmarks/reproduce_benchmark.py --save")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
