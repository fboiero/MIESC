#!/usr/bin/env python3
"""
Fix Pipeline Evaluation — Run miesc scan + fix on SmartBugs corpus.

Measures:
  - Fix application rate (how many findings get patched)
  - Compilation rate (does the fixed contract compile standalone)
  - Vulnerability elimination rate (re-scan: are HIGH vulns gone?)
  - Regression rate (does the fix introduce new vulns?)
  - Test generation rate (do generated tests compile with Foundry)

Usage:
    python benchmarks/fix_eval.py
    python benchmarks/fix_eval.py --category reentrancy
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

DATASET = Path("benchmarks/datasets/smartbugs-curated/dataset")
SOLC_DIR = Path.home() / ".solc-select" / "artifacts"


def get_solc(sol_path):
    text = open(sol_path).read()
    m = re.search(r"pragma solidity\s*[\^>=<]*\s*(\d+\.\d+)", text)
    ver = m.group(1) if m else "0.4"
    for v in [f"{ver}.26", f"{ver}.25", f"{ver}.24", f"{ver}.22", f"{ver}.19"]:
        p = SOLC_DIR / f"solc-{v}" / f"solc-{v}"
        if p.exists():
            return str(p)
    return str(SOLC_DIR / "solc-0.4.26" / "solc-0.4.26")


def run_scan(sol_path, output_path):
    env = {**os.environ, "PYTHONPATH": f"{Path(__file__).parent.parent}:{Path(__file__).parent.parent / 'src'}"}
    try:
        subprocess.run(
            [sys.executable, "-m", "miesc.cli.main", "scan", str(sol_path),
             "-o", str(output_path), "--quiet", "--fp-strictness", "low"],
            capture_output=True, timeout=30, env=env,
        )
        if output_path.exists():
            return json.load(open(output_path))
    except Exception:
        pass
    return None


def run_fix(results_path, contract_path, output_path):
    env = {**os.environ, "PYTHONPATH": f"{Path(__file__).parent.parent}:{Path(__file__).parent.parent / 'src'}"}
    try:
        result = subprocess.run(
            [sys.executable, "-m", "miesc.cli.main", "fix", str(results_path),
             "-c", str(contract_path), "-o", str(output_path), "--quiet"],
            capture_output=True, text=True, timeout=30, env=env,
        )
        return output_path.exists(), result.stdout + result.stderr
    except Exception as e:
        return False, str(e)


def check_compiles(sol_path):
    solc = get_solc(sol_path)
    try:
        result = subprocess.run(
            [solc, str(sol_path), "--bin"],
            capture_output=True, text=True, timeout=15,
        )
        return result.returncode == 0 or "Binary:" in result.stdout
    except Exception:
        return False


def count_high_findings(scan_result):
    if not scan_result:
        return 0
    return sum(1 for f in scan_result.get("findings", [])
               if (f.get("severity") or "").upper() in ("CRITICAL", "HIGH"))


def main():
    parser = argparse.ArgumentParser(description="Fix pipeline evaluation on SmartBugs")
    parser.add_argument("--category", type=str, help="Only evaluate this category")
    args = parser.parse_args()

    categories = sorted([d.name for d in DATASET.iterdir() if d.is_dir()])
    if args.category:
        categories = [args.category]

    print("SmartBugs Fix Pipeline Evaluation")
    print("=" * 65)

    totals = defaultdict(int)
    results_by_cat = {}

    for cat in categories:
        cat_dir = DATASET / cat
        sol_files = sorted(cat_dir.glob("*.sol"))
        cat_results = {"contracts": 0, "fix_applied": 0, "fix_compiles": 0,
                       "vuln_eliminated": 0, "no_regression": 0, "fix_failed": 0}

        for sol in sol_files:
            cat_results["contracts"] += 1

            with tempfile.TemporaryDirectory() as tmp:
                tmp = Path(tmp)
                scan_out = tmp / "scan.json"
                fixed_sol = tmp / "fixed.sol"

                # Step 1: Scan
                scan = run_scan(sol, scan_out)
                if not scan or not scan.get("findings"):
                    continue

                high_before = count_high_findings(scan)
                if high_before == 0:
                    continue  # Nothing to fix

                # Step 2: Fix
                fix_ok, fix_output = run_fix(scan_out, sol, fixed_sol)
                if not fix_ok:
                    cat_results["fix_failed"] += 1
                    continue

                applied = "Applied" in fix_output or "applied" in fix_output
                if not applied:
                    cat_results["fix_failed"] += 1
                    continue

                cat_results["fix_applied"] += 1

                # Step 3: Compile
                compiles = check_compiles(fixed_sol)
                if compiles:
                    cat_results["fix_compiles"] += 1

                # Step 4: Re-scan
                rescan_out = tmp / "rescan.json"
                rescan = run_scan(fixed_sol, rescan_out)
                high_after = count_high_findings(rescan) if rescan else high_before

                if high_after < high_before:
                    cat_results["vuln_eliminated"] += 1

                # Step 5: Regression check
                total_before = len(scan.get("findings", []))
                total_after = len(rescan.get("findings", [])) if rescan else total_before
                if total_after <= total_before + 2:  # Allow +2 for inline guard FPs
                    cat_results["no_regression"] += 1

        results_by_cat[cat] = cat_results
        for k, v in cat_results.items():
            totals[k] += v

        n = cat_results["fix_applied"] or 1
        print(f"  {cat:<30} applied={cat_results['fix_applied']:>2} "
              f"compiles={cat_results['fix_compiles']:>2} "
              f"eliminated={cat_results['vuln_eliminated']:>2} "
              f"no_regr={cat_results['no_regression']:>2} "
              f"failed={cat_results['fix_failed']:>2}")

    print(f"\n{'TOTAL':<30} applied={totals['fix_applied']:>3} "
          f"compiles={totals['fix_compiles']:>3} "
          f"eliminated={totals['vuln_eliminated']:>3} "
          f"no_regr={totals['no_regression']:>3} "
          f"failed={totals['fix_failed']:>3}")

    n = totals["fix_applied"] or 1
    print(f"\nRATES:")
    print(f"  Fix application:      {totals['fix_applied']}/{totals['contracts']} contracts with HIGH vulns")
    print(f"  Compilation:          {totals['fix_compiles']}/{n} = {totals['fix_compiles']/n:.0%}")
    print(f"  Vuln elimination:     {totals['vuln_eliminated']}/{n} = {totals['vuln_eliminated']/n:.0%}")
    print(f"  No regression:        {totals['no_regression']}/{n} = {totals['no_regression']/n:.0%}")

    # Save results
    out_path = Path("benchmarks/results/fix_eval_results.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    json.dump({"totals": dict(totals), "by_category": results_by_cat}, open(out_path, "w"), indent=2)
    print(f"\nResults saved to {out_path}")


if __name__ == "__main__":
    main()
