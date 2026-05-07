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
    python benchmarks/fix_eval.py --skip-rescan --details-output benchmarks/results/paper2_compile_failure_taxonomy.json
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.security.remediation_pipeline import (  # noqa: E402
    compile_contract as compile_contract_evidence,
)
from src.security.remediation_pipeline import (
    remediate_contract,
)

DATASET_CANDIDATES = [
    Path("data/benchmarks/smartbugs-curated/dataset"),
    Path("benchmarks/datasets/smartbugs-curated/dataset"),
]
DATASET = next((path for path in DATASET_CANDIDATES if path.exists()), DATASET_CANDIDATES[0])
MAX_ERROR_CHARS = 2000


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


def compile_contract(sol_path):
    """Compile using the shared Paper 2 remediation pipeline taxonomy."""
    return compile_contract_evidence(Path(sol_path)).to_dict()


def check_compiles(sol_path):
    return compile_contract(sol_path)["compiles"]


def count_high_findings(scan_result):
    if not scan_result:
        return 0
    return sum(1 for f in scan_result.get("findings", [])
               if (f.get("severity") or "").upper() in ("CRITICAL", "HIGH"))


def main():
    parser = argparse.ArgumentParser(description="Fix pipeline evaluation on SmartBugs")
    parser.add_argument("--category", type=str, help="Only evaluate this category")
    parser.add_argument(
        "--details-output",
        type=Path,
        help="Optional JSON path for per-contract Paper 2 remediation details.",
    )
    parser.add_argument(
        "--skip-rescan",
        action="store_true",
        help="Skip post-fix re-scan when only compile taxonomy is needed.",
    )
    args = parser.parse_args()

    categories = sorted([d.name for d in DATASET.iterdir() if d.is_dir()])
    if args.category:
        categories = [args.category]

    print("SmartBugs Fix Pipeline Evaluation")
    print("=" * 65)
    print(f"Dataset: {DATASET}")

    totals = defaultdict(int)
    results_by_cat = {}
    detailed_contracts = []
    compile_failure_taxonomy = defaultdict(int)

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

                # Steps 2-5: shared remediation pipeline
                evidence = remediate_contract(
                    contract_path=sol,
                    results=scan,
                    output_path=fixed_sol,
                    compile_check=True,
                    rescan_check=not args.skip_rescan,
                    no_regression_bound=2,
                )
                if evidence.fixes_applied == 0:
                    cat_results["fix_failed"] += 1
                    continue

                cat_results["fix_applied"] += 1

                compile_result = evidence.compile.to_dict()
                compiles = compile_result["compiles"]
                if compiles:
                    cat_results["fix_compiles"] += 1
                else:
                    compile_failure_taxonomy[compile_result["failure_class"]] += 1

                rescan = evidence.rescan
                total_before = rescan.total_before if rescan.checked else len(scan.get("findings", []))
                high_after = rescan.high_after
                total_after = rescan.total_after
                vuln_eliminated = rescan.eliminated
                no_regression = rescan.no_regression

                if rescan.checked:
                    if vuln_eliminated:
                        cat_results["vuln_eliminated"] += 1
                    if no_regression:
                        cat_results["no_regression"] += 1

                if args.details_output:
                    detailed_contracts.append({
                        "category": cat,
                        "contract": str(sol),
                        "fix_applied": True,
                        "fix_output_summary": (
                            f"shared remediation pipeline: applied={evidence.fixes_applied}, "
                            f"skipped={evidence.fixes_skipped}"
                        )[:MAX_ERROR_CHARS],
                        "high_before": high_before,
                        "high_after": high_after,
                        "total_findings_before": total_before,
                        "total_findings_after": total_after,
                        "vuln_eliminated": vuln_eliminated,
                        "no_regression": no_regression,
                        "compile": compile_result,
                        "evidence": evidence.to_dict(),
                    })

        results_by_cat[cat] = cat_results
        for k, v in cat_results.items():
            totals[k] += v

        n = cat_results["fix_applied"] or 1
        print(f"  {cat:<30} applied={cat_results['fix_applied']:>2} "
              f"compiles={cat_results['fix_compiles']:>2} "
              f"eliminated={cat_results['vuln_eliminated']:>2} "
              f"no_regr={cat_results['no_regression']:>2} "
              f"failed={cat_results['fix_failed']:>2}", flush=True)

    print(f"\n{'TOTAL':<30} applied={totals['fix_applied']:>3} "
          f"compiles={totals['fix_compiles']:>3} "
          f"eliminated={totals['vuln_eliminated']:>3} "
          f"no_regr={totals['no_regression']:>3} "
          f"failed={totals['fix_failed']:>3}")

    n = totals["fix_applied"] or 1
    print("\nRATES:")
    print(f"  Fix application:      {totals['fix_applied']}/{totals['contracts']} contracts with HIGH vulns")
    print(f"  Compilation:          {totals['fix_compiles']}/{n} = {totals['fix_compiles']/n:.0%}")
    print(f"  Vuln elimination:     {totals['vuln_eliminated']}/{n} = {totals['vuln_eliminated']/n:.0%}")
    print(f"  No regression:        {totals['no_regression']}/{n} = {totals['no_regression']/n:.0%}")

    if not args.skip_rescan:
        # Save aggregate results only for full evaluation runs.
        out_path = Path("benchmarks/results/fix_eval_results.json")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        json.dump({"totals": dict(totals), "by_category": results_by_cat}, open(out_path, "w"), indent=2)
        print(f"\nResults saved to {out_path}")
    else:
        print("\nSkipped aggregate fix_eval_results.json update because --skip-rescan was used.")

    if args.details_output:
        details_payload = {
            "artifact": "paper2_fix_eval_contract_details",
            "scope": "Paper 2 remediation only; does not modify Paper 1 detection evidence.",
            "dataset": str(DATASET),
            "totals": dict(totals),
            "by_category": results_by_cat,
            "compile_failure_taxonomy": dict(sorted(compile_failure_taxonomy.items())),
            "contracts": detailed_contracts,
        }
        args.details_output.parent.mkdir(parents=True, exist_ok=True)
        args.details_output.write_text(json.dumps(details_payload, indent=2) + "\n")
        print(f"Details saved to {args.details_output}")


if __name__ == "__main__":
    main()
