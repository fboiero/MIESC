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
import re
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

DATASET_CANDIDATES = [
    Path("data/benchmarks/smartbugs-curated/dataset"),
    Path("benchmarks/datasets/smartbugs-curated/dataset"),
]
DATASET = next((path for path in DATASET_CANDIDATES if path.exists()), DATASET_CANDIDATES[0])
SOLC_DIR = Path.home() / ".solc-select" / "artifacts"
MAX_ERROR_CHARS = 2000


def get_solc(sol_path):
    text = open(sol_path).read()
    m = re.search(r"pragma solidity\s*([^;]+);", text)
    constraint = m.group(1).strip() if m else ""
    exact = re.fullmatch(r"(\d+\.\d+\.\d+)", constraint)
    if exact:
        candidates = [exact.group(1)]
    else:
        version = re.search(r"(\d+\.\d+)(?:\.(\d+))?", constraint)
        if version and version.group(2):
            base = version.group(1)
            candidates = [f"{base}.{version.group(2)}"]
        else:
            ver = version.group(1) if version else "0.4"
            candidates = [f"{ver}.26", f"{ver}.25", f"{ver}.24", f"{ver}.23", f"{ver}.22", f"{ver}.19"]

    for v in candidates:
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


def classify_compile_failure(stderr, stdout=""):
    text = f"{stderr}\n{stdout}".lower()
    if "source file requires different compiler version" in text or "requires different compiler version" in text:
        return "solidity_version_mismatch"
    if "source \"" in text and "not found" in text:
        return "missing_import_or_dependency"
    if "file not found" in text or "no such file" in text:
        return "missing_import_or_dependency"
    if "undeclared identifier" in text or "identifier not found" in text or "not found or not visible" in text:
        return "undefined_symbol"
    if "parsererror" in text:
        return "parser_or_syntax_error"
    if "typeerror" in text:
        return "type_error"
    if "timeout" in text:
        return "compile_timeout"
    if "not found" in text and "solc" in text:
        return "solc_unavailable"
    return "other_compile_error"


def compile_contract(sol_path):
    solc = get_solc(sol_path)
    try:
        result = subprocess.run(
            [solc, str(sol_path), "--bin"],
            capture_output=True, text=True, timeout=15,
        )
        compiles = result.returncode == 0 or "Binary:" in result.stdout
        return {
            "compiles": compiles,
            "solc": solc,
            "returncode": result.returncode,
            "stdout": result.stdout[:MAX_ERROR_CHARS],
            "stderr": result.stderr[:MAX_ERROR_CHARS],
            "failure_class": None if compiles else classify_compile_failure(result.stderr, result.stdout),
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "compiles": False,
            "solc": solc,
            "returncode": None,
            "stdout": (exc.stdout or "")[:MAX_ERROR_CHARS] if isinstance(exc.stdout, str) else "",
            "stderr": "compile timeout",
            "failure_class": "compile_timeout",
        }
    except Exception as exc:
        return {
            "compiles": False,
            "solc": solc,
            "returncode": None,
            "stdout": "",
            "stderr": str(exc)[:MAX_ERROR_CHARS],
            "failure_class": classify_compile_failure(str(exc)),
        }


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
                compile_result = compile_contract(fixed_sol)
                compiles = compile_result["compiles"]
                if compiles:
                    cat_results["fix_compiles"] += 1
                else:
                    compile_failure_taxonomy[compile_result["failure_class"]] += 1

                total_before = len(scan.get("findings", []))
                high_after = None
                total_after = None
                vuln_eliminated = None
                no_regression = None

                if not args.skip_rescan:
                    # Step 4: Re-scan
                    rescan_out = tmp / "rescan.json"
                    rescan = run_scan(fixed_sol, rescan_out)
                    high_after = count_high_findings(rescan) if rescan else high_before

                    vuln_eliminated = high_after < high_before
                    if vuln_eliminated:
                        cat_results["vuln_eliminated"] += 1

                    # Step 5: Regression check
                    total_after = len(rescan.get("findings", [])) if rescan else total_before
                    no_regression = total_after <= total_before + 2
                    if no_regression:  # Allow +2 for inline guard FPs
                        cat_results["no_regression"] += 1

                if args.details_output:
                    detailed_contracts.append({
                        "category": cat,
                        "contract": str(sol),
                        "fix_applied": True,
                        "fix_output_summary": fix_output[:MAX_ERROR_CHARS],
                        "high_before": high_before,
                        "high_after": high_after,
                        "total_findings_before": total_before,
                        "total_findings_after": total_after,
                        "vuln_eliminated": vuln_eliminated,
                        "no_regression": no_regression,
                        "compile": compile_result,
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
