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
    python benchmarks/fix_eval.py --category unchecked_low_level_calls --limit 5 --skip-rescan
    python benchmarks/fix_eval.py --skip-rescan --details-output benchmarks/results/paper2_compile_failure_taxonomy.json
    python benchmarks/fix_eval.py --results-output benchmarks/results/fix_eval_full_dry_20260620_codex.json
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

from src.security.remediation_pipeline import (  # noqa: E402
    compile_contract as compile_contract_evidence,
)
from src.security.remediation_pipeline import (
    remediate_contract,
    select_solc,
)

DATASET_CANDIDATES = [
    Path("data/benchmarks/smartbugs-curated/dataset"),
    Path("benchmarks/datasets/smartbugs-curated/dataset"),
]
DATASET = next((path for path in DATASET_CANDIDATES if path.exists()), DATASET_CANDIDATES[0])
MAX_ERROR_CHARS = 2000
DEFAULT_SCAN_TIMEOUT = 30
DEFAULT_EXTERNAL_TIMEOUT = 30
MAX_EXTERNAL_HIGH_CHECK_EXAMPLES = 3
VOLATILE_TMP_PATH_RE = re.compile(
    r"(?:\.\./)+(?:\.\./)*var/folders/[^\s\"']+/T/tmp[\w.-]+|"
    r"(?:\.\./)+(?:\.\./)*var/folders/[^\s\"']+/T|"
    r"(?:\.\./)+(?:\.\./)*var/folders/[^\s\"']*|"
    r"(?:/private)?/var/folders/[^\s\"']+/T/tmp[\w.-]+|"
    r"(?:/private)?/var/folders/[^\s\"']+/T|"
    r"(?:/private)?/var/folders/[^\s\"']*|"
    r"/tmp/tmp[\w.-]+"
)


def _empty_external_validation(tool="slither", status="not_requested"):
    return {
        "checked": False,
        "tool": tool,
        "status": status,
        "returncode": None,
        "findings_total": None,
        "high_findings": None,
        "high_checks": [],
        "detector_summary": {},
        "stdout": "",
        "stderr": "",
    }


def run_scan(sol_path, output_path, timeout=DEFAULT_SCAN_TIMEOUT):
    env = {
        **os.environ,
        "PYTHONPATH": f"{Path(__file__).parent.parent}:{Path(__file__).parent.parent / 'src'}",
    }
    try:
        subprocess.run(
            [
                sys.executable,
                "-m",
                "miesc.cli.main",
                "scan",
                str(sol_path),
                "-o",
                str(output_path),
                "--quiet",
                "--fp-strictness",
                "low",
            ],
            capture_output=True,
            timeout=timeout,
            env=env,
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


def stabilize_details_payload(value):
    """Remove volatile local paths/timestamps from benchmark detail artifacts."""
    if isinstance(value, dict):
        return {
            key: ("<generated_at>" if key == "generated_at" else stabilize_details_payload(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [stabilize_details_payload(item) for item in value]
    if isinstance(value, str):
        return VOLATILE_TMP_PATH_RE.sub("<tmp>", value)
    return value


def run_external_validation(sol_path, tool="slither", timeout=DEFAULT_EXTERNAL_TIMEOUT):
    """Run an independent validator over a patched Solidity file."""
    if tool == "none":
        return _empty_external_validation(status="disabled")
    if tool != "slither":
        return _empty_external_validation(tool=tool, status="unsupported")

    with tempfile.TemporaryDirectory() as tmp:
        json_output = Path(tmp) / "slither.json"
        cmd = [
            tool,
            str(sol_path),
            "--solc",
            select_solc(Path(sol_path)),
            "--json",
            str(json_output),
        ]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except FileNotFoundError as exc:
            return {
                **_empty_external_validation(tool=tool, status="unavailable"),
                "stderr": str(exc)[:MAX_ERROR_CHARS],
            }
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout if isinstance(exc.stdout, str) else ""
            stderr = exc.stderr if isinstance(exc.stderr, str) else ""
            return {
                **_empty_external_validation(tool=tool, status="timeout"),
                "checked": True,
                "stdout": stdout[:MAX_ERROR_CHARS],
                "stderr": stderr[:MAX_ERROR_CHARS],
            }

        try:
            payload = json.loads(json_output.read_text() if json_output.exists() else "{}")
        except json.JSONDecodeError:
            payload = {}

    detectors = payload.get("results", {}).get("detectors", [])
    high_findings = sum(
        1
        for detector in detectors
        if str(detector.get("impact", "")).lower() in {"high", "critical"}
    )
    high_checks = sorted(
        {
            str(detector.get("check") or "unknown")
            for detector in detectors
            if str(detector.get("impact", "")).lower() in {"high", "critical"}
        }
    )
    detector_summary = defaultdict(int)
    for detector in detectors:
        impact = str(detector.get("impact") or "unknown").lower()
        check = str(detector.get("check") or "unknown")
        detector_summary[f"{impact}:{check}"] += 1
    status = "clean_high" if high_findings == 0 else "findings"
    if result.returncode != 0 and not detectors and not payload.get("success"):
        status = "error"

    return {
        "checked": True,
        "tool": tool,
        "status": status,
        "returncode": result.returncode,
        "findings_total": len(detectors),
        "high_findings": high_findings,
        "high_checks": high_checks,
        "detector_summary": dict(sorted(detector_summary.items())),
        "stdout": result.stdout[:MAX_ERROR_CHARS],
        "stderr": result.stderr[:MAX_ERROR_CHARS],
    }


def count_high_findings(scan_result):
    if not scan_result:
        return 0
    return sum(
        1
        for f in scan_result.get("findings", [])
        if (f.get("severity") or "").upper() in ("CRITICAL", "HIGH")
    )


def main():
    parser = argparse.ArgumentParser(description="Fix pipeline evaluation on SmartBugs")
    parser.add_argument("--category", type=str, help="Only evaluate this category")
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Maximum contracts to evaluate per category. Useful for bounded probes.",
    )
    parser.add_argument(
        "--scan-timeout",
        type=int,
        default=DEFAULT_SCAN_TIMEOUT,
        help=f"Per-contract scan timeout in seconds (default: {DEFAULT_SCAN_TIMEOUT}).",
    )
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable per-contract progress output.",
    )
    parser.add_argument(
        "--details-output",
        type=Path,
        help="Optional JSON path for per-contract Paper 2 remediation details.",
    )
    parser.add_argument(
        "--results-output",
        type=Path,
        help=(
            "Optional JSON path for aggregate results. Use a dated additive path "
            "for non-canonical dry runs."
        ),
    )
    parser.add_argument(
        "--skip-rescan",
        action="store_true",
        help="Skip post-fix re-scan when only compile taxonomy is needed.",
    )
    parser.add_argument(
        "--external-validator",
        choices=("none", "slither"),
        default="none",
        help="Optionally run an independent validator over patched contracts that compile.",
    )
    parser.add_argument(
        "--external-timeout",
        type=int,
        default=DEFAULT_EXTERNAL_TIMEOUT,
        help=(
            "Per patched-contract external validation timeout in seconds "
            f"(default: {DEFAULT_EXTERNAL_TIMEOUT})."
        ),
    )
    args = parser.parse_args()

    categories = sorted([d.name for d in DATASET.iterdir() if d.is_dir()])
    if args.category:
        categories = [args.category]

    print("SmartBugs Fix Pipeline Evaluation")
    print("=" * 65)
    print(f"Dataset: {DATASET}")
    if args.limit is not None:
        print(f"Limit: {args.limit} contract(s) per category")
    print(f"Scan timeout: {args.scan_timeout}s")
    if args.external_validator != "none":
        print(
            f"External validator: {args.external_validator} "
            f"({args.external_timeout}s timeout)"
        )

    totals = defaultdict(int)
    results_by_cat = {}
    detailed_contracts = []
    compile_failure_taxonomy = defaultdict(int)
    external_high_checks = defaultdict(int)
    external_high_check_examples = defaultdict(list)

    for cat in categories:
        cat_dir = DATASET / cat
        if not cat_dir.exists():
            print(f"  {cat:<30} missing category directory: {cat_dir}", flush=True)
            continue
        sol_files = sorted(cat_dir.glob("*.sol"))
        if args.limit is not None:
            sol_files = sol_files[: args.limit]
        cat_results = {
            "contracts": 0,
            "fix_applied": 0,
            "fix_compiles": 0,
            "vuln_eliminated": 0,
            "no_regression": 0,
            "fix_failed": 0,
            "scan_empty": 0,
            "no_high": 0,
            "external_checked": 0,
            "external_clean_high": 0,
            "external_findings": 0,
            "external_errors": 0,
        }

        print(f"\nCategory {cat}: {len(sol_files)} contract(s)", flush=True)

        for idx, sol in enumerate(sol_files, start=1):
            cat_results["contracts"] += 1
            if not args.no_progress:
                print(f"    [{idx}/{len(sol_files)}] scan {sol.name}", flush=True)

            with tempfile.TemporaryDirectory() as tmp:
                tmp = Path(tmp)
                scan_out = tmp / "scan.json"
                fixed_sol = tmp / "fixed.sol"

                # Step 1: Scan
                scan = run_scan(sol, scan_out, timeout=args.scan_timeout)
                if not scan or not scan.get("findings"):
                    cat_results["scan_empty"] += 1
                    if args.details_output:
                        detailed_contracts.append(
                            {
                                "category": cat,
                                "contract": str(sol),
                                "status": "scan_empty",
                                "fix_applied": False,
                                "fix_output_summary": "scan produced no findings",
                                "high_before": 0,
                                "high_after": None,
                                "total_findings_before": 0,
                                "total_findings_after": None,
                                "vuln_eliminated": None,
                                "no_regression": None,
                                "compile": {"checked": False, "compiles": None},
                                "evidence": None,
                            }
                        )
                    continue

                high_before = count_high_findings(scan)
                if high_before == 0:
                    cat_results["no_high"] += 1
                    if args.details_output:
                        detailed_contracts.append(
                            {
                                "category": cat,
                                "contract": str(sol),
                                "status": "no_high",
                                "fix_applied": False,
                                "fix_output_summary": "scan produced no HIGH findings",
                                "high_before": high_before,
                                "high_after": None,
                                "total_findings_before": len(scan.get("findings", [])),
                                "total_findings_after": None,
                                "vuln_eliminated": None,
                                "no_regression": None,
                                "compile": {"checked": False, "compiles": None},
                                "evidence": None,
                            }
                        )
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
                    if args.details_output:
                        detailed_contracts.append(
                            {
                                "category": cat,
                                "contract": str(sol),
                                "status": "fix_failed",
                                "fix_applied": False,
                                "fix_output_summary": (
                                    "shared remediation pipeline: applied=0, "
                                    f"skipped={evidence.fixes_skipped}"
                                )[:MAX_ERROR_CHARS],
                                "high_before": high_before,
                                "high_after": None,
                                "total_findings_before": len(scan.get("findings", [])),
                                "total_findings_after": None,
                                "vuln_eliminated": None,
                                "no_regression": None,
                                "compile": evidence.compile.to_dict(),
                                "evidence": evidence.to_dict(),
                            }
                        )
                    continue

                cat_results["fix_applied"] += 1

                compile_result = evidence.compile.to_dict()
                compiles = compile_result["compiles"]
                if compiles:
                    cat_results["fix_compiles"] += 1
                else:
                    compile_failure_taxonomy[compile_result["failure_class"]] += 1

                external_validation = _empty_external_validation(
                    status=(
                        "not_requested"
                        if args.external_validator == "none"
                        else "skipped_compile_failed"
                    )
                )
                if compiles and args.external_validator != "none":
                    external_validation = run_external_validation(
                        fixed_sol,
                        tool=args.external_validator,
                        timeout=args.external_timeout,
                    )
                    cat_results["external_checked"] += int(external_validation["checked"])
                    cat_results["external_clean_high"] += int(
                        external_validation["status"] == "clean_high"
                    )
                    cat_results["external_findings"] += int(
                        external_validation["status"] == "findings"
                    )
                    cat_results["external_errors"] += int(
                        external_validation["status"]
                        in {"error", "timeout", "unavailable", "unsupported"}
                    )
                    for high_check in external_validation.get("high_checks", []):
                        external_high_checks[high_check] += 1
                        if (
                            len(external_high_check_examples[high_check])
                            < MAX_EXTERNAL_HIGH_CHECK_EXAMPLES
                        ):
                            external_high_check_examples[high_check].append(
                                {
                                    "category": cat,
                                    "contract": str(sol),
                                    "external_status": external_validation["status"],
                                    "high_findings": external_validation["high_findings"],
                                }
                            )

                rescan = evidence.rescan
                total_before = (
                    rescan.total_before if rescan.checked else len(scan.get("findings", []))
                )
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
                    detailed_contracts.append(
                        {
                            "category": cat,
                            "contract": str(sol),
                            "status": "applied",
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
                            "external_validation": external_validation,
                            "evidence": evidence.to_dict(),
                        }
                    )

        results_by_cat[cat] = cat_results
        for k, v in cat_results.items():
            totals[k] += v

        print(
            f"  {cat:<30} applied={cat_results['fix_applied']:>2} "
            f"compiles={cat_results['fix_compiles']:>2} "
            f"eliminated={cat_results['vuln_eliminated']:>2} "
            f"no_regr={cat_results['no_regression']:>2} "
            f"failed={cat_results['fix_failed']:>2} "
            f"empty={cat_results['scan_empty']:>2} "
            f"no_high={cat_results['no_high']:>2}",
            flush=True,
        )

    print(
        f"\n{'TOTAL':<30} applied={totals['fix_applied']:>3} "
        f"compiles={totals['fix_compiles']:>3} "
        f"eliminated={totals['vuln_eliminated']:>3} "
        f"no_regr={totals['no_regression']:>3} "
        f"failed={totals['fix_failed']:>3}"
    )
    if args.external_validator != "none":
        print(
            f"{'':<30} external_checked={totals['external_checked']:>3} "
            f"clean_high={totals['external_clean_high']:>3} "
            f"findings={totals['external_findings']:>3} "
            f"errors={totals['external_errors']:>3}"
        )
        if external_high_checks:
            print("  External HIGH checks:")
            for check, count in sorted(
                external_high_checks.items(), key=lambda item: (-item[1], item[0])
            ):
                print(f"    {check}: {count}")

    n = totals["fix_applied"] or 1
    print("\nRATES:")
    print(
        f"  Fix application:      {totals['fix_applied']}/{totals['contracts']} contracts with HIGH vulns"
    )
    print(
        f"  Compilation:          {totals['fix_compiles']}/{n} = {totals['fix_compiles'] / n:.0%}"
    )
    print(
        f"  Vuln elimination:     {totals['vuln_eliminated']}/{n} = {totals['vuln_eliminated'] / n:.0%}"
    )
    print(
        f"  No regression:        {totals['no_regression']}/{n} = {totals['no_regression'] / n:.0%}"
    )

    external_high_check_summary = dict(
        sorted(external_high_checks.items(), key=lambda item: (-item[1], item[0]))
    )
    external_high_check_example_summary = {
        check: external_high_check_examples[check]
        for check in external_high_check_summary
    }
    aggregate_payload = {
        "totals": dict(totals),
        "by_category": results_by_cat,
        "external_high_checks": external_high_check_summary,
        "external_high_check_examples": external_high_check_example_summary,
    }
    if not args.skip_rescan or args.results_output:
        # Preserve the historical canonical path unless the caller explicitly
        # requests a dated additive artifact for a dry run.
        out_path = args.results_output or Path("benchmarks/results/fix_eval_results.json")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(aggregate_payload, indent=2) + "\n")
        print(f"\nResults saved to {out_path}")
    else:
        print("\nSkipped aggregate fix_eval_results.json update because --skip-rescan was used.")

    if args.details_output:
        details_payload = {
            "artifact": "paper2_fix_eval_contract_details",
            "scope": "Paper 2 remediation only; does not modify Paper 1 detection evidence.",
            "dataset": str(DATASET),
            "limit": args.limit,
            "scan_timeout": args.scan_timeout,
            "skip_rescan": args.skip_rescan,
            "external_validator": args.external_validator,
            "external_timeout": args.external_timeout,
            "totals": dict(totals),
            "by_category": results_by_cat,
            "external_high_checks": external_high_check_summary,
            "external_high_check_examples": external_high_check_example_summary,
            "compile_failure_taxonomy": dict(sorted(compile_failure_taxonomy.items())),
            "contracts": detailed_contracts,
        }
        args.details_output.parent.mkdir(parents=True, exist_ok=True)
        details_payload = stabilize_details_payload(details_payload)
        args.details_output.write_text(json.dumps(details_payload, indent=2) + "\n")
        print(f"Details saved to {args.details_output}")


if __name__ == "__main__":
    main()
