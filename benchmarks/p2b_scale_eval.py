#!/usr/bin/env python3
"""P2-B — At-scale evaluation of the Paper 2 generation contributions.

Paper 2's biggest reviewer objection: three of its five contributions
(test generation, spec generation, compliance mapping) are evaluated on a
SINGLE contract. This harness runs them over a stratified sample of the
SmartBugs-curated corpus and reports rates, converting anecdote into evidence.

Per contract the pipeline is:
    scan → test-gen → specs (smtchecker) → compliance

Metrics
-------
Robust / deterministic (measured here, no external solver needed):
  * tests_generated_rate   — % contracts where `test-gen` emitted a test file
  * specs_generated_rate   — % contracts where `specs` emitted a spec file
  * compliance_coverage    — mean (mapped findings / total findings)

Toolchain-dependent (NOT yet implemented — see _toolchain_compile_check /
_toolchain_discharge_check; they return None = 'unmeasured' so the harness never
fabricates a false 0%). Implementing them needs a real Foundry project and a
merged SMTChecker contract, validated on a free machine:
  * tests_compile_rate     — % generated tests that compile (forge)
  * specs_discharge_rate   — % specs SMTChecker can process (solc model-checker)

Additive: writes a dated JSON, never overwrites frozen Paper 2 artifacts.

Usage:
    # generation + compliance only (safe to run anytime, CPU-light for compliance;
    # scan still needs solc so prefer running with the corpus solc available):
    python benchmarks/p2b_scale_eval.py --sample 25

    # full run with compile/discharge, once the machine is free:
    PATH="$HOME/Library/Python/3.9/bin:$PATH" \\
      python benchmarks/p2b_scale_eval.py --sample 25 --with-toolchain

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL-3.0
"""

import argparse
import json
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from benchmarks.reproduce_benchmark import find_dataset, get_contracts_by_category  # noqa: E402

RESULTS_DIR = PROJECT_ROOT / "benchmarks" / "results"
CLI = [sys.executable, "-m", "miesc.cli.main"]


def stratified_sample(contracts_by_cat, n):
    """Pick ~n contracts spread across categories (round-robin for balance)."""
    buckets = {c: list(files) for c, files in contracts_by_cat.items()}
    picked = []
    while len(picked) < n and any(buckets.values()):
        for cat in list(buckets):
            if buckets[cat]:
                picked.append((cat, buckets[cat].pop(0)))
                if len(picked) >= n:
                    break
    return picked


def run(cmd, timeout):
    """Run a CLI subcommand; return (ok, stdout+stderr)."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode == 0, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return False, "TIMEOUT"
    except Exception as e:  # noqa: BLE001
        return False, f"ERROR: {e}"


def compliance_coverage(comp_json_path):
    """mapped findings / total findings from a compliance JSON, or None."""
    try:
        data = json.loads(Path(comp_json_path).read_text())
    except Exception:  # noqa: BLE001
        return None
    mapped = data.get("mappings") or data.get("mapped") or []
    total = data.get("total_findings")
    if total is None:
        total = data.get("findings_count")
    if total is None:  # cannot compute a ratio without a denominator
        return None
    return (len(mapped) / total) if total else 0.0


def eval_contract(sol_path, workdir, scan_timeout, with_toolchain):
    """Run the P2-B pipeline for one contract; return a per-contract record."""
    rec = {"contract": str(sol_path), "scan_ok": False,
           "test_generated": False, "spec_generated": False,
           "compliance_coverage": None,
           "test_compiles": None, "spec_discharges": None}

    scan_json = workdir / "scan.json"
    rec["scan_ok"], _ = run(CLI + ["scan", str(sol_path), "-o", str(scan_json),
                                   "--quiet", "--fp-strictness", "low"], scan_timeout)
    if not rec["scan_ok"] or not scan_json.exists():
        return rec

    test_dir = workdir / "tests"
    ok, _ = run(CLI + ["test-gen", str(scan_json), "-c", str(sol_path),
                       "-o", str(test_dir), "--quiet"], 120)
    rec["test_generated"] = ok and test_dir.exists() and any(test_dir.rglob("*.sol"))

    spec_file = workdir / "spec.sol"
    ok, _ = run(CLI + ["specs", str(scan_json), "-f", "smtchecker",
                       "-o", str(spec_file), "--quiet"], 120)
    rec["spec_generated"] = ok and spec_file.exists()

    comp_json = workdir / "comp.json"
    ok, _ = run(CLI + ["compliance", str(scan_json), "-f", "json",
                       "-o", str(comp_json), "--quiet"], 60)
    if ok and comp_json.exists():
        rec["compliance_coverage"] = compliance_coverage(comp_json)

    if with_toolchain:
        # NOTE (anti-artifact): a naive `forge build <file>` / `solc <asserts>`
        # ALWAYS fails — a Foundry test needs a project (foundry.toml + forge-std
        # + the contract under src/), and the SMTChecker spec is annotations that
        # must be merged into the contract. A blind run would report a FALSE 0%
        # compile/discharge rate. Until these are implemented against a real
        # project on a free machine, leave them UNMEASURED (None), never False.
        rec["test_compiles"] = _toolchain_compile_check(test_dir, sol_path) if rec["test_generated"] else None
        rec["spec_discharges"] = _toolchain_discharge_check(spec_file, sol_path) if rec["spec_generated"] else None

    return rec


def _toolchain_compile_check(test_dir, sol_path):
    """Return True/False if a real Foundry compile check runs, else None.

    Not yet implemented: needs a minimal Foundry project (foundry.toml, forge-std,
    the contract under src/, the generated test under test/) and `forge build`.
    Returning None keeps the metric honestly 'unmeasured' rather than a false 0%.
    """
    return None


def _toolchain_discharge_check(spec_file, sol_path):
    """Return True/False if a real SMTChecker discharge check runs, else None.

    Not yet implemented: the `specs -f smtchecker` output is annotations that must
    be merged into the contract before `solc --model-checker-engine chc` can run.
    Returning None keeps the metric honestly 'unmeasured' rather than a false 0%.
    """
    return None


def main():
    ap = argparse.ArgumentParser(description="P2-B at-scale evaluation")
    ap.add_argument("--sample", type=int, default=25, help="contracts to sample (default: 25)")
    ap.add_argument("--scan-timeout", type=int, default=30)
    ap.add_argument("--with-toolchain", action="store_true",
                    help="also run forge/solc compile & SMTChecker discharge checks")
    ap.add_argument("--save", action="store_true", default=True)
    args = ap.parse_args()

    dataset = find_dataset()
    sample = stratified_sample(get_contracts_by_category(dataset), args.sample)
    print(f"P2-B at-scale eval: {len(sample)} contracts "
          f"(toolchain={'on' if args.with_toolchain else 'off'})")
    if args.with_toolchain:
        print("  WARNING: compile/discharge checks are stubs (report None, not 0%). "
              "Implement _toolchain_*_check against a real project before trusting them.")

    records = []
    for i, (cat, sol) in enumerate(sample, 1):
        print(f"  [{i}/{len(sample)}] {cat}/{Path(sol).name}")
        with tempfile.TemporaryDirectory() as td:
            records.append(eval_contract(Path(sol), Path(td), args.scan_timeout,
                                         args.with_toolchain))

    n = len(records)
    def rate(key):
        vals = [r[key] for r in records if r[key] is not None]
        return (sum(bool(v) for v in vals) / len(vals)) if vals else None
    covs = [r["compliance_coverage"] for r in records if r["compliance_coverage"] is not None]

    summary = {
        "contracts": n,
        "tests_generated_rate": rate("test_generated"),
        "specs_generated_rate": rate("spec_generated"),
        "compliance_coverage_mean": (sum(covs) / len(covs)) if covs else None,
        "tests_compile_rate": rate("test_compiles"),
        "specs_discharge_rate": rate("spec_discharges"),
    }

    print("\n=== P2-B SUMMARY ===")
    for k, v in summary.items():
        shown = f"{v:.1%}" if isinstance(v, float) else ("not measured" if v is None else str(v))
        print(f"  {k:<26} {shown}")

    if args.save:
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = RESULTS_DIR / f"p2b_scale_eval_{ts}.json"
        out.write_text(json.dumps({"timestamp": ts, "summary": summary,
                                   "records": records}, indent=2) + "\n")
        print(f"\n  Saved to: {out}")


if __name__ == "__main__":
    main()
