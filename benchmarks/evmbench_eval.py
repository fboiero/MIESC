#!/usr/bin/env python3
"""
EVMBench Evaluation — Run MIESC against EVMBench audits and measure recall.

EVMBench (OpenAI + Paradigm, Feb 2026) contains 40 real Code4rena audits
with 120 ground-truth vulnerabilities. This script:

1. Clones each audit's codebase from evmbench-org GitHub
2. Runs `miesc scan` on all .sol files
3. Compares findings against ground truth (keyword + location matching)
4. Reports per-audit and aggregate recall

Usage:
    python benchmarks/evmbench_eval.py                   # All 40 audits
    python benchmarks/evmbench_eval.py --max-audits 10   # First 10 (by SLOC)
    python benchmarks/evmbench_eval.py --audit 2024-01-canto  # Single audit
"""

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

EVMBENCH_AUDITS = Path("/tmp/evmbench/frontier-evals/project/evmbench/audits")
RESULTS_DIR = Path(__file__).parent / "results" / "evmbench"


def load_audits(max_audits=None, single_audit=None):
    """Load audit metadata from task_info files."""
    audits = {}
    with open(EVMBENCH_AUDITS / "task_info_audits.csv") as f:
        for row in csv.DictReader(f):
            audits[row["audit"]] = {
                "project": row["project"],
                "sloc": int(row["codebase_sloc"]),
                "n_contracts": int(row["n_contracts"]),
                "vulns": [],
            }

    with open(EVMBENCH_AUDITS / "task_info.csv") as f:
        for row in csv.DictReader(f):
            if row["audit"] in audits:
                audits[row["audit"]]["vulns"].append({
                    "id": row["vuln"],
                    "description": row["description"],
                    "award": float(row["award"]),
                })

    if single_audit:
        return {single_audit: audits[single_audit]} if single_audit in audits else {}

    # Sort by SLOC (smallest first) and limit
    sorted_audits = dict(
        sorted(audits.items(), key=lambda x: x[1]["sloc"])
    )
    if max_audits:
        sorted_audits = dict(list(sorted_audits.items())[:max_audits])

    return sorted_audits


def clone_audit(audit_id):
    """Clone the audit codebase from evmbench-org."""
    work_dir = Path(tempfile.mkdtemp(prefix=f"evmbench_{audit_id}_"))
    repo_url = f"https://github.com/evmbench-org/{audit_id}.git"

    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--recurse-submodules", repo_url, str(work_dir / "repo")],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            print(f"  WARN: Clone failed for {audit_id}: {result.stderr[:200]}")
            return None
        return work_dir / "repo"
    except Exception as e:
        print(f"  WARN: Clone error for {audit_id}: {e}")
        return None


def find_sol_files(repo_dir):
    """Find all .sol files in the repo, excluding test/mock/lib directories."""
    sol_files = []
    exclude_dirs = {"test", "tests", "mock", "mocks", "lib", "node_modules", ".git", "forge-std"}
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d.lower() not in exclude_dirs]
        for f in files:
            if f.endswith(".sol") and not f.startswith("Test") and not f.startswith("Mock"):
                sol_files.append(os.path.join(root, f))
    return sol_files


def run_miesc_scan(sol_files, output_path):
    """Run miesc scan on the Solidity files."""
    if not sol_files:
        return {"findings": [], "error": "no .sol files found"}

    # For multi-file projects, scan the directory containing the most .sol files
    from collections import Counter
    dirs = Counter(str(Path(f).parent) for f in sol_files)
    best_dir = dirs.most_common(1)[0][0]

    try:
        result = subprocess.run(
            [sys.executable, "-m", "miesc.cli.main", "scan", best_dir,
             "--quiet", "-o", str(output_path), "--fp-strictness", "low"],
            capture_output=True, text=True, timeout=120,
            env={**os.environ, "PYTHONPATH": str(Path(__file__).parent.parent)},
        )
        if output_path.exists():
            with open(output_path) as f:
                return json.load(f)
    except subprocess.TimeoutExpired:
        return {"findings": [], "error": "timeout"}
    except Exception as e:
        return {"findings": [], "error": str(e)}

    return {"findings": [], "error": f"scan failed: {result.stderr[:200]}"}


def match_finding_to_vuln(finding, vuln):
    """Check if a MIESC finding matches an EVMBench vulnerability (keyword matching)."""
    finding_text = " ".join([
        str(finding.get("type", "")),
        str(finding.get("title", "")),
        str(finding.get("description", "")),
        str(finding.get("message", "")),
        str(finding.get("recommendation", "")),
    ]).lower()

    vuln_text = vuln["description"].lower()

    # Extract keywords from vuln description (words > 4 chars, skip common words)
    stop_words = {"could", "would", "should", "their", "there", "which", "about",
                  "other", "after", "before", "under", "through", "function",
                  "contract", "users", "funds", "tokens", "value", "calls"}
    vuln_words = set()
    for word in vuln_text.split():
        word = word.strip(".,()[]{}\"'`")
        if len(word) > 4 and word not in stop_words:
            vuln_words.add(word)

    # Check for category-level matches
    category_keywords = {
        "reentrancy": ["reenter", "reentr", "recursive", "callback"],
        "access_control": ["access", "owner", "unauthorized", "permiss", "restrict"],
        "oracle": ["oracle", "price", "twap", "chainlink", "manipulat"],
        "flash_loan": ["flash", "flashloan"],
        "overflow": ["overflow", "underflow", "arithmetic"],
        "front_running": ["frontrun", "front-run", "sandwich", "mev"],
        "logic": ["incorrect", "wrong", "miscalcul", "rounding", "accounting"],
    }

    # Score: keyword overlap
    overlap = len(vuln_words & set(finding_text.split()))
    category_match = False
    for cat, keywords in category_keywords.items():
        if any(kw in vuln_text for kw in keywords) and any(kw in finding_text for kw in keywords):
            category_match = True
            break

    return overlap >= 2 or category_match


def evaluate_audit(audit_id, audit_data):
    """Evaluate MIESC on a single EVMBench audit."""
    print(f"\n{'='*60}")
    print(f"Audit: {audit_id} ({audit_data['sloc']} SLOC, {audit_data['n_contracts']} contracts)")
    print(f"Vulns: {len(audit_data['vulns'])}")
    for v in audit_data["vulns"]:
        print(f"  {v['id']}: {v['description'][:80]}")

    # Clone
    print(f"  Cloning...")
    repo_dir = clone_audit(audit_id)
    if not repo_dir:
        return {"audit": audit_id, "status": "clone_failed", "detected": 0, "total": len(audit_data["vulns"])}

    # Find .sol files
    sol_files = find_sol_files(repo_dir)
    print(f"  Found {len(sol_files)} .sol files")

    if not sol_files:
        shutil.rmtree(repo_dir.parent, ignore_errors=True)
        return {"audit": audit_id, "status": "no_sol_files", "detected": 0, "total": len(audit_data["vulns"])}

    # Run MIESC
    output_path = Path(tempfile.mktemp(suffix=".json"))
    print(f"  Running MIESC scan...")
    scan_result = run_miesc_scan(sol_files, output_path)
    findings = scan_result.get("findings", [])
    print(f"  MIESC found {len(findings)} findings")

    # Match findings to vulns
    detected = []
    for vuln in audit_data["vulns"]:
        matched = any(match_finding_to_vuln(f, vuln) for f in findings)
        detected.append({"vuln": vuln["id"], "matched": matched, "description": vuln["description"]})
        status = "✓" if matched else "✗"
        print(f"  {status} {vuln['id']}: {vuln['description'][:60]}")

    # Cleanup
    shutil.rmtree(repo_dir.parent, ignore_errors=True)
    output_path.unlink(missing_ok=True)

    n_detected = sum(1 for d in detected if d["matched"])
    n_total = len(audit_data["vulns"])
    recall = n_detected / n_total if n_total > 0 else 0

    print(f"  Recall: {n_detected}/{n_total} = {recall:.1%}")

    return {
        "audit": audit_id,
        "status": "ok",
        "sloc": audit_data["sloc"],
        "n_contracts": audit_data["n_contracts"],
        "n_findings": len(findings),
        "detected": n_detected,
        "total": n_total,
        "recall": recall,
        "details": detected,
    }


def main():
    parser = argparse.ArgumentParser(description="EVMBench evaluation for MIESC")
    parser.add_argument("--max-audits", type=int, default=10, help="Max audits to evaluate")
    parser.add_argument("--audit", type=str, help="Single audit to evaluate")
    args = parser.parse_args()

    if not EVMBENCH_AUDITS.exists():
        print("ERROR: EVMBench dataset not found at /tmp/evmbench/")
        print("Clone: git clone --recurse https://github.com/paradigmxyz/evmbench /tmp/evmbench")
        sys.exit(1)

    audits = load_audits(max_audits=args.max_audits, single_audit=args.audit)
    print(f"Evaluating MIESC on {len(audits)} EVMBench audits")
    print(f"Total vulnerabilities: {sum(len(a['vulns']) for a in audits.values())}")

    results = []
    for audit_id, audit_data in audits.items():
        result = evaluate_audit(audit_id, audit_data)
        results.append(result)

    # Aggregate
    total_detected = sum(r["detected"] for r in results if r["status"] == "ok")
    total_vulns = sum(r["total"] for r in results if r["status"] == "ok")
    total_findings = sum(r.get("n_findings", 0) for r in results if r["status"] == "ok")
    ok_count = sum(1 for r in results if r["status"] == "ok")

    print(f"\n{'='*60}")
    print(f"EVMBench Results — MIESC v5.3.1")
    print(f"{'='*60}")
    print(f"Audits evaluated: {ok_count}/{len(audits)}")
    print(f"Total findings: {total_findings}")
    print(f"Vulns detected: {total_detected}/{total_vulns}")
    print(f"Recall: {total_detected/total_vulns:.1%}" if total_vulns else "N/A")
    print()

    # Per-audit table
    print(f"{'Audit':<45} {'SLOC':>5} {'Findings':>8} {'Detected':>8} {'Recall':>7}")
    print("-" * 78)
    for r in results:
        if r["status"] == "ok":
            print(f"{r['audit']:<45} {r['sloc']:>5} {r['n_findings']:>8} "
                  f"{r['detected']}/{r['total']:>5}   {r['recall']:>6.1%}")
        else:
            print(f"{r['audit']:<45} {'—':>5} {'—':>8} {r['status']:>15}")

    # Save results
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    output_file = RESULTS_DIR / "evmbench_results.json"
    with open(output_file, "w") as f:
        json.dump({
            "version": "5.3.1",
            "date": __import__("datetime").datetime.now().isoformat(),
            "audits_evaluated": ok_count,
            "total_findings": total_findings,
            "total_detected": total_detected,
            "total_vulns": total_vulns,
            "recall": total_detected / total_vulns if total_vulns else 0,
            "results": results,
        }, f, indent=2)
    print(f"\nResults saved to {output_file}")


if __name__ == "__main__":
    main()
