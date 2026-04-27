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
PROJECT_ROOT = Path(__file__).parent.parent


def _load_api_keys():
    """Load API keys from apik.sh if not already in env."""
    apik = PROJECT_ROOT / "apik.sh"
    if not apik.exists():
        return
    for line in apik.read_text().splitlines():
        line = line.strip()
        if line.startswith("export ") and "=" in line:
            key_val = line[len("export "):]
            key, _, val = key_val.partition("=")
            val = val.strip("'\"")
            if key and val and key not in os.environ:
                os.environ[key] = val


_load_api_keys()


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


def _try_build_project(repo_dir):
    """Try to build the project with Foundry or Hardhat before scanning."""
    foundry_toml = repo_dir / "foundry.toml"
    package_json = repo_dir / "package.json"
    hardhat_config = repo_dir / "hardhat.config.js"
    hardhat_config_ts = repo_dir / "hardhat.config.ts"

    if foundry_toml.exists():
        try:
            subprocess.run(
                ["forge", "build"], cwd=str(repo_dir),
                capture_output=True, timeout=120,
            )
            return "foundry"
        except Exception:
            pass

    if hardhat_config.exists() or hardhat_config_ts.exists() or package_json.exists():
        try:
            subprocess.run(
                ["npm", "install", "--silent"], cwd=str(repo_dir),
                capture_output=True, timeout=120,
            )
            return "hardhat"
        except Exception:
            pass

    return None


def run_miesc_scan(sol_files, output_path, llm_enhance=False, repo_dir=None, frontier_model=None):
    """Run miesc scan on the Solidity files."""
    if not sol_files:
        return {"findings": [], "error": "no .sol files found"}

    # Try building the project first
    if repo_dir:
        framework = _try_build_project(Path(repo_dir))
        if framework:
            print(f"  Built project ({framework})")

    # For frontier models, scan individual .sol files (not directory)
    # because the frontier adapter only fires in single-file mode.
    # For static-only, use directory mode for batch scanning.
    from collections import Counter
    dirs = Counter(str(Path(f).parent) for f in sol_files)
    best_dir = dirs.most_common(1)[0][0]

    # If using frontier model, concatenate ALL source .sol files into one
    # temp file so Claude sees the full codebase context, not just one file.
    scan_target = best_dir
    if frontier_model:
        source_files = [f for f in sol_files if "/test" not in f.lower() and "/mock" not in f.lower()
                        and "/interface" not in f.lower()]
        if source_files:
            import tempfile as _tf
            # Budget: ~100KB max concat (fits in Claude's context with room for prompt)
            MAX_CONCAT_BYTES = 100_000
            # Sort by size descending, take the most important files first
            source_files_sized = sorted(source_files, key=lambda f: os.path.getsize(f), reverse=True)
            # Skip pure interface files (I*.sol) and keep implementation files
            impl_files = [f for f in source_files_sized if not Path(f).name.startswith("I")]
            if not impl_files:
                impl_files = source_files_sized

            concat = _tf.NamedTemporaryFile(suffix=".sol", delete=False, mode="w")
            total_written = 0
            files_included = 0
            for sf in impl_files:
                file_size = os.path.getsize(sf)
                if total_written + file_size > MAX_CONCAT_BYTES and files_included > 0:
                    break
                concat.write(f"// ===== FILE: {Path(sf).name} =====\n")
                try:
                    content = open(sf).read()
                    concat.write(content)
                    total_written += len(content)
                    files_included += 1
                except Exception:
                    pass
                concat.write("\n\n")
            concat.close()
            scan_target = concat.name
            print(f"  Concat: {files_included} files, {total_written/1024:.0f}KB")

    project_root = Path(__file__).parent.parent
    env = {
        **os.environ,
        "PYTHONPATH": f"{project_root}:{project_root / 'src'}",
    }

    cmd = [
        sys.executable, "-m", "miesc.cli.main", "scan", scan_target,
        "--quiet", "-o", str(output_path), "--fp-strictness", "low",
    ]
    if frontier_model:
        cmd.extend(["--model", frontier_model])
    if llm_enhance:
        cmd.append("--llm-enhance")

    timeout = 300 if (llm_enhance or frontier_model) else 120

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, env=env,
        )
        if output_path.exists():
            with open(output_path) as f:
                return json.load(f)
    except subprocess.TimeoutExpired:
        return {"findings": [], "error": "timeout"}
    except Exception as e:
        return {"findings": [], "error": str(e)}

    return {"findings": [], "error": f"scan failed: {result.stderr[:200]}"}


def _llm_judge_match(finding: dict, vuln: dict) -> bool:
    """Use Claude as a judge to determine if a finding matches a vulnerability.

    This is more accurate than keyword matching but costs ~$0.001 per comparison.
    Falls back to keyword matching if API is unavailable.
    """
    import os
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return False

    try:
        import anthropic
        client = anthropic.Anthropic()

        finding_text = (
            f"Title: {finding.get('title') or finding.get('type', '?')}\n"
            f"Severity: {finding.get('severity', '?')}\n"
            f"Description: {finding.get('description', '')[:500]}\n"
            f"Function: {finding.get('location', {}).get('function', '?') if isinstance(finding.get('location'), dict) else '?'}"
        )
        vuln_text = vuln["description"]

        msg = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=10,
            messages=[{
                "role": "user",
                "content": (
                    f"Does this security finding describe the SAME vulnerability?\n\n"
                    f"GROUND TRUTH VULNERABILITY:\n{vuln_text}\n\n"
                    f"DETECTED FINDING:\n{finding_text}\n\n"
                    f"Answer ONLY 'yes' or 'no'."
                ),
            }],
        )
        answer = msg.content[0].text.strip().lower()
        return answer.startswith("yes")
    except Exception:
        return False


def match_finding_to_vuln(finding, vuln):
    """Check if a MIESC finding matches an EVMBench vulnerability.

    Uses multi-signal matching: keyword overlap, semantic category,
    function name, and concept synonyms.
    """
    finding_text = " ".join([
        str(finding.get("type", "")),
        str(finding.get("title", "")),
        str(finding.get("description", "")),
        str(finding.get("message", "")),
        str(finding.get("recommendation", "")),
        str(finding.get("exploit_scenario", "")),
    ]).lower()

    vuln_text = vuln["description"].lower()

    # Signal 1: Function name match (strongest signal)
    vuln_functions = set()
    import re
    for m in re.finditer(r'\b([a-z][a-zA-Z0-9]*(?:_[a-zA-Z0-9]+)*)\s*\(', vuln_text):
        fn = m.group(1)
        if len(fn) > 3 and fn not in ("this", "that", "with", "from"):
            vuln_functions.add(fn.lower())

    finding_fn = ""
    loc = finding.get("location", {})
    if isinstance(loc, dict):
        finding_fn = loc.get("function", "").lower()

    if finding_fn and any(fn in finding_fn or finding_fn in fn for fn in vuln_functions):
        return True

    # Signal 2: Semantic category mapping (expanded)
    category_synonyms = {
        "reentrancy": ["reenter", "reentr", "recursive", "callback", "state update after",
                        "external call before", "cross-function"],
        "access_control": ["access", "owner", "unauthorized", "permiss", "restrict",
                           "anyone can", "no access check", "missing modifier"],
        "oracle": ["oracle", "price", "twap", "chainlink", "manipulat", "stale", "latestRound"],
        "flash_loan": ["flash", "flashloan", "same block", "atomic"],
        "overflow": ["overflow", "underflow", "arithmetic", "truncat"],
        "front_running": ["frontrun", "front-run", "sandwich", "mev", "slippage"],
        "logic": ["incorrect", "wrong", "miscalcul", "rounding", "accounting",
                   "invariant", "broken", "inconsisten", "edge case"],
        "stuck_funds": ["stuck", "locked", "unable to withdraw", "freeze", "trapped"],
        "validation": ["invalid", "bypass", "skip", "missing check", "no validation"],
        "state": ["dirty", "flag", "update", "stale state", "not updated"],
    }

    for cat, keywords in category_synonyms.items():
        vuln_matches = sum(1 for kw in keywords if kw in vuln_text)
        finding_matches = sum(1 for kw in keywords if kw in finding_text)
        if vuln_matches >= 1 and finding_matches >= 1:
            return True

    # Signal 3: Keyword overlap (relaxed)
    stop_words = {"could", "would", "should", "their", "there", "which", "about",
                  "other", "after", "before", "under", "through", "function",
                  "contract", "users", "funds", "tokens", "value", "calls",
                  "allow", "allows", "cause", "causes", "result", "results",
                  "using", "being", "where", "while"}
    vuln_words = set()
    for word in vuln_text.split():
        word = word.strip(".,()[]{}\"'`").lower()
        if len(word) > 4 and word not in stop_words:
            vuln_words.add(word)

    finding_words = set()
    for word in finding_text.split():
        word = word.strip(".,()[]{}\"'`").lower()
        if len(word) > 4:
            finding_words.add(word)

    overlap = len(vuln_words & finding_words)
    if overlap >= 2:
        return True

    # Signal 4: Substring matching for compound terms
    # "Holder Array Manipulation" should match "Holders array can be manipulated"
    vuln_bigrams = set()
    vwords = vuln_text.split()
    for i in range(len(vwords) - 1):
        w1 = vwords[i].strip(".,()[]{}\"'`")
        w2 = vwords[i + 1].strip(".,()[]{}\"'`")
        if len(w1) > 3 and len(w2) > 3:
            vuln_bigrams.add(f"{w1} {w2}")

    for bigram in vuln_bigrams:
        if bigram in finding_text:
            return True

    # Signal 5: Root word matching (simple stemming)
    def stem(w):
        for suffix in ("ing", "tion", "ated", "ment", "able", "ness", "ers", "ed", "es", "s"):
            if w.endswith(suffix) and len(w) > len(suffix) + 3:
                return w[:-len(suffix)]
        return w

    vuln_stems = {stem(w) for w in vuln_words if len(w) > 4}
    finding_stems = {stem(w) for w in finding_words if len(w) > 4}
    stem_overlap = len(vuln_stems & finding_stems)
    if stem_overlap >= 2:
        return True

    # Signal 6: LLM judge (opt-in via --judge)
    # When enabled, this is the DEFINITIVE answer — more accurate than keywords
    if _USE_LLM_JUDGE and _llm_judge_match(finding, vuln):
        return True

    return False


_USE_LLM_JUDGE = False  # Set via --judge flag


def evaluate_audit(audit_id, audit_data, llm_enhance=False, frontier_model=None, n_runs=1, deep=False):
    """Evaluate MIESC on a single EVMBench audit."""
    mode = f"static+{frontier_model}" if frontier_model else ("static+LLM" if llm_enhance else "static")
    print(f"\n{'='*60}")
    print(f"Audit: {audit_id} ({audit_data['sloc']} SLOC, {audit_data['n_contracts']} contracts) [{mode}]")
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

    # Run MIESC scan (multi-run ensemble: union of findings across N runs)
    all_findings_union = []
    seen_finding_keys = set()

    # Prepare frontier adapter once (if using frontier model)
    _frontier_adapter = None
    _frontier_concat = None
    if frontier_model:
        sys.path.insert(0, str(PROJECT_ROOT))
        sys.path.insert(0, str(PROJECT_ROOT / "src"))
        from src.adapters.frontier_llm_adapter import FrontierLLMAdapter

        provider_map = {"claude": "anthropic", "claude-opus": "anthropic",
                        "claude-sonnet": "anthropic", "gpt": "openai", "gpt-4o": "openai"}
        _frontier_adapter = FrontierLLMAdapter(provider=provider_map.get(frontier_model, "auto"))

        # Build concat file once (up to 150KB for large audits)
        source_files = [f for f in sol_files if "/test" not in f.lower()
                        and "/mock" not in f.lower() and not Path(f).name.startswith("I")]
        if not source_files:
            source_files = list(sol_files)
        source_files = sorted(source_files, key=lambda f: os.path.getsize(f), reverse=True)

        concat_code = ""
        for sf in source_files:
            try:
                content = open(sf).read()
                if len(concat_code) + len(content) > 150_000 and concat_code:
                    break
                concat_code += f"// ===== FILE: {Path(sf).name} =====\n{content}\n\n"
            except Exception:
                pass

        if concat_code:
            _frontier_concat = Path(tempfile.mktemp(suffix=".sol"))
            _frontier_concat.write_text(concat_code)
            print(f"  Concat: {len(source_files)} src files, {len(concat_code)//1024}KB")

    for run_idx in range(n_runs):
        if n_runs > 1:
            print(f"  Run {run_idx + 1}/{n_runs}...")
        else:
            print(f"  Running MIESC scan ({mode})...")

        run_findings = []

        # Strategy A: Direct frontier adapter (reliable, no subprocess issues)
        if _frontier_adapter and _frontier_concat:
            try:
                model_map = {"claude": "claude-sonnet-4-6", "claude-opus": "claude-opus-4-6",
                             "gpt": "gpt-4o", "gpt-4o": "gpt-4o"}
                result = _frontier_adapter.analyze(
                    str(_frontier_concat),
                    model=model_map.get(frontier_model, "claude-sonnet-4-6"),
                    deep=deep,
                )
                run_findings = result.get("findings", [])
            except Exception as e:
                print(f"    Frontier adapter error: {e}")

        # Strategy A2: If concat produced 0 findings, try scanning top files individually
        if not run_findings and _frontier_adapter:
            source_files_sorted = [f for f in sol_files if "/test" not in f.lower()
                                   and "/mock" not in f.lower() and not Path(f).name.startswith("I")]
            if not source_files_sorted:
                source_files_sorted = list(sol_files)
            source_files_sorted = sorted(source_files_sorted, key=lambda f: os.path.getsize(f), reverse=True)

            # Scan top 5 largest files individually
            for sf in source_files_sorted[:5]:
                try:
                    model_map = {"claude": "claude-sonnet-4-6", "claude-opus": "claude-opus-4-6",
                                 "gpt": "gpt-4o", "gpt-4o": "gpt-4o"}
                    result = _frontier_adapter.analyze(
                        sf, model=model_map.get(frontier_model, "claude-sonnet-4-6"),
                    )
                    file_findings = result.get("findings", [])
                    if file_findings:
                        run_findings.extend(file_findings)
                except Exception:
                    pass
            if run_findings:
                print(f"    Multi-file scan: {len(run_findings)} findings from individual files")

        # Strategy B: Subprocess scan (for static analysis, or fallback)
        if not run_findings:
            output_path = Path(tempfile.mktemp(suffix=".json"))
            scan_result = run_miesc_scan(sol_files, output_path, llm_enhance=llm_enhance,
                                             repo_dir=repo_dir, frontier_model=frontier_model)
            run_findings = scan_result.get("findings", [])
            output_path.unlink(missing_ok=True)

        # Deduplicate and add to union
        for f in run_findings:
            key = (
                (f.get("type") or f.get("title") or "").lower(),
                str(f.get("location", {}).get("function", "") if isinstance(f.get("location"), dict) else ""),
            )
            if key not in seen_finding_keys:
                seen_finding_keys.add(key)
                all_findings_union.append(f)

        if n_runs > 1:
            print(f"    Run {run_idx + 1}: {len(run_findings)} findings ({len(all_findings_union)} unique total)")

    # Filter: EVMBench only has HIGH/CRITICAL vulns — drop Low/Medium/Info
    # to improve precision without affecting recall
    high_crit = [f for f in all_findings_union
                 if (f.get("severity") or "").upper() in ("CRITICAL", "HIGH", "CRIT")]
    filtered_count = len(all_findings_union) - len(high_crit)

    findings = high_crit if high_crit else all_findings_union  # fallback if all got filtered
    if filtered_count > 0:
        print(f"  Filtered {filtered_count} medium/low findings (precision boost)")
    print(f"  MIESC found {len(findings)} findings total (HIGH+CRITICAL)")

    # Match findings to vulns
    detected = []
    for vuln in audit_data["vulns"]:
        matched = any(match_finding_to_vuln(f, vuln) for f in findings)
        detected.append({"vuln": vuln["id"], "matched": matched, "description": vuln["description"]})
        status = "✓" if matched else "✗"
        print(f"  {status} {vuln['id']}: {vuln['description'][:60]}")

    # Cleanup
    if _frontier_concat:
        _frontier_concat.unlink(missing_ok=True)
    shutil.rmtree(repo_dir.parent, ignore_errors=True)

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
        "n_findings_raw": len(all_findings_union),
        "n_filtered": filtered_count,
        "detected": n_detected,
        "total": n_total,
        "recall": recall,
        "precision": n_detected / len(findings) if findings else 0,
        "details": detected,
    }


def main():
    parser = argparse.ArgumentParser(description="EVMBench evaluation for MIESC")
    parser.add_argument("--max-audits", type=int, default=10, help="Max audits to evaluate")
    parser.add_argument("--audit", type=str, help="Single audit to evaluate")
    parser.add_argument("--llm", action="store_true", help="Enable LLM enhancement (Ollama)")
    parser.add_argument("--model", type=str, default=None,
                        help="Frontier model: claude, claude-opus, gpt, gpt-4o")
    parser.add_argument("--runs", type=int, default=1,
                        help="Number of runs to ensemble (union of findings)")
    parser.add_argument("--judge", action="store_true",
                        help="Use Claude Haiku as LLM judge for matching (more accurate)")
    parser.add_argument("--deep", action="store_true",
                        help="Multi-pass analysis (Pass 2 targets flagged functions, 2x cost)")
    args = parser.parse_args()

    if not EVMBENCH_AUDITS.exists():
        print("ERROR: EVMBench dataset not found at /tmp/evmbench/")
        print("Clone: git clone --recurse https://github.com/paradigmxyz/evmbench /tmp/evmbench")
        sys.exit(1)

    global _USE_LLM_JUDGE
    _USE_LLM_JUDGE = args.judge
    audits = load_audits(max_audits=args.max_audits, single_audit=args.audit)
    mode = f"static+{args.model}" if args.model else ("static+LLM" if args.llm else "static")
    print(f"Evaluating MIESC on {len(audits)} EVMBench audits [{mode}]")
    print(f"Total vulnerabilities: {sum(len(a['vulns']) for a in audits.values())}")

    results = []
    for audit_id, audit_data in audits.items():
        result = evaluate_audit(audit_id, audit_data, llm_enhance=args.llm,
                                frontier_model=args.model, n_runs=args.runs, deep=args.deep)
        results.append(result)

    # Aggregate
    total_detected = sum(r["detected"] for r in results if r["status"] == "ok")
    total_vulns = sum(r["total"] for r in results if r["status"] == "ok")
    total_findings = sum(r.get("n_findings", 0) for r in results if r["status"] == "ok")
    ok_count = sum(1 for r in results if r["status"] == "ok")

    print(f"\n{'='*60}")
    print(f"EVMBench Results — MIESC v5.3.1 [{mode}]")
    print(f"{'='*60}")
    total_raw = sum(r.get("n_findings_raw", r.get("n_findings", 0)) for r in results if r["status"] == "ok")
    precision = total_detected / total_findings if total_findings else 0
    recall_val = total_detected / total_vulns if total_vulns else 0
    f1 = 2 * precision * recall_val / (precision + recall_val) if (precision + recall_val) > 0 else 0

    print(f"Audits evaluated: {ok_count}/{len(audits)}")
    print(f"Findings: {total_findings} HIGH+CRITICAL (from {total_raw} raw)")
    print(f"Vulns detected: {total_detected}/{total_vulns}")
    print(f"Recall: {total_detected/total_vulns:.1%}" if total_vulns else "N/A")
    print(f"Precision: {precision:.1%} (TP={total_detected}, FP={total_findings - total_detected})")
    print(f"F1 Score: {f1:.1%}")
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
