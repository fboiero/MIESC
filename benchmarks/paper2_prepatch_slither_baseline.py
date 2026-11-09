"""Pre-patch Slither baseline for Paper 2.

Runs Slither ten times on each ORIGINAL SmartBugs-curated contracts with the same solc
version the canonical remediation run used for each contract, and compares the
HIGH-impact detectors before patching with those reported after patching
(taken from the canonical per-contract details artifact). A HIGH check counts as
present before patching if any of the ten runs reports it; checks that appear
in only some runs are listed as flaky.

Usage (from the repository root, Slither 0.11.6 as pinned in requirements-lock.txt):
    python3 benchmarks/paper2_prepatch_slither_baseline.py \
        benchmarks/results/paper2_compile_failure_taxonomy.json . \
        ~/.solc-select/artifacts benchmarks/results/paper2_prepatch_slither_baseline.json
"""

import ast
import json
import re
import subprocess
import sys
import tempfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

details_path, repo_root, solc_dir, out_path = sys.argv[1:5]
repo_root, solc_dir = Path(repo_root), Path(solc_dir)
details = json.loads(Path(details_path).read_text())


def parse(v):
    if isinstance(v, str):
        try:
            return ast.literal_eval(v)
        except (ValueError, SyntaxError):
            return {}
    return v or {}


def solc_for(rec):
    comp = parse(rec.get("compile"))
    m = re.search(r"solc-(\d+\.\d+\.\d+)", comp.get("solc") or "")
    ver = m.group(1) if m else "0.4.26"
    for path in (solc_dir / f"solc-{ver}" / f"solc-{ver}", solc_dir / f"solc-{ver}"):
        if path.is_file():
            return str(path), ver
    return str(solc_dir / "solc-0.4.26"), ver


def high_checks(sol, solc):
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "s.json"
        r = subprocess.run(
            ["slither", str(sol), "--solc", solc, "--json", str(out)],
            capture_output=True,
            text=True,
            timeout=180,
        )
        try:
            payload = json.loads(out.read_text()) if out.exists() else {}
        except json.JSONDecodeError:
            payload = {}
    dets = payload.get("results", {}).get("detectors", [])
    ok = bool(payload.get("success")) or bool(dets)
    checks = Counter(
        str(d.get("check"))
        for d in dets
        if str(d.get("impact", "")).lower() in {"high", "critical"}
    )
    return ok, dict(checks), r.returncode


RUNS = 10  # some Slither detectors (e.g. encode-packed-collision) are nondeterministic


def run(rec):
    sol = repo_root / rec["contract"]
    solc, ver = solc_for(rec)
    results = [high_checks(sol, solc) for _ in range(RUNS)]
    ok = any(r[0] for r in results)
    rc = results[0][2]
    seen = [set(r[1]) for r in results if r[0]]
    checks = {}
    for r in results:
        for k, v in r[1].items():
            checks[k] = max(checks.get(k, 0), v)
    flaky = sorted(set().union(*seen) - set.intersection(*seen)) if seen else []
    post = parse(rec.get("external_validation"))
    return {
        "contract": rec["contract"],
        "category": rec["category"],
        "patched": str(rec.get("fix_applied")) == "True",
        "solc": ver,
        "pre_ok": ok,
        "pre_returncode": rc,
        "pre_high_checks": dict(sorted(checks.items())),
        "pre_flaky_checks": flaky,
        "post_checked": bool(post.get("checked")),
        "post_high_checks": post.get("high_checks", []),
        "post_detector_summary": post.get("detector_summary", {}),
    }


with ThreadPoolExecutor(max_workers=6) as ex:
    rows = list(ex.map(run, details["contracts"]))

Path(out_path).write_text(json.dumps(rows, indent=1, sort_keys=True))
print(f"done: {len(rows)} contracts, pre-patch analysed ok: {sum(r['pre_ok'] for r in rows)}")
