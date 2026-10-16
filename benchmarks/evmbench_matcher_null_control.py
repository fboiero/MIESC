"""Null control for the EVMBench multi-signal matcher (Paper 1, Section IV).

1. Feeds four generic findings that reference no audited contract to
   ``match_finding_to_vuln`` and reports how many ground-truth vulnerabilities
   the matcher still credits as detected.
2. Defines the *control-resistant* subset (vulnerabilities the generic findings
   cannot match) and reports each stored run's credited recall on it.

Usage (from the repository root):
    python3 benchmarks/evmbench_matcher_null_control.py \
        benchmarks/results/evmbench/evmbench_claude46_40_FINAL.json \
        [benchmarks/results/evmbench/evmbench_static_40.json ...] \
        [--ensemble benchmarks/results/evmbench/evmbench_ensemble_40.json]
The first file supplies the ground-truth vulnerability list; every file given
is also scored on the control-resistant subset.
"""

import argparse
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("evmbench_eval", HERE / "evmbench_eval.py")
ev = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ev)
ev._USE_LLM_JUDGE = False  # keyword/category signals only, as in the stored runs

GENERIC_FINDINGS = [
    {
        "type": "access-control",
        "title": "Missing access control on privileged function",
        "description": "Anyone can call this function because the owner check is missing.",
        "location": {"function": "setFee"},
    },
    {
        "type": "reentrancy",
        "title": "Reentrancy in withdraw",
        "description": "External call before state update allows reentrancy.",
        "location": {"function": "withdraw"},
    },
    {
        "type": "oracle-manipulation",
        "title": "Oracle price can be manipulated",
        "description": "The price is read from a spot oracle and may be stale.",
        "location": {"function": "getPrice"},
    },
    {
        "type": "logic",
        "title": "Incorrect accounting",
        "description": "The calculation is incorrect and may lead to wrong rounding.",
        "location": {"function": "calc"},
    },
]


def run_details(path):
    data = json.loads(Path(path).read_text())
    return {
        (r["audit"], d["vuln"]): (d["description"], bool(d.get("matched")))
        for r in data["results"]
        for d in r.get("details", [])
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "runs", nargs="+", help="provider result files; the first defines the vulnerabilities"
    )
    ap.add_argument("--ensemble", help="evmbench_ensemble_40.json (union artifact)")
    a = ap.parse_args()

    base = run_details(a.runs[0])
    credited = {
        k
        for k, (desc, _) in base.items()
        if any(ev.match_finding_to_vuln(f, {"description": desc}) for f in GENERIC_FINDINGS)
    }
    resistant = set(base) - credited
    print(
        f"Null control: {len(credited)}/{len(base)} vulnerabilities credited "
        f"({100 * len(credited) / len(base):.1f}%) to contract-agnostic findings"
    )
    print(f"Control-resistant subset: {len(resistant)} vulnerabilities")

    for path in a.runs:
        det = run_details(path)
        hit = sum(1 for k in resistant if det.get(k, (None, False))[1])
        print(f"  {Path(path).name}: {hit}/{len(resistant)} ({100 * hit / len(resistant):.0f}%)")
    if a.ensemble:
        ens = json.loads(Path(a.ensemble).read_text())
        det = {(v["audit"], v["vuln"]) for v in ens["vulnerabilities"] if v.get("matched")}
        hit = len(det & resistant)
        print(
            f"  {Path(a.ensemble).name}: {hit}/{len(resistant)} ({100 * hit / len(resistant):.0f}%)"
        )


if __name__ == "__main__":
    main()
