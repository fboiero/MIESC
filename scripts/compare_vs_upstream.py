#!/usr/bin/env python3
"""
Compare this fork (alva-p/MIESC) against upstream (fboiero/MIESC): benchmark
metrics + feature/code diff, in one JSON meant to feed a chart.

Not a new metrics engine — reuses the exact `aggregate`/`per_category` shape
`miesc evaluate corpus -o` already produces (same one scripts/compare_benchmark_runs.py
reads) for the benchmark half, and plain `git`/`gh` calls for the feature-diff half.

Recipe to regenerate the two benchmark inputs before running this (~12-15 min
each, safe to run in parallel — layers 1,6,7 have no LLM step):

    git fetch upstream main
    git worktree add /tmp/miesc-upstream upstream/main
    miesc evaluate corpus benchmarks/datasets/smartbugs-curated/dataset \\
        --layers 1,6,7 -o /tmp/fork_result.json
    (cd /tmp/miesc-upstream && python -m miesc.cli.main evaluate corpus \\
        benchmarks/datasets/smartbugs-curated/dataset --layers 1,6,7 \\
        -o /tmp/upstream_result.json)
    git worktree remove /tmp/miesc-upstream

Usage:
    python scripts/compare_vs_upstream.py \\
        --fork-result /tmp/fork_result.json \\
        --upstream-result /tmp/upstream_result.json \\
        -o benchmarks/results/vs_upstream_$(date +%Y%m%d).json

Author: Pineda Álvaro (PPS)
"""

from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any, Dict


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], capture_output=True, text=True, check=True
    ).stdout.strip()


def _gh_merged_prs() -> list[Dict[str, Any]]:
    out = subprocess.run(
        [
            "gh", "pr", "list", "--repo", "alva-p/MIESC", "--state", "merged",
            "--limit", "100", "--json", "number,title,mergedAt",
        ],
        capture_output=True, text=True, check=True,
    ).stdout
    prs = json.loads(out)
    return sorted(prs, key=lambda p: p["number"])


def _feature_diff(upstream_worktree: Path | None) -> Dict[str, Any]:
    # "upstream/main...main": left count = commits only in upstream (fork is
    # behind by this many), right count = commits only in main (fork is ahead).
    upstream_only, fork_only = _git(
        "rev-list", "--left-right", "--count", "upstream/main...main"
    ).split()
    diffstat = _git("diff", "--shortstat", "upstream/main", "main")
    fork_tests = len(list(Path("tests").glob("test_*.py")))
    upstream_tests = (
        len(list((upstream_worktree / "tests").glob("test_*.py")))
        if upstream_worktree
        else None
    )
    return {
        "commits_behind_upstream": int(upstream_only),
        "commits_ahead_of_upstream": int(fork_only),
        "diffstat": diffstat,
        "fork_test_files": fork_tests,
        "upstream_test_files": upstream_tests,
        "merged_prs": _gh_merged_prs(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fork-result", type=Path, required=True)
    parser.add_argument("--upstream-result", type=Path, required=True)
    parser.add_argument(
        "--upstream-worktree", type=Path, default=None,
        help="Path to a git worktree checkout of upstream/main (for test-file count)",
    )
    parser.add_argument("-o", "--output", type=Path, required=True)
    args = parser.parse_args()

    fork = json.loads(args.fork_result.read_text())
    upstream = json.loads(args.upstream_result.read_text())

    if fork["aggregate"]["contracts_evaluated"] != upstream["aggregate"]["contracts_evaluated"]:
        print(
            "WARNING: contract count differs between runs — not apples-to-apples",
        )

    combined = {
        "generated_at": datetime.now().isoformat(),
        "benchmark": {
            "layers": "1,6,7",
            "corpus": "smartbugs-curated (143 contracts)",
            "fork": fork["aggregate"],
            "upstream": upstream["aggregate"],
            "fork_per_category": fork.get("per_category", {}),
            "upstream_per_category": upstream.get("per_category", {}),
        },
        "features": _feature_diff(args.upstream_worktree),
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(combined, indent=2))
    print(f"Wrote {args.output}")
    print(
        f"Fork:     P {fork['aggregate']['precision']:.4f}  "
        f"R {fork['aggregate']['recall']:.4f}  F1 {fork['aggregate']['f1']:.4f}"
    )
    print(
        f"Upstream: P {upstream['aggregate']['precision']:.4f}  "
        f"R {upstream['aggregate']['recall']:.4f}  F1 {upstream['aggregate']['f1']:.4f}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
