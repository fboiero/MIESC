#!/usr/bin/env python3
"""
Code4rena findings scraper — ground truth for the wild benign-context eval.

Code4rena findings are HUMAN-validated competitive-audit results with exact file+line
locations — the highest-quality real-world source we found. They live as GitHub Issues in
code-423n4/<contest>-findings repos; each issue body has a standardized "# Lines of code"
section with permalinks: github.com/<org>/<repo>/blob/<sha>/<path>#L<a>-L<b>.

Key efficiency: we do NOT clone the audited repos. We fetch only the referenced files via
raw.githubusercontent.com at the pinned SHA — single files, not full clones.

Phases:
  contests              list code-423n4 *-findings repos (gh api)
  scrape <repo>...      pull issues, keep High/Med, parse "# Lines of code" -> findings JSONL
  build <findings.jsonl> fetch referenced files @SHA -> flat .sol corpus + vulnerabilities.json

Requires the authenticated `gh` CLI for the API (raw file fetch is plain HTTPS).

Caveat — category is keyword-mapped from free-text titles (Code4rena has no SWC/DASP tag),
so it is NOISY. Unmapped findings get category "other" and will NOT anchor (recall-safe:
under-credit rather than inflate). Severity (high/med) is taken from issue labels.

Usage:
  python3 scripts/code4rena_scraper.py contests | grep 2023
  python3 scripts/code4rena_scraper.py scrape 2023-05-ajna --out c4_findings.jsonl --max 200
  python3 scripts/code4rena_scraper.py build c4_findings.jsonl --out-corpus c4_corpus --out-gt c4_gt.json

Author: Fernando Boiero · License: AGPL-3.0
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request

# Permalink: github.com/<org>/<repo>/blob/<ref>/<path>#L<start>[C..][-L<end>[C..]]
# <ref> is a commit SHA (Code4rena) OR a branch/tag like main (Sherlock) — accept both.
PERMALINK_RE = re.compile(
    r"github\.com/([^/\s]+)/([^/\s]+)/blob/([^/\s#]+)/([^\s#)]+)"
    r"#L(\d+)(?:C\d+)?(?:-L(\d+)(?:C\d+)?)?"
)
# keyword -> our verifier category (order matters: first hit wins)
CATEGORY_KEYWORDS = [
    ("reentran", "reentrancy"),
    ("overflow", "arithmetic"), ("underflow", "arithmetic"), ("arithmetic", "arithmetic"),
    ("rounding", "arithmetic"), ("precision loss", "arithmetic"),
    ("access control", "access_control"), ("unauthor", "access_control"),
    ("onlyowner", "access_control"), ("only owner", "access_control"),
    ("privilege", "access_control"), ("permission", "access_control"),
    ("missing check", "access_control"),
    ("unchecked", "unchecked_low_level_calls"), ("return value", "unchecked_low_level_calls"),
    ("low-level call", "unchecked_low_level_calls"), ("low level call", "unchecked_low_level_calls"),
    ("randomness", "bad_randomness"), ("entropy", "bad_randomness"),
    ("timestamp", "time_manipulation"), ("block.timestamp", "time_manipulation"),
    ("front-run", "front_running"), ("front run", "front_running"), ("frontrun", "front_running"),
    ("sandwich", "front_running"), ("mev", "front_running"), ("ordering", "front_running"),
    ("denial of service", "denial_of_service"), ("dos", "denial_of_service"),
    ("gas limit", "denial_of_service"), ("out of gas", "denial_of_service"),
]


def title_category(title: str) -> str:
    t = (title or "").lower()
    for kw, cat in CATEGORY_KEYWORDS:
        if kw in t:
            return cat
    return "other"


def severity_from(labels: list, title: str) -> str | None:
    """Return 'high' | 'medium' | None (None = not an exploitable finding -> skip)."""
    names = " ".join(l.get("name", "") if isinstance(l, dict) else str(l) for l in labels).lower()
    if "high risk" in names or re.search(r"\b3 ?\(high", names):
        return "high"
    if "med risk" in names or "medium risk" in names or re.search(r"\b2 ?\(med", names):
        return "medium"
    t = (title or "").strip().lower()
    if re.match(r"h-?\d", t):
        return "high"
    if re.match(r"m-?\d", t):
        return "medium"
    return None


def parse_locations(body: str) -> list[dict]:
    """Extract every blob permalink in the issue body -> [{org,repo,sha,path,lstart,lend}]."""
    out = []
    for m in PERMALINK_RE.finditer(body or ""):
        org, repo, sha, path, a, b = m.groups()
        a = int(a)
        b = int(b) if b else a
        out.append({"org": org, "repo": repo, "sha": sha, "path": path,
                    "lstart": min(a, b), "lend": max(a, b)})
    return out


def _gh_api(path: str, paginate: bool = True) -> list:
    cmd = ["gh", "api", path]
    if paginate:
        cmd.append("--paginate")
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        print(f"  gh api error ({path}): {r.stderr.strip()[:200]}", file=sys.stderr)
        return []
    # --paginate concatenates JSON arrays as separate documents; normalize to one list.
    txt = r.stdout.strip()
    if not txt:
        return []
    try:
        data = json.loads(txt)
        return data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        items: list = []
        for chunk in re.split(r"(?<=\])\s*(?=\[)", txt):
            try:
                items.extend(json.loads(chunk))
            except json.JSONDecodeError:
                pass
        return items


def cmd_contests(args) -> int:
    repos = _gh_api("orgs/code-423n4/repos?per_page=100")
    names = sorted(r["name"] for r in repos if r.get("name", "").endswith("-findings"))
    for n in names:
        print(n)
    print(f"\n{len(names)} findings repos", file=sys.stderr)
    return 0


def cmd_scrape(args) -> int:
    records, kept, skipped = [], 0, 0
    for repo in args.repos:
        issues = _gh_api(f"repos/code-423n4/{repo}/issues?state=all&per_page=100")
        issues = [i for i in issues if "pull_request" not in i]
        if args.max:
            issues = issues[: args.max]
        for it in issues:
            sev = severity_from(it.get("labels", []), it.get("title", ""))
            if not sev:
                skipped += 1
                continue
            locs = parse_locations(it.get("body", ""))
            if not locs:
                skipped += 1
                continue
            records.append({
                "contest": repo, "issue": it.get("number"), "title": it.get("title", ""),
                "severity": sev, "category": title_category(it.get("title", "")),
                "locations": locs,
            })
            kept += 1
        print(f"  {repo}: kept {kept} findings so far")
    with open(args.out, "w") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
    print(f"\nscraped {kept} High/Med findings ({skipped} skipped: no severity or no code links)")
    print(f"  findings: {args.out}")
    return 0


def _raw_fetch(org: str, repo: str, sha: str, path: str, cache: dict) -> str | None:
    key = f"{org}/{repo}/{sha}/{path}"
    if key in cache:
        return cache[key]
    url = f"https://raw.githubusercontent.com/{org}/{repo}/{sha}/{path}"
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            text = resp.read().decode("utf-8", errors="ignore")
    except Exception:  # noqa: BLE001
        text = None
    cache[key] = text
    return text


def cmd_build(args) -> int:
    records = [json.loads(l) for l in open(args.infile) if l.strip()]
    os.makedirs(args.out_corpus, exist_ok=True)
    cache: dict = {}
    files: dict = {}  # flat_name -> {"vulns": {cat: set(lines)}}
    fetched, missing = 0, 0
    for rec in records:
        cat = rec.get("category", "other")
        for loc in rec.get("locations", []):
            if not loc["path"].endswith(".sol"):
                continue
            code = _raw_fetch(loc["org"], loc["repo"], loc["sha"], loc["path"], cache)
            if code is None:
                missing += 1
                continue
            flat = re.sub(r"[^A-Za-z0-9_.-]", "_",
                          f"{loc['org']}__{loc['repo']}__{loc['sha'][:8]}__{loc['path'].replace('/', '__')}")
            if flat not in files:
                with open(os.path.join(args.out_corpus, flat), "w", errors="ignore") as fh:
                    fh.write(code)
                files[flat] = {}
                fetched += 1
            files[flat].setdefault(cat, set()).update(range(loc["lstart"], loc["lend"] + 1))
    entries = [{"path": flat,
                "vulnerabilities": [{"category": c, "lines": sorted(ls)} for c, ls in cats.items()]}
               for flat, cats in files.items()]
    json.dump(entries, open(args.out_gt, "w"), indent=2)
    print(f"built {len(entries)} contracts ({fetched} files fetched, {missing} permalinks unreachable)")
    print(f"  corpus: {args.out_corpus}\n  ground truth: {args.out_gt}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Code4rena findings scraper for the wild eval")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("contests")
    sc = sub.add_parser("scrape")
    sc.add_argument("repos", nargs="+", help="one or more <contest>-findings repo names")
    sc.add_argument("--out", default="c4_findings.jsonl")
    sc.add_argument("--max", type=int, default=0, help="max issues per repo (0 = all)")
    bd = sub.add_parser("build")
    bd.add_argument("infile")
    bd.add_argument("--out-corpus", required=True)
    bd.add_argument("--out-gt", required=True)
    args = ap.parse_args()
    return {"contests": cmd_contests, "scrape": cmd_scrape, "build": cmd_build}[args.cmd](args)


if __name__ == "__main__":
    raise SystemExit(main())
