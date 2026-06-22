#!/usr/bin/env python3
"""
Sherlock findings scraper — ground truth for the wild benign-context eval.

Sherlock contest findings are HUMAN-validated audit results. Unlike Code4rena (GitHub
Issues), they are markdown FILES in sherlock-audit/<contest>-judging repos, laid out as
severity folders `<n>-H/` and `<n>-M/`, each holding warden submissions with `<id>-best.md`
as the chosen canonical write-up. Severity is encoded in the FOLDER name (authoritative).
Locations are GitHub permalinks embedded inline (often `blob/main/...`, a branch ref).

This reuses Code4rena's shared machinery (permalink parsing, title→category, raw file fetch
at the pinned ref, and the `build` phase) — it emits the SAME findings JSONL schema, so the
output is consumed by the identical `build`.

Phases:
  contests               list sherlock-audit *-judging repos
  scrape <repo>...        walk severity folders, take the -best.md per issue -> findings JSONL
  build <findings.jsonl>  (delegates to code4rena_scraper.build) fetch files -> corpus + gt

Requires the authenticated `gh` CLI. Same category caveat as Code4rena (free-text titles →
keyword-mapped; unmapped → "other", never anchors → recall-safe). Only High/Med kept.
NOTE: Sherlock permalinks usually pin to `main` (a branch), not a commit SHA — the judging
snapshot is frozen, but the fetched source is whatever `main` holds; record the run date.

Usage:
  python3 scripts/sherlock_scraper.py contests | grep 2023
  python3 scripts/sherlock_scraper.py scrape 2023-02-gmx-judging --out sherlock.jsonl
  python3 scripts/sherlock_scraper.py build sherlock.jsonl --out-corpus s_corpus --out-gt s_gt.json

Author: Fernando Boiero · License: AGPL-3.0
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import code4rena_scraper as c4  # noqa: E402  (shared parsing/build machinery)

ORG = "sherlock-audit"
# severity folder: <number>-<H|M>/<file>.md  (Low/Info/QA folders are not [HM] -> skipped)
FOLDER_RE = re.compile(r"^(\d+)-([HM])/(.+\.md)$")


def _default_branch(repo: str) -> str:
    resp = c4._gh_api(f"repos/{ORG}/{repo}", paginate=False)
    return (resp[0].get("default_branch") if resp else None) or "main"


def _first_heading(body: str) -> str:
    for line in (body or "").splitlines():
        m = re.match(r"^#\s+(.+)", line.strip())
        if m:
            return m.group(1).strip()
    return ""


def cmd_contests(args) -> int:
    repos = c4._gh_api(f"orgs/{ORG}/repos?per_page=100")
    names = sorted(r["name"] for r in repos if r.get("name", "").endswith("-judging"))
    for n in names:
        print(n)
    print(f"\n{len(names)} judging repos", file=sys.stderr)
    return 0


def cmd_scrape(args) -> int:
    cache: dict = {}
    records, kept, skipped = [], 0, 0
    for repo in args.repos:
        branch = _default_branch(repo)
        resp = c4._gh_api(f"repos/{ORG}/{repo}/git/trees/{branch}?recursive=1", paginate=False)
        tree = (resp[0].get("tree") if resp else []) or []
        # group md files by their severity folder; canonical = the *-best.md if present
        folders: dict = {}
        sev_of: dict = {}
        for node in tree:
            m = FOLDER_RE.match(node.get("path", ""))
            if not m:
                continue
            folder = f"{m.group(1)}-{m.group(2)}"
            folders.setdefault(folder, []).append(node["path"])
            sev_of[folder] = "high" if m.group(2) == "H" else "medium"
        chosen = []
        for folder, paths in folders.items():
            best = [p for p in paths if p.endswith("-best.md")]
            chosen.append((folder, sorted(best)[0] if best else sorted(paths)[0]))
        if args.max:
            chosen = chosen[: args.max]
        for folder, path in chosen:
            body = c4._raw_fetch(ORG, repo, branch, path, cache)
            if body is None:
                skipped += 1
                continue
            locs = c4.parse_locations(body)
            if not locs:
                skipped += 1
                continue
            title = _first_heading(body)
            records.append({
                "contest": repo, "issue": path, "title": title,
                "severity": sev_of[folder], "category": c4.title_category(title),
                "locations": locs,
            })
            kept += 1
        print(f"  {repo}: kept {kept} findings so far")
    with open(args.out, "w") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
    print(f"\nscraped {kept} High/Med findings ({skipped} skipped: no body or no code links)")
    print(f"  findings: {args.out}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Sherlock findings scraper for the wild eval")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("contests")
    sc = sub.add_parser("scrape")
    sc.add_argument("repos", nargs="+", help="one or more <contest>-judging repo names")
    sc.add_argument("--out", default="sherlock_findings.jsonl")
    sc.add_argument("--max", type=int, default=0, help="max issues per repo (0 = all)")
    bd = sub.add_parser("build")  # identical to Code4rena's build (shared JSONL schema)
    bd.add_argument("infile")
    bd.add_argument("--out-corpus", required=True)
    bd.add_argument("--out-gt", required=True)
    args = ap.parse_args()
    if args.cmd == "build":
        return c4.cmd_build(args)
    return {"contests": cmd_contests, "scrape": cmd_scrape}[args.cmd](args)


if __name__ == "__main__":
    raise SystemExit(main())
