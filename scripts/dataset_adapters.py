#!/usr/bin/env python3
"""
Ground-truth adapters — convert labeled SC vuln datasets into the SmartBugs-style
vulnerabilities.json that scripts/wild_benign_context_eval.py --ground-truth consumes.

Output format (per the harness's load_ground_truth):
    [ {"path": "<basename>.sol", "vulnerabilities": [{"category": <our-cat>, "lines": [int,...]}],
       "clean": <bool, optional> }, ... ]
plus a corpus directory of .sol files whose BASENAMES match the "path" keys (the harness
keys ground truth by basename, so names must be unique — both adapters flatten/rename).

Two sources (both verified line-level, both human/deterministic — NOT tool-derived, so no
circularity):

  solidifi  — DependableSystemsLab/SolidiFI-benchmark. Injected bugs with exact location.
              buggy_contracts/<Type>/{buggy_N.sol, BugLog_N.csv}; BugLog cols loc,length,...
              -> lines [loc, loc+length-1]; LABEL from the FOLDER (the CSV 'bug type' value
              is UTF-7-mangled for Re-entrancy), contracts flattened to <Type>__buggy_N.sol.

  fsalzano  — fsalzano/Empirical-Analysis-...-Line-Level-...  Real contracts, MANUAL human
              line-level annotation. sample_of_interest_with_code.csv cols label,tag,contract,
              contract_code; tag = "529: time_manipulation; 563: time_manipulation;".
              Code is inline -> materialized to <address>.sol. 'no' tag = human-verified
              clean (emitted with clean=true: any finding there is a true FP).

Usage:
  python3 scripts/dataset_adapters.py solidifi <solidifi_repo> --out-corpus solidifi_corpus --out-gt solidifi_gt.json
  python3 scripts/dataset_adapters.py fsalzano <repo_or_csv>    --out-corpus fsalzano_corpus --out-gt fsalzano_gt.json
then:
  python3 scripts/wild_benign_context_eval.py collect <out-corpus> --ground-truth <out-gt> -o wild_findings.jsonl

Author: Fernando Boiero · License: AGPL-3.0
"""
from __future__ import annotations

import argparse
import csv
import glob
import json
import os
import re
import shutil
import sys

csv.field_size_limit(10_000_000)  # fsalzano inlines full contract source in one CSV cell

# Map each dataset's vuln vocabulary onto the categories the verifier / Slither path uses
# (same vocabulary as DETECTOR_CATEGORY in wild_benign_context_eval.py).
SOLIDIFI_MAP = {
    "Overflow-Underflow": "arithmetic",
    "Re-entrancy": "reentrancy",
    "TOD": "front_running",              # transaction-ordering dependence
    "Timestamp-Dependency": "time_manipulation",
    "Unchecked-Send": "unchecked_low_level_calls",
    "Unhandled-Exceptions": "unchecked_low_level_calls",
    "tx.origin": "access_control",
}
FSALZANO_MAP = {
    "access_control": "access_control",
    "arithmetic": "arithmetic",
    "reentrancy": "reentrancy",
    "unchecked_low_calls": "unchecked_low_level_calls",
    "bad_randomness": "bad_randomness",
    "front_running": "front_running",
    "time_manipulation": "time_manipulation",
    "denial_service": "denial_of_service",
    "short_addresses": "short_addresses",
}
# DAppSCAN uses the SWC registry; map the SWC numbers that correspond to our categories.
# Unmapped SWCs (informational: outdated compiler, floating pragma, code-with-no-effects,
# etc.) are kept under "swc-<n>" so they never falsely anchor against a Slither category.
SWC_MAP = {
    "107": "reentrancy",
    "101": "arithmetic",
    "104": "unchecked_low_level_calls",
    "105": "access_control", "106": "access_control", "100": "access_control",
    "108": "access_control", "112": "access_control", "115": "access_control",
    "120": "bad_randomness",
    "116": "time_manipulation",
    "114": "front_running",
    "113": "denial_of_service", "128": "denial_of_service",
}


def _write(out_corpus: str, name: str, code: str) -> None:
    with open(os.path.join(out_corpus, name), "w", errors="ignore") as fh:
        fh.write(code)


def adapt_solidifi(args) -> int:
    buggy_root = os.path.join(args.repo, "buggy_contracts")
    if not os.path.isdir(buggy_root):
        print(f"ERROR: {buggy_root} not found (point at the SolidiFI-benchmark repo root).")
        return 1
    os.makedirs(args.out_corpus, exist_ok=True)
    entries, contracts, bugs, skipped = [], 0, 0, 0
    for folder in sorted(os.listdir(buggy_root)):
        fdir = os.path.join(buggy_root, folder)
        if not os.path.isdir(fdir):
            continue
        cat = SOLIDIFI_MAP.get(folder)
        if not cat:
            print(f"  skip folder {folder!r} (no category mapping)")
            continue
        for log in sorted(glob.glob(os.path.join(fdir, "BugLog_*.csv"))):
            m = re.search(r"BugLog_(\d+)\.csv$", log)
            if not m:
                continue
            n = m.group(1)
            sol = os.path.join(fdir, f"buggy_{n}.sol")
            if not os.path.exists(sol):
                skipped += 1  # BugLog without a contract -> can't anchor, drop it
                continue
            lines: list[int] = []
            with open(log, errors="ignore") as fh:
                for row in csv.DictReader(fh):
                    try:
                        loc, length = int(row["loc"]), int(row.get("length", 1) or 1)
                    except (ValueError, KeyError, TypeError):
                        continue
                    lines.extend(range(loc, loc + max(length, 1)))
                    bugs += 1
            if not lines:
                skipped += 1
                continue
            flat = f"{folder.replace('.', '_')}__buggy_{n}.sol"
            shutil.copyfile(sol, os.path.join(args.out_corpus, flat))
            entries.append({"path": flat, "name": flat,
                            "vulnerabilities": [{"category": cat, "lines": sorted(set(lines))}]})
            contracts += 1
    json.dump(entries, open(args.out_gt, "w"), indent=2)
    print(f"SolidiFI: {contracts} contracts, {bugs} injected bugs, {skipped} skipped")
    print(f"  corpus: {args.out_corpus}\n  ground truth: {args.out_gt}")
    return 0


def _find_fsalzano_csv(path: str) -> str | None:
    if os.path.isfile(path):
        return path
    for cand in ("csvs/sample_of_interest_with_code.csv", "sample_of_interest_with_code.csv"):
        p = os.path.join(path, cand)
        if os.path.isfile(p):
            return p
    hits = glob.glob(os.path.join(path, "**", "sample_of_interest_with_code.csv"), recursive=True)
    return hits[0] if hits else None


def adapt_fsalzano(args) -> int:
    csv_path = _find_fsalzano_csv(args.repo)
    if not csv_path:
        print("ERROR: sample_of_interest_with_code.csv not found (need the *_with_code* CSV "
              "so source can be materialized). Point at the repo or the CSV directly.")
        return 1
    os.makedirs(args.out_corpus, exist_ok=True)
    entries, vuln_c, clean_c, instances, no_code = [], 0, 0, 0, 0
    with open(csv_path, errors="ignore") as fh:
        for row in csv.DictReader(fh):
            addr = (row.get("contract") or "").strip()
            code = row.get("contract_code") or ""
            if not addr or not code.strip():
                no_code += 1
                continue
            flat = f"{addr}.sol"
            _write(args.out_corpus, flat, code)
            tag = (row.get("tag") or "").strip()
            if not tag or tag.lower() == "no":
                entries.append({"path": flat, "vulnerabilities": [], "clean": True})
                clean_c += 1
                continue
            bycat: dict[str, list[int]] = {}
            for pair in tag.split(";"):
                pair = pair.strip()
                if not pair or ":" not in pair:
                    continue
                line_s, raw_cat = pair.split(":", 1)
                try:
                    line = int(line_s.strip())
                except ValueError:
                    continue
                cat = FSALZANO_MAP.get(raw_cat.strip(), raw_cat.strip())
                bycat.setdefault(cat, []).append(line)
                instances += 1
            entries.append({"path": flat,
                            "vulnerabilities": [{"category": c, "lines": sorted(set(ls))}
                                                for c, ls in bycat.items()]})
            vuln_c += 1
    json.dump(entries, open(args.out_gt, "w"), indent=2)
    print(f"fsalzano: {vuln_c} vulnerable contracts ({instances} line instances), "
          f"{clean_c} human-verified CLEAN (true negatives), {no_code} rows w/o code skipped")
    print(f"  corpus: {args.out_corpus}\n  ground truth: {args.out_gt}")
    return 0


def _swc_category(raw: str) -> str:
    """'SWC-135-Code With No Effects' -> mapped category or 'swc-135' (inert for anchoring)."""
    m = re.search(r"SWC-?(\d+)", raw or "", re.IGNORECASE)
    if not m:
        return (raw or "other").strip().lower()
    return SWC_MAP.get(m.group(1), f"swc-{m.group(1)}")


def _parse_linenumber(val) -> list[int]:
    """DAppSCAN lineNumber: 'L74' | 'L45-47' | 'L3' | 74 -> list of ints."""
    s = str(val).strip().lstrip("Ll")
    if not s:
        return []
    if "-" in s:
        try:
            a, b = (int(x) for x in s.split("-", 1))
            return list(range(min(a, b), max(a, b) + 1))
        except ValueError:
            return []
    try:
        return [int(s)]
    except ValueError:
        return []


def adapt_dappscan(args) -> int:
    # Prefer the source-level SWC tree; fall back to scanning the whole repo for label JSONs.
    roots = [os.path.join(args.repo, "DAppSCAN-source", "SWCsource"), args.repo]
    root = next((r for r in roots if os.path.isdir(r)), None)
    if not root:
        print(f"ERROR: {args.repo} not found (point at the DAppSCAN repo root).")
        return 1
    os.makedirs(args.out_corpus, exist_ok=True)
    entries, contracts, weaknesses, no_sol = [], 0, 0, 0
    for jpath in glob.glob(os.path.join(root, "**", "*.json"), recursive=True):
        try:
            data = json.load(open(jpath, errors="ignore"))
        except (ValueError, OSError):
            continue
        swcs = data.get("SWCs") if isinstance(data, dict) else None
        if not isinstance(swcs, list) or not swcs:
            continue
        # locate source: filePath is REPO-ROOT-relative (labels live under SWCsource/, the
        # source under contracts/), so resolve against args.repo; fall back to sibling .sol.
        fp = str(data.get("filePath") or "")
        sol = None
        if fp.endswith(".sol"):
            cand = os.path.join(args.repo, fp)
            sol = cand if os.path.exists(cand) else None
        if not sol:
            stem = os.path.splitext(jpath)[0] + ".sol"
            sol = stem if os.path.exists(stem) else None
        if not sol:
            no_sol += 1
            continue
        bycat: dict[str, list[int]] = {}
        for s in swcs:
            if not isinstance(s, dict):
                continue
            cat = _swc_category(s.get("category", ""))
            lines = _parse_linenumber(s.get("lineNumber", ""))
            if lines:
                bycat.setdefault(cat, []).extend(lines)
                weaknesses += 1
        if not bycat:
            continue
        rel = os.path.relpath(sol, args.repo).replace(os.sep, "__")
        flat = re.sub(r"[^A-Za-z0-9_.-]", "_", rel)
        shutil.copyfile(sol, os.path.join(args.out_corpus, flat))
        entries.append({"path": flat, "name": flat,
                        "vulnerabilities": [{"category": c, "lines": sorted(set(ls))}
                                            for c, ls in bycat.items()]})
        contracts += 1
    json.dump(entries, open(args.out_gt, "w"), indent=2)
    print(f"DAppSCAN: {contracts} contracts, {weaknesses} located weaknesses, {no_sol} label files w/o source")
    print(f"  corpus: {args.out_corpus}\n  ground truth: {args.out_gt}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Ground-truth dataset adapters for the wild eval")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("solidifi", "fsalzano", "dappscan"):
        p = sub.add_parser(name)
        p.add_argument("repo", help="dataset repo dir (fsalzano also accepts the CSV path)")
        p.add_argument("--out-corpus", required=True, help="dir to write the .sol corpus into")
        p.add_argument("--out-gt", required=True, help="vulnerabilities.json to write")
    args = ap.parse_args()
    return {"solidifi": adapt_solidifi, "fsalzano": adapt_fsalzano,
            "dappscan": adapt_dappscan}[args.cmd](args)


if __name__ == "__main__":
    raise SystemExit(main())
