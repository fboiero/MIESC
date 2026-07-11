#!/usr/bin/env python3
"""Repository quality auditor — read-only.

Scores the repo on four hygiene dimensions and prints an actionable report:
  1. Build hygiene   — build/tooling artifacts present but not gitignored
  2. Structure       — duplicate source roots, redundant output dirs, dataset dupes
  3. Root cleanliness— stray/scaffolding/secret files that don't belong at repo root
  4. Documentation   — markdown volume, orphan docs, broken relative links, stale drafts

Does NOT modify anything. Emits a human summary and a JSON report (--json <path>).
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _sh(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=ROOT, capture_output=True, text=True
    ).stdout


def _is_ignored(rel: str) -> bool:
    return (
        subprocess.run(
            ["git", "check-ignore", "-q", rel], cwd=ROOT, capture_output=True
        ).returncode
        == 0
    )


# ---------------------------------------------------------------- dimensions
def audit_build_hygiene() -> list[dict]:
    findings = []
    artifact_dirs = [
        "dist",
        "build",
        "site",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "htmlcov",
        "node_modules",
        ".streamlit",
    ]
    for name in artifact_dirs:
        p = ROOT / name
        if p.is_dir() and not _is_ignored(name):
            findings.append(
                {"severity": "high", "item": f"{name}/", "why": "build/tooling artifact present but not gitignored"}
            )
    # glob-y artifacts
    for pat, why in [
        ("*.egg-info", "packaging artifact"),
        ("miesc-[0-9]*", "extracted/duplicate versioned package dir"),
    ]:
        for p in ROOT.glob(pat):
            rel = p.name + ("/" if p.is_dir() else "")
            if not _is_ignored(p.name):
                findings.append({"severity": "high", "item": rel, "why": why + " not gitignored"})
    # committed junk
    for junk, why in [("*.pyc", "compiled bytecode"), ("*.DS_Store", "macOS metadata")]:
        hits = [f for f in _sh("ls-files", junk).splitlines() if f]
        if hits:
            findings.append({"severity": "medium", "item": f"{len(hits)}x {junk}", "why": f"{why} tracked in git"})
    # true sync-conflict dupes only: "name 2.ext" WHERE base "name.ext" also exists
    dupes = []
    for f in _sh("ls-files").splitlines():
        m = re.match(r"^(.*) 2(\.[A-Za-z0-9]+)$", f)
        if m and (ROOT / (m.group(1) + m.group(2))).exists():
            dupes.append(f)
    if dupes:
        findings.append({"severity": "medium", "item": f"{len(dupes)}x sync-conflict dupes", "why": "'name 2.ext' with base present: " + ", ".join(dupes[:3])})
    return findings


def audit_structure() -> list[dict]:
    findings = []
    if (ROOT / "miesc").is_dir() and (ROOT / "src").is_dir():
        n_miesc = len(list((ROOT / "miesc").rglob("*.py")))
        n_src = len(list((ROOT / "src").rglob("*.py")))
        findings.append(
            {"severity": "high", "item": "miesc/ + src/", "why": f"two Python source roots coexist (miesc/={n_miesc} .py, src/={n_src} .py) — legacy vs modern split"}
        )
    output_dirs = [d for d in ["reports", "results", "evaluation_results", "validation_results", "analysis", "out", "output"] if (ROOT / d).is_dir()]
    if len(output_dirs) > 2:
        findings.append({"severity": "medium", "item": ", ".join(output_dirs), "why": f"{len(output_dirs)} separate output/results dirs — consolidate"})
    if (ROOT / "data" / "benchmarks").is_dir() and (ROOT / "benchmarks" / "datasets").is_dir():
        findings.append({"severity": "medium", "item": "data/benchmarks + benchmarks/datasets", "why": "dataset lives in two locations"})
    return findings


def audit_root_cleanliness() -> list[dict]:
    findings = []
    # Only tracked (shipped) files matter for public-repo cleanliness; gitignored
    # local-only files (LANES.md, diagnostic-report.json, apik.sh) are fine.
    root_files = [p for p in ROOT.iterdir() if p.is_file() and not _is_ignored(p.name)]
    scaffolding = re.compile(r"^(LANES|LANES_ROADMAP|LOOP_PROTOCOL|AGENT.*|.*COORDINATION.*)\.md$", re.I)
    secret_templates = (".example", ".sample", ".template", ".baseline", ".dist")
    for p in root_files:
        n = p.name
        if scaffolding.match(n):
            findings.append({"severity": "medium", "item": n, "why": "internal agent/coordination scaffolding shipped at repo root"})
        elif n.endswith(".spec"):
            findings.append({"severity": "low", "item": n, "why": "build spec at root — move to packaging/ or ignore"})
        elif re.match(r".*(diagnostic|debug).*\.(json|log|txt)$", n, re.I):
            findings.append({"severity": "medium", "item": n, "why": "stray generated file at root"})
        elif re.match(r".*(apik|api.?key|secret|credential)", n, re.I) and not n.endswith(secret_templates):
            findings.append({"severity": "high", "item": n, "why": "possible secret/credential file at root NOT gitignored"})
    if len(root_files) > 18:
        findings.append({"severity": "low", "item": f"{len(root_files)} tracked root files", "why": "root is cluttered (target < ~18 shipped top-level files)"})
    return findings


def audit_docs() -> list[dict]:
    findings = []
    md_files = [Path(f) for f in _sh("ls-files", "*.md").splitlines() if f]
    total = len(md_files)
    # build link graph (which md files are referenced by a relative link somewhere)
    link_re = re.compile(r"\]\(([^)]+\.md)[)#]")
    referenced: set[str] = set()
    broken = []
    for f in md_files:
        try:
            text = (ROOT / f).read_text(errors="replace")
        except Exception:
            continue
        for m in link_re.finditer(text):
            target = m.group(1).split("#")[0]
            if target.startswith(("http://", "https://")):
                continue
            resolved = (ROOT / f).parent / target
            try:
                rel = resolved.resolve().relative_to(ROOT)
                referenced.add(str(rel))
                if not resolved.exists():
                    broken.append((str(f), target))
            except Exception:
                pass
    # orphan docs under docs/ that nothing links to (and aren't READMEs/index)
    orphans = [
        str(f) for f in md_files
        if str(f).startswith("docs/")
        and str(f) not in referenced
        and f.name.lower() not in {"readme.md", "index.md"}
    ]
    # stale drafts: dated filenames older than ~9 months, or WIP/DRAFT/TODO-heavy
    stale = []
    for f in md_files:
        mdate = re.search(r"(20\d{2})(\d{2})(\d{2})", f.name)
        if mdate:
            y, mo = int(mdate.group(1)), int(mdate.group(2))
            if (2026 - y) * 12 + (7 - mo) > 9:
                stale.append(str(f))
    findings.append({"severity": "info", "item": f"{total} markdown files", "why": f"{len([m for m in md_files if str(m).startswith('docs/')])} under docs/"})
    if broken:
        findings.append({"severity": "high", "item": f"{len(broken)} broken relative links", "why": "; ".join(f"{a} -> {b}" for a, b in broken[:6]) + (" ..." if len(broken) > 6 else "")})
    if orphans:
        findings.append({"severity": "medium", "item": f"{len(orphans)} orphan docs", "why": "not linked from any other doc: " + ", ".join(orphans[:6]) + (" ..." if len(orphans) > 6 else "")})
    if stale:
        findings.append({"severity": "low", "item": f"{len(stale)} old dated docs (>9mo)", "why": "candidates for docs/archive/: " + ", ".join(stale[:5]) + (" ..." if len(stale) > 5 else "")})
    return findings


# ---------------------------------------------------------------- scoring
def _score(findings: list[dict]) -> float:
    penalty = sum({"high": 2.5, "medium": 1.0, "low": 0.4, "info": 0.0}.get(f["severity"], 0.5) for f in findings)
    return max(0.0, round(10.0 - penalty, 1))


def main() -> None:
    dims = {
        "build_hygiene": audit_build_hygiene(),
        "structure": audit_structure(),
        "root_cleanliness": audit_root_cleanliness(),
        "documentation": audit_docs(),
    }
    report = {"generated_utc": datetime.now(timezone.utc).isoformat(), "dimensions": {}, "scores": {}}
    print("\n" + "=" * 70)
    print("  REPO QUALITY AUDIT")
    print("=" * 70)
    for dim, findings in dims.items():
        sc = _score([f for f in findings if f["severity"] != "info"])
        report["dimensions"][dim] = findings
        report["scores"][dim] = sc
        print(f"\n  {dim.upper():<20} score {sc}/10")
        for f in findings:
            mark = {"high": "🔴", "medium": "🟡", "low": "🔵", "info": "ℹ️ "}.get(f["severity"], "  ")
            print(f"    {mark} {f['item']}: {f['why']}")
    overall = round(sum(report["scores"].values()) / len(report["scores"]), 1)
    report["scores"]["overall"] = overall
    print("\n" + "=" * 70)
    print(f"  OVERALL: {overall}/10")
    print("=" * 70)
    if "--json" in sys.argv:
        out = Path(sys.argv[sys.argv.index("--json") + 1])
        out.write_text(json.dumps(report, indent=2))
        print(f"  wrote {out}")


if __name__ == "__main__":
    main()
