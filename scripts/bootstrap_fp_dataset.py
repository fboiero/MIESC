#!/usr/bin/env python3
"""
Bootstrap a labeled FP dataset from MIESC scans of the Rekt + SmartBugs corpora.

Principle: we have ground-truth vulnerability classes for Rekt exploits and
SmartBugs contracts. A finding on an exploit/vulnerable fixture whose TYPE
matches the ground-truth class is a strong true-positive signal. Low-severity
"info" findings on those same fixtures (pragma version, naming, constants)
are near-universal false positives. This lets us produce ~100+ labels
automatically to seed AuditorTrainedFPClassifier.

Output: a JSONL file ready for `clf.train()`.

Heuristic rules:
  - severity in {info, informational} AND type in {solc-version, pragma,
    naming-convention, constants-instead-of-literals, ...} → label=False (FP)
  - severity in {high, critical} AND type matches GT vuln class → label=True (TP)
  - ambiguous (e.g. Medium + unrelated type) → skipped to keep the seed clean

Usage:
    python3 scripts/bootstrap_fp_dataset.py --output data/fp_seed.jsonl
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Near-universal noise patterns — label=False (FP) regardless of source
FP_TYPES = {
    "solc-version", "pragma", "naming-convention", "useless-public-function",
    "constants-instead-of-literals", "push-zero-opcode",
    "unspecific-solidity-pragma", "invalid-solc-version",
    "pragma-not-pinned", "fallback-function",
    "assembly", "assembly-used", "inline-assembly",
    "boolean-equality", "boolean-cst", "immutable",
    "magic-number", "unused-state", "unused-return",
}

# Mapping from GT class -> set of keyword fragments present in finding type
GT_KEYWORDS: Dict[str, List[str]] = {
    "reentrancy": ["reentran", "external-call-before-write"],
    "access_control": ["access", "auth", "owner", "privileg", "tx-origin",
                       "tx.origin", "suicid", "selfdestruct", "unprotected",
                       "arbitrary-send"],
    "flash_loan": ["flash", "loan"],
    "flash_loan_governance": ["flash", "governance", "vote"],
    "oracle_manipulation": ["oracle", "price", "manipul", "twap"],
    "input_validation": ["input", "valid", "unchecked"],
    "arithmetic": ["overflow", "underflow", "integer", "arithmetic"],
    "initialization": ["init", "initializ"],
    "signature_verification": ["signature", "ecdsa", "ecrecover", "merkle"],
}


def _flatten_finding_text(f: Dict[str, Any]) -> str:
    return " ".join(
        str(f.get(k, "")) for k in ("type", "title", "check", "description", "category")
    ).lower()


def _type_matches_class(ftype: str, gt_class: str) -> bool:
    keywords = GT_KEYWORDS.get(gt_class, [])
    t = ftype.lower()
    return any(k in t for k in keywords)


def _severity_bucket(sev: str) -> str:
    s = sev.lower()
    if s in ("critical",):
        return "critical"
    if s in ("high",):
        return "high"
    if s in ("medium",):
        return "medium"
    if s in ("low",):
        return "low"
    return "info"


def label_finding(
    f: Dict[str, Any],
    gt_class: Optional[str],
    source: str = "",
) -> Optional[Tuple[bool, str]]:
    """
    Return (label, reason) where label=True for TP, False for FP, None to skip.

    Uses the canonical taxonomy (miesc.core.finding_taxonomy) for class matching
    so Slither's `arbitrary-send-eth` is correctly recognized as access_control,
    etc.
    """
    from miesc.core.finding_taxonomy import CanonicalCategory, normalize_finding_type

    ftype = str(f.get("type", f.get("check", ""))).lower().strip()
    if not ftype:
        return None
    sev = _severity_bucket(f.get("severity", ""))

    # Rule 1: noise types → FP
    if ftype in FP_TYPES:
        return (False, f"noise-type:{ftype}")
    for noise in FP_TYPES:
        if noise in ftype:
            return (False, f"noise-substring:{noise}")

    # Look up canonical category AND expected class
    canonical = normalize_finding_type(f)
    gt_canonical = None
    if gt_class:
        # Normalize the GT string too (maps smartbugs 'arithmetic' -> ARITHMETIC, etc.)
        gt_canonical = normalize_finding_type(gt_class.replace("_", "-"))

    # Rule 2a: TP when canonical category matches GT category (any severity — SmartBugs
    # contracts are victim-side code; any detector finding the intended vuln is a TP)
    if canonical and gt_canonical and canonical == gt_canonical:
        return (True, f"canonical-match:{canonical.value}")

    # Rule 2b: Keyword fallback for cases the taxonomy missed
    if gt_class and sev in ("high", "critical") and _type_matches_class(ftype, gt_class):
        return (True, f"gt-keyword:{gt_class}")

    # Rule 3a: [REMOVED in v5.1.7] — flagging off-category HIGH findings as FP
    # was over-eager; a reentrancy finding in an access-control folder could
    # be a genuine secondary vulnerability, not noise. Leave them unlabeled.

    # Rule 3b: Info severity on unmatched type → FP (these ARE near-always noise)
    if sev in ("info",) and gt_class and not _type_matches_class(ftype, gt_class):
        return (False, "info-off-class")

    return None


def scan_contract(contract_path: str) -> List[Dict[str, Any]]:
    """Run `miesc scan` and return findings."""
    import os
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out_path = tf.name
    try:
        subprocess.run(
            ["python3", "-m", "miesc.cli.main", "scan", contract_path, "--quiet", "-o", out_path],
            capture_output=True, text=True, timeout=120,
        )
        if not os.path.exists(out_path) or os.path.getsize(out_path) == 0:
            return []
        data = json.loads(open(out_path).read())
        return data.get("findings", data.get("results", []))
    except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
        return []
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass


def collect_from_rekt() -> List[Dict[str, Any]]:
    """Scan the 11 Rekt exploits and emit labeled samples."""
    gt_path = PROJECT_ROOT / "data" / "datasets" / "rekt_exploits" / "exploits_ground_truth.json"
    gt = json.loads(gt_path.read_text())
    out: List[Dict[str, Any]] = []
    for e in gt["exploits"]:
        contract = e.get("contract_file") or e.get("contract")
        if not contract:
            continue
        path = PROJECT_ROOT / "data" / "datasets" / "rekt_exploits" / contract
        if not path.exists():
            alt = PROJECT_ROOT / "data" / "datasets" / "rekt_exploits" / "contracts" / Path(contract).name
            if alt.exists():
                path = alt
            else:
                continue
        findings = scan_contract(str(path))
        vuln_class = e.get("vulnerability_class", e.get("vulnerability", ""))
        try:
            context = path.read_text()[:4000]
        except Exception:
            context = ""
        for f in findings:
            labeled = label_finding(f, vuln_class, source="rekt")
            if labeled is None:
                continue
            label, reason = labeled
            out.append({
                "finding": f,
                "context": context,
                "label": label,
                "_source": "rekt",
                "_exploit": e.get("name"),
                "_gt_class": vuln_class,
                "_reason": reason,
            })
    return out


def collect_from_smartbugs() -> List[Dict[str, Any]]:
    """Scan the SmartBugs-curated corpus (categorized folders)."""
    ds = PROJECT_ROOT / "benchmarks" / "datasets" / "smartbugs-curated" / "dataset"
    if not ds.exists():
        return []
    out: List[Dict[str, Any]] = []
    for category_dir in ds.iterdir():
        if not category_dir.is_dir():
            continue
        category = category_dir.name  # e.g., "arithmetic", "front_running"
        for sol in category_dir.glob("*.sol"):
            findings = scan_contract(str(sol))
            try:
                context = sol.read_text()[:4000]
            except Exception:
                context = ""
            for f in findings:
                labeled = label_finding(f, category, source="smartbugs")
                if labeled is None:
                    continue
                label, reason = labeled
                out.append({
                    "finding": f,
                    "context": context,
                    "label": label,
                    "_source": "smartbugs",
                    "_fixture": sol.name,
                    "_gt_class": category,
                    "_reason": reason,
                })
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=str(PROJECT_ROOT / "data" / "fp_seed.jsonl"))
    parser.add_argument("--skip-smartbugs", action="store_true")
    parser.add_argument("--skip-rekt", action="store_true")
    parser.add_argument("--train", action="store_true",
                        help="Also train AuditorTrainedFPClassifier on the produced dataset")
    args = parser.parse_args()

    samples: List[Dict[str, Any]] = []
    if not args.skip_rekt:
        print("Scanning Rekt exploits...")
        samples.extend(collect_from_rekt())
        print(f"  After Rekt: {len(samples)} samples")
    if not args.skip_smartbugs:
        print("Scanning SmartBugs corpus...")
        samples.extend(collect_from_smartbugs())
        print(f"  After SmartBugs: {len(samples)} samples")

    # Stats
    tp = sum(1 for s in samples if s["label"])
    fp = len(samples) - tp
    by_reason = Counter(s["_reason"] for s in samples)
    print()
    print(f"Total samples: {len(samples)}  ({tp} TP / {fp} FP)")
    print("Breakdown by reason:")
    for r, c in by_reason.most_common():
        print(f"  {c:>4}  {r}")

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        for s in samples:
            f.write(json.dumps(s) + "\n")
    print(f"\nWrote {len(samples)} samples to {out_path}")

    if args.train and len(samples) >= 10:
        print("\nTraining AuditorTrainedFPClassifier on the bootstrapped dataset...")
        from miesc.ml.fp_ml_classifier import AuditorTrainedFPClassifier
        clf = AuditorTrainedFPClassifier()
        metrics = clf.train(str(out_path))
        print(f"Metrics: {metrics}")


if __name__ == "__main__":
    main()
