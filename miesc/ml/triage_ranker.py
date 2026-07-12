"""
Recall-safe triage ranker.

Scores each finding with P(real) and ORDERS findings so the most-likely-real surface first.
It NEVER drops a finding (recall stays 1.0) — it is pure reordering, sidestepping the
recall-safety dilemma that caps aggressive FP-dropping at ~+4pp precision.

Validated on the six wild ground-truth sources (docs/research/SAFE_PRECISION_FEASIBILITY_20260624.md):
ranking AUC 0.927; at 90% recall the auditor reviews half the findings at ~2x the precision
(0.62 vs 0.30 baseline). Model: GradientBoosting over MIESC's coarse FP features plus the
12 structural signals the recall-safe verifier uses.

Graceful by design: if no trained model is present (or scikit-learn is unavailable), `score`
returns None and `rank` leaves the order unchanged — callers degrade to the existing
confidence ordering. Train a model with `scripts/train_triage_model.py`.
"""
from __future__ import annotations

import os
import re
from typing import Any, Callable, Optional

DEFAULT_MODEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "models", "triage_model.joblib",
)


_BENIGN_PATTERNS: Optional[list] = None


def _benign_patterns() -> list:
    global _BENIGN_PATTERNS
    if _BENIGN_PATTERNS is None:
        from miesc.ml.benign_context_verifier import load_benign_patterns
        _BENIGN_PATTERNS = load_benign_patterns()
    return _BENIGN_PATTERNS


def _structural_features(finding: dict[str, Any], code: str) -> list[float]:
    """The 12 structural signals the deterministic recall-safe verifier uses, as numbers."""
    from miesc.ml.benign_context_verifier import (
        _CONTEXTUAL_BENIGN, _extract_function, _func_signature, _function_at_line,
        _is_cei, _timestamp_is_benign, match_benign,
    )

    _loc = finding.get("location")
    loc = _loc if isinstance(_loc, dict) else {}
    fn = finding.get("function") or loc.get("function") or ""
    line = finding.get("line") or loc.get("line") or 0
    try:
        line = int(line)
    except (TypeError, ValueError):
        line = 0
    f2 = {"type": finding.get("type"), "title": finding.get("check") or finding.get("title"),
          "location": {"function": fn, "line": line}}
    benign = match_benign(f2, code, _benign_patterns())
    has_benign = 1.0 if benign else 0.0
    is_ctx = 1.0 if (benign and benign["id"] in _CONTEXTUAL_BENIGN) else 0.0
    is_det = 1.0 if (benign and benign["id"] not in _CONTEXTUAL_BENIGN) else 0.0
    if fn and fn not in ("unknown", ""):
        body, sig = _extract_function(code, fn), _func_signature(code, fn)
    elif line:
        body, sig = _function_at_line(code, line)
    else:
        body, sig = "", ""
    scoped = 1.0 if body else 0.0
    has_guard = 1.0 if re.search(r"nonReentrant|ReentrancyGuard|onlyOwner|onlyRole", sig or "") else 0.0
    is_cei = 1.0 if (body and _is_cei(body)) else 0.0
    ts_benign = 1.0 if (body and _timestamp_is_benign(body)) else 0.0
    pragma08 = 1.0 if re.search(r"pragma\s+solidity\s*\^?0\.8", code) else 0.0
    lines = code.splitlines()
    flagged = lines[line - 1] if (1 <= line <= len(lines)) else ""
    window = " ".join(lines[line - 1:line + 2]) if flagged else ""
    checked = 1.0 if re.search(r"require\s*\(\s*(ok|success)", window) else 0.0
    native_transfer = 1.0 if (re.search(r"\.transfer\(", flagged)
                              and not re.search(r"\.transfer\([^)]*,", flagged)) else 0.0
    safeerc = 1.0 if re.search(r"safeTransfer|SafeERC20", flagged) else 0.0
    body_len = min(len(body) / 2000.0, 1.0)
    return [has_benign, is_ctx, is_det, scoped, has_guard, is_cei, ts_benign,
            pragma08, checked, native_transfer, safeerc, body_len]


def features_for(finding: dict[str, Any], code: str) -> list[float]:
    """Coarse FP features (17) + structural signals (12) -> the 29-d feature vector."""
    from miesc.ml.fp_ml_classifier import extract_features
    coarse = list(extract_features(finding, code).to_vector())
    return coarse + _structural_features(finding, code)


class TriageRanker:
    """Loads a persisted triage model and ranks findings by P(real) — recall-safe."""

    def __init__(self, model_path: str = DEFAULT_MODEL_PATH):
        self.model = None
        self.model_path = model_path
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self.model_path):
            return
        try:
            import joblib
            self.model = joblib.load(self.model_path)
        except Exception:  # noqa: BLE001 — missing joblib/sklearn or stale model -> degrade
            self.model = None

    def available(self) -> bool:
        return self.model is not None

    def score(self, finding: dict[str, Any], code: str) -> Optional[float]:
        """P(real) in [0,1], or None when no model is available."""
        if self.model is None:
            return None
        try:
            return float(self.model.predict_proba([features_for(finding, code)])[0][1])
        except Exception:  # noqa: BLE001 — never let scoring break a scan
            return None

    def rank(
        self,
        findings: list[dict[str, Any]],
        code_lookup: Callable[[dict[str, Any]], str],
    ) -> list[dict[str, Any]]:
        """Return findings ordered by P(real) descending. NEVER drops any finding (recall 1.0).
        Annotates each with `triage_score`. If no model, returns findings unchanged."""
        if self.model is None:
            return findings
        scored = []
        for f in findings:
            s = self.score(f, code_lookup(f) or "")
            if s is not None:
                f["triage_score"] = round(s, 4)
            scored.append((f, s if s is not None else -1.0))
        scored.sort(key=lambda x: x[1], reverse=True)
        return [f for f, _ in scored]


def rank_results(all_results: list[dict[str, Any]], *, contract: str = "") -> int:
    """Reorder each result's findings by P(real), in place — recall-safe (never drops).
    Shared by `miesc scan --rank` and `miesc audit --rank`. Reads each finding's source for
    feature extraction (by finding `file`, else the `contract` path). Returns the number of
    findings ranked, or -1 when no trained model is available (caller leaves order unchanged)."""
    ranker = TriageRanker()
    if not ranker.available():
        return -1
    cache: dict[str, str] = {}

    def code_for(f: dict[str, Any]) -> str:
        _loc = f.get("location")
        loc = _loc if isinstance(_loc, dict) else {}
        path = f.get("file") or loc.get("file") or contract
        if path not in cache:
            try:
                cache[path] = open(path, errors="ignore").read()
            except Exception:  # noqa: BLE001
                cache[path] = ""
        return cache[path]

    total = 0
    for result in all_results:
        fs = result.get("findings") or []
        if fs:
            result["findings"] = ranker.rank(fs, code_for)
            total += len(fs)
    return total


def train(dataset_path: str, model_path: str = DEFAULT_MODEL_PATH) -> dict[str, Any]:
    """Train the GradientBoosting triage model on a labeled JSONL dataset
    ({"finding": {...}, "context": "...", "label": true/false}; True = real) and persist it.
    Returns held-out metrics (AUC + the recall-safe baseline). Requires scikit-learn."""
    import json

    import joblib
    import numpy as np
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.metrics import roc_auc_score
    from sklearn.model_selection import train_test_split

    rows = [json.loads(l) for l in open(dataset_path) if l.strip()]
    X = np.array([features_for(r["finding"], r.get("context", "")) for r in rows])
    y = np.array([1 if r["label"] else 0 for r in rows])
    if len(set(y.tolist())) < 2 or len(y) < 20:
        raise ValueError(f"need >=20 samples with both classes; got {len(y)}")
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
    # n_estimators/max_depth tuned by 5-fold CV AUC (0.932 -> 0.949); triage never drops, so
    # a higher-AUC (better-ordering) model carries no recall risk.
    model = GradientBoostingClassifier(n_estimators=400, max_depth=4, random_state=42)
    model.fit(Xtr, ytr)
    auc = float(roc_auc_score(yte, model.predict_proba(Xte)[:, 1]))
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    joblib.dump(model, model_path)
    return {"samples": len(y), "real": int(y.sum()), "fp": int((y == 0).sum()),
            "features": X.shape[1], "heldout_auc": round(auc, 4), "model_path": model_path}
