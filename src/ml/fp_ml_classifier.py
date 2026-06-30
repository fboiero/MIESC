"""
Auditor-Trained False Positive Classifier
==========================================

Trains a lightweight scikit-learn classifier on auditor-validated findings
to predict whether a given finding is a true positive or false positive.

Unlike the rule-based FP filter (src/ml/fp_filter.py) and the heuristic
feature classifier (src/ml/fp_classifier.py), this model LEARNS from
user-provided data — letting teams improve precision over time with
their own validated findings.

Features extracted from each finding:
  1. severity (ordinal: CRITICAL=4, HIGH=3, ...)
  2. tool (one-hot: slither, aderyn, mythril, etc.)
  3. vuln type (bag-of-words over normalized types)
  4. confidence score (float)
  5. has SWC ID (binary)
  6. contract context length (int, bucketed)
  7. known library used (binary: OpenZeppelin, Solmate)
  8. solidity version >= 0.8 (binary)

Training data format (CSV or JSONL):
  {
    "severity": "high",
    "tool": "slither",
    "type": "reentrancy-eth",
    "confidence": 0.75,
    "swc_id": "SWC-107",
    "context": "<50 chars of code>",
    "label": true  // true = real bug, false = false positive
  }

Usage:
    from src.ml.fp_ml_classifier import AuditorTrainedFPClassifier

    clf = AuditorTrainedFPClassifier()
    clf.train("data/auditor_labels.jsonl")
    proba = clf.predict_fp_probability(finding, code_context)
    # proba < 0.5 => likely true positive

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
License: AGPL-3.0
"""

from __future__ import annotations

import json
import logging
import pickle
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# =============================================================================
# Feature engineering
# =============================================================================


SEVERITY_ORDINAL = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
    "informational": 0,
}

KNOWN_TOOLS = [
    "slither",
    "aderyn",
    "mythril",
    "solhint",
    "semgrep",
    "halmos",
    "echidna",
    "manticore",
    "smartllm",
    "gptscan",
]

KNOWN_LIBRARIES = [
    "openzeppelin",
    "solmate",
    "@openzeppelin",
    "safeerc20",
    "reentrancyguard",
    "ownable",
    "access control",
]


@dataclass
class AuditorFindingFeatures:
    """Engineered features for a single finding (auditor-trained model)."""

    severity_ord: int = 0
    confidence: float = 0.5
    has_swc: int = 0
    tool_onehot: List[int] = field(default_factory=lambda: [0] * len(KNOWN_TOOLS))
    vuln_type_hash: int = 0
    context_length_bucket: int = 0  # 0=tiny, 1=short, 2=medium, 3=long
    has_library: int = 0
    solidity_0_8_plus: int = 0

    def to_vector(self) -> List[float]:
        """Convert to a flat feature vector for sklearn."""
        v = [
            float(self.severity_ord),
            float(self.confidence),
            float(self.has_swc),
            float(self.vuln_type_hash % 1000) / 1000.0,
            float(self.context_length_bucket),
            float(self.has_library),
            float(self.solidity_0_8_plus),
        ]
        v.extend(float(x) for x in self.tool_onehot)
        return v


def extract_features(
    finding: Dict[str, Any],
    code_context: str = "",
) -> AuditorFindingFeatures:
    """Extract features from a single finding + code context."""
    f = AuditorFindingFeatures()

    # Severity
    sev = str(finding.get("severity", "")).lower()
    f.severity_ord = SEVERITY_ORDINAL.get(sev, 0)

    # Confidence (some adapters provide it)
    try:
        f.confidence = float(finding.get("confidence", 0.5))
    except (TypeError, ValueError):
        f.confidence = 0.5

    # SWC ID present
    f.has_swc = 1 if finding.get("swc_id") or finding.get("swc") else 0

    # Tool one-hot
    tool = str(finding.get("tool", "")).lower()
    for i, t in enumerate(KNOWN_TOOLS):
        if t in tool:
            f.tool_onehot[i] = 1

    # Vuln type (hashed int for bag-of-words-like signal)
    vuln_type = str(finding.get("type", finding.get("check", ""))).lower()
    f.vuln_type_hash = hash(vuln_type) & 0xFFFFFF

    # Code context features
    ctx = code_context.lower()
    length = len(ctx)
    if length < 500:
        f.context_length_bucket = 0
    elif length < 2000:
        f.context_length_bucket = 1
    elif length < 10000:
        f.context_length_bucket = 2
    else:
        f.context_length_bucket = 3

    f.has_library = int(any(lib in ctx for lib in KNOWN_LIBRARIES))

    # Solidity 0.8+
    m = re.search(r"pragma\s+solidity\s*[\^>=]*\s*(\d+)\.(\d+)", ctx)
    if m:
        major, minor = int(m.group(1)), int(m.group(2))
        f.solidity_0_8_plus = int(major > 0 or minor >= 8)

    return f


# =============================================================================
# Classifier
# =============================================================================


class AuditorTrainedFPClassifier:
    """scikit-learn based FP/TP classifier trained on auditor-labeled findings.

    Falls back to rule-based scoring when sklearn is unavailable or
    the model isn't trained yet.
    """

    DEFAULT_MODEL_PATH = Path.home() / ".miesc" / "models" / "fp_auditor_classifier.pkl"

    def __init__(self, model_path: Optional[Path] = None):
        self.model_path = model_path or self.DEFAULT_MODEL_PATH
        self.model: Any = None
        self._sklearn_available = self._check_sklearn()
        self._load_model()

    @staticmethod
    def _check_sklearn() -> bool:
        try:
            import sklearn  # noqa: F401

            return True
        except ImportError:
            logger.debug("scikit-learn not installed; using rule-based fallback")
            return False

    def _load_model(self) -> None:
        """Load a pre-trained model if available."""
        if not self.model_path.exists():
            return
        try:
            with open(self.model_path, "rb") as f:
                self.model = pickle.load(f)
            logger.info(f"Loaded FP classifier from {self.model_path}")
        except Exception as e:
            logger.warning(f"Failed to load FP model: {e}")
            self.model = None

    def save_model(self, path: Optional[Path] = None) -> None:
        """Persist the trained model."""
        target = path or self.model_path
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "wb") as f:
            pickle.dump(self.model, f)
        logger.info(f"Saved FP classifier to {target}")

    def train(self, dataset_path: str) -> Dict[str, float]:
        """Train on a JSONL dataset of labeled findings.

        Dataset format (one JSON per line):
            {"finding": {...}, "context": "...", "label": true/false}

        Returns training metrics: accuracy, precision, recall.
        """
        if not self._sklearn_available:
            raise RuntimeError("scikit-learn required for training. Install: pip install miesc[ml]")

        from sklearn.ensemble import GradientBoostingClassifier
        from sklearn.metrics import precision_recall_fscore_support
        from sklearn.model_selection import train_test_split

        X, y = self._load_dataset(dataset_path)
        if len(X) < 10:
            raise ValueError(
                f"Need at least 10 training samples, got {len(X)}. "
                "Collect more auditor-validated findings."
            )

        # Split & train
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )

        self.model = GradientBoostingClassifier(
            n_estimators=100,
            max_depth=3,
            random_state=42,
        )
        self.model.fit(X_train, y_train)

        # Evaluate
        y_pred = self.model.predict(X_test)
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_test, y_pred, average="binary", zero_division=0
        )
        accuracy = self.model.score(X_test, y_test)

        metrics = {
            "accuracy": round(accuracy, 3),
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1": round(f1, 3),
            "train_samples": len(X_train),
            "test_samples": len(X_test),
        }
        logger.info(f"FP classifier trained: {metrics}")

        self.save_model()
        return metrics

    def predict_fp_probability(
        self,
        finding: Dict[str, Any],
        code_context: str = "",
    ) -> float:
        """
        Predict probability that this finding is a FALSE POSITIVE.

        Returns 0.0 (definitely real) → 1.0 (definitely FP).

        If no trained model is available, falls back to a simple rule-based
        heuristic (identical behavior to rule-based fp_filter).
        """
        features = extract_features(finding, code_context)

        if self.model is not None and self._sklearn_available:
            vec = [features.to_vector()]
            # Some sklearn classifiers use predict_proba; else decision_function
            if hasattr(self.model, "predict_proba"):
                # class 0 = FP (label=False), class 1 = TP (label=True)
                # We want P(FP) = P(class=0)
                proba = self.model.predict_proba(vec)[0]
                # The label mapping depends on training; conventionally False=0
                return float(proba[0])
            pred = self.model.predict(vec)[0]
            return 1.0 if pred == 0 else 0.0

        # Rule-based fallback
        return self._heuristic_fp_probability(features)

    def _heuristic_fp_probability(self, f: AuditorFindingFeatures) -> float:
        """Fallback heuristic when no trained model available."""
        score = 0.3  # base

        # Low severity → more likely FP
        if f.severity_ord <= 1:
            score += 0.3
        # Known library → more likely FP (safe patterns)
        if f.has_library:
            score += 0.2
        # No SWC → more likely noise
        if not f.has_swc:
            score += 0.1
        # Low confidence → more likely FP
        if f.confidence < 0.5:
            score += 0.2
        # Solidity 0.8+ AND overflow-type → almost certainly FP
        if f.solidity_0_8_plus and f.vuln_type_hash % 100 < 20:
            # crude bucket to flag arithmetic-related types
            score += 0.3

        return min(score, 1.0)

    def _load_dataset(self, path: str) -> Tuple[List[List[float]], List[int]]:
        """Load labeled findings from JSONL."""
        X: List[List[float]] = []
        y: List[int] = []
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue

                finding = row.get("finding", row)
                context = row.get("context", "")
                label = row.get("label", None)
                if label is None:
                    continue

                feat = extract_features(finding, context)
                X.append(feat.to_vector())
                y.append(1 if label else 0)
        return X, y

    def is_trained(self) -> bool:
        return self.model is not None


def create_sample_dataset(output_path: Path, n: int = 20) -> int:
    """
    Create a synthetic labeled dataset for demonstration/testing.

    In production, this would be replaced by real auditor-validated findings
    collected over time.
    """
    import random

    random.seed(42)

    samples = []
    # True positives (real bugs)
    tp_templates = [
        ("reentrancy-eth", "high", "slither", 0.9, "SWC-107", True),
        ("selfdestruct-identifier", "high", "aderyn", 0.95, "SWC-106", True),
        ("delegate-call-unchecked-address", "high", "aderyn", 0.9, "SWC-112", True),
        ("weak-randomness", "high", "aderyn", 0.85, "SWC-120", True),
        ("unchecked-return", "medium", "aderyn", 0.8, "SWC-104", True),
        ("tx-origin", "medium", "slither", 0.85, "SWC-115", True),
    ]
    # False positives (noise)
    fp_templates = [
        ("solc-version", "info", "slither", 0.3, None, False),
        ("naming-convention", "info", "slither", 0.2, None, False),
        ("unspecific-solidity-pragma", "low", "aderyn", 0.4, None, False),
        ("useless-public-function", "low", "aderyn", 0.3, None, False),
        ("push-zero-opcode", "info", "aderyn", 0.2, None, False),
        ("constants-instead-of-literals", "low", "aderyn", 0.3, None, False),
    ]

    def row(tmpl: Any) -> Any:
        vuln_type, sev, tool, conf, swc, label = tmpl
        finding = {
            "type": vuln_type,
            "severity": sev,
            "tool": tool,
            "confidence": conf,
        }
        if swc:
            finding["swc_id"] = swc
        context = "pragma solidity ^0.8.20;\ncontract T { function f() public {} }"
        return {"finding": finding, "context": context, "label": label}

    for _ in range(n // 2):
        samples.append(row(random.choice(tp_templates)))
        samples.append(row(random.choice(fp_templates)))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        for s in samples:
            f.write(json.dumps(s) + "\n")

    return len(samples)
