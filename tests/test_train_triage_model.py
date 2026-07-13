"""
Test for the triage training dataset builder (scripts/train_triage_model.py::build_dataset):
reshapes wild-harness anchored labels into the classifier dataset format with dedup.
No network / no sklearn needed.
"""

import importlib.util
import json
import os
import sys

_SCRIPTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
sys.path.insert(0, _SCRIPTS)
_SPEC = importlib.util.spec_from_file_location(
    "train_triage_model", os.path.join(_SCRIPTS, "train_triage_model.py")
)
ttm = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(ttm)


def test_build_dataset_reshapes_and_dedups(tmp_path, monkeypatch):
    wild = tmp_path / "wild.jsonl"
    rows = [
        # real vuln
        {
            "type": "reentrancy",
            "check": "reentrancy_crossfunction",
            "severity": "high",
            "function": "w",
            "line": 5,
            "contract": "A.sol",
            "code": "contract A{}",
            "label": True,
        },
        # benign FP
        {
            "type": "arithmetic",
            "check": "arithmetic",
            "severity": "medium",
            "function": "a",
            "line": 9,
            "contract": "B.sol",
            "code": "contract B{}",
            "label": False,
        },
        # exact duplicate of the first (same check/line/contract/label) -> deduped
        {
            "type": "reentrancy",
            "check": "reentrancy_crossfunction",
            "severity": "high",
            "function": "w",
            "line": 5,
            "contract": "A.sol",
            "code": "contract A{}",
            "label": True,
        },
        # unanchored (label None) -> skipped
        {"type": "x", "check": "x", "line": 1, "contract": "C.sol", "code": "c", "label": None},
    ]
    wild.write_text("\n".join(json.dumps(r) for r in rows))
    monkeypatch.setattr(ttm, "WILD_GLOBS", [str(wild)])

    out = tmp_path / "ds.jsonl"
    n = ttm.build_dataset(str(out))
    assert n == 2  # dedup dropped the repeat; None-label skipped

    built = [json.loads(l) for l in open(out)]
    assert len(built) == 2
    # shape: {finding: {...}, context, label}
    for b in built:
        assert set(b) >= {"finding", "context", "label"}
        assert set(b["finding"]) >= {"type", "check", "severity", "function", "line"}
    labels = sorted(b["label"] for b in built)
    assert labels == [False, True]
    real = next(b for b in built if b["label"])
    assert real["finding"]["check"] == "reentrancy_crossfunction"
    assert real["context"] == "contract A{}"
