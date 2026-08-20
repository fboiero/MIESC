"""Tests for the model-deserialization guard.

pickle.load / joblib.load execute arbitrary code. MIESC refuses to deserialize a
model file that is writable by group or others (another user could have replaced
it with a malicious payload), following the principle SSH uses for private keys.
"""

import os
import pickle
import sys
from pathlib import Path

import pytest

from miesc.ml.fp_ml_classifier import AuditorTrainedFPClassifier
from miesc.ml.triage_ranker import TriageRanker
from miesc.security.safe_deserialize import (
    is_group_or_world_writable,
    safe_to_deserialize,
)

posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX permission bits not meaningful on Windows"
)


def _write_model(path: Path, mode: int, obj=None) -> Path:
    path.write_bytes(pickle.dumps(obj if obj is not None else {"is_dummy": True}))
    os.chmod(path, mode)
    return path


# --------------------------------------------------------------------------- #
# Helper unit tests
# --------------------------------------------------------------------------- #


@posix_only
@pytest.mark.parametrize(
    "mode,expected",
    [
        (0o600, False),
        (0o644, False),
        (0o664, True),  # group-writable
        (0o666, True),  # group + world writable
        (0o602, True),  # world-writable
    ],
)
def test_is_group_or_world_writable(tmp_path, mode, expected):
    f = _write_model(tmp_path / "m.pkl", mode)
    assert is_group_or_world_writable(f) is expected


def test_is_group_or_world_writable_missing_path(tmp_path):
    assert is_group_or_world_writable(tmp_path / "nope.pkl") is False


@posix_only
def test_safe_to_deserialize(tmp_path):
    safe = _write_model(tmp_path / "safe.pkl", 0o600)
    unsafe = _write_model(tmp_path / "unsafe.pkl", 0o666)
    assert safe_to_deserialize(safe) is True
    assert safe_to_deserialize(unsafe) is False


# --------------------------------------------------------------------------- #
# Loader integration
# --------------------------------------------------------------------------- #


@posix_only
def test_fp_classifier_refuses_group_writable_model(tmp_path):
    """A group/world-writable model must NOT be deserialized."""
    model = _write_model(tmp_path / "fp.pkl", 0o666)
    clf = AuditorTrainedFPClassifier(model_path=model)
    assert clf.model is None


@posix_only
def test_fp_classifier_loads_owner_only_model(tmp_path):
    """A 0600 model is trusted and loads normally (no false refusal)."""
    model = _write_model(tmp_path / "fp.pkl", 0o600, obj={"is_dummy": True})
    clf = AuditorTrainedFPClassifier(model_path=model)
    assert clf.model == {"is_dummy": True}


@posix_only
def test_triage_ranker_refuses_group_writable_model(tmp_path):
    """The refusal happens before joblib is even imported, so no joblib needed."""
    model = _write_model(tmp_path / "triage.joblib", 0o664)
    ranker = TriageRanker(model_path=str(model))
    assert ranker.model is None
