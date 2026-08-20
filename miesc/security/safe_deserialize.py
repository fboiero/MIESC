"""Guard against deserializing model files another user could have tampered with.

``pickle.load`` / ``joblib.load`` execute arbitrary code during deserialization.
MIESC's ML models (the FP classifier, the triage ranker) are trained locally and
written to fixed paths, so the file is normally the user's own trusted artifact.
But if that file is writable by *other* users — a shared/multi-user host, a
world-writable cache directory, a poisoned image layer — another party could
replace it with a code-executing payload that runs the next time a scan loads it.

Following the principle SSH applies to private keys, refuse to deserialize a
model file that is writable by group or others. The check is POSIX-based and a
no-op where mode bits are not exposed; callers fail safe (model stays ``None``,
degrading to the rule-based path) rather than raising.
"""

from __future__ import annotations

import logging
import os
import stat
from pathlib import Path
from typing import Union

logger = logging.getLogger(__name__)

PathLike = Union[str, Path]


def is_group_or_world_writable(path: PathLike) -> bool:
    """Return True if ``path`` is writable by group or others (POSIX mode bits).

    Returns False when the path is missing or the platform/filesystem does not
    expose POSIX permission bits, where the check is not meaningful.
    """
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return False
    return bool(mode & (stat.S_IWGRP | stat.S_IWOTH))


def safe_to_deserialize(path: PathLike) -> bool:
    """True if ``path`` is safe to pickle/joblib-load (not writable by others).

    Logs a warning and returns False when the file is group/world-writable,
    since another user could have replaced it with a malicious payload.
    """
    if is_group_or_world_writable(path):
        logger.warning(
            "Refusing to deserialize %s: file is writable by group/other; another "
            "user could replace it with a code-executing payload. Fix: chmod go-w %s",
            path,
            path,
        )
        return False
    return True
