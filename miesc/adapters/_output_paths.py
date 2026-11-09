"""Per-run output files for tools that write their JSON report to disk.

Slither and Aderyn used fixed paths (``/tmp/slither_output.json``,
``/tmp/aderyn_output.json``). Two MIESC processes on the same machine — a
``make bench`` and a ``miesc scan``, or parallel CI jobs — then read each
other's output and attributed one contract's findings to another (observed
on 2026-10-20: two SmartBugs contracts flipped during a benchmark because a
scan ran at the same time). Each run now gets its own file and removes it.

Author: Fernando Boiero
License: AGPL-3.0
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def new_output_path(tool: str, suffix: str = ".json") -> str:
    """Return a unique, not-yet-existing path for ``tool``'s report.

    The file is created and immediately removed so the name is reserved by
    this process but the tool sees a clean slate (several tools refuse to
    overwrite or append to an existing report).
    """
    fd, path = tempfile.mkstemp(prefix=f"miesc-{tool}-", suffix=suffix)
    os.close(fd)
    Path(path).unlink(missing_ok=True)
    return path


def discard_output_path(path: str | None, owned: bool) -> None:
    """Remove a report file this run created; leave caller-supplied paths alone."""
    if owned and path:
        Path(path).unlink(missing_ok=True)
