"""Tell dependency files apart from the contract under audit.

Slither and Aderyn compile (and report on) every file the target reaches:
its relatively imported siblings *and* the packages under ``lib/`` or
``node_modules/``. A lint on ``lib/openzeppelin-contracts/.../Ownable.sol``
is not a finding about the target, but one on a sibling ``Helper.sol`` that
the target inherits from is: dropping it is a false negative. So the filter
removes only dependency files and keeps everything else, including findings
with no source mapping and siblings imported by non-relative project paths
(``src/B.sol``, a project-defined remapping).

Author: Fernando Boiero
License: AGPL-3.0
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable


def is_dependency_file(path: str, root: Path, prefixes: Iterable[str]) -> bool:
    """True if ``path`` (absolute, or relative to ``root``) is a dependency.

    A dependency lives under ``root/lib/``, anywhere under a
    ``node_modules/`` directory, or is named by a package import prefix such
    as ``@openzeppelin/``. An empty path (no source mapping) is never one.
    """
    if not path:
        return False
    rel = Path(path)
    if rel.is_absolute():
        try:
            rel = rel.resolve().relative_to(root.resolve())
        except ValueError:
            pass
    return (
        "node_modules" in rel.parts or rel.parts[:1] == ("lib",) or path.startswith(tuple(prefixes))
    )
