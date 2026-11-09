"""Shared Solidity source loader for file-based adapters.

File-based adapters (LLM/AI, pattern analyzers) read contract source text and do
not compile. When ``miesc audit full`` is pointed at a project **directory**
(required by the compilation-based tools such as Slither/Mythril/Medusa), these
adapters used to crash on ``open(<dir>)`` with ``[Errno 21] Is a directory``.

This loader resolves a path to source text whether it is a single ``.sol`` file
or a project directory. For a directory it concatenates the first-party,
in-scope ``.sol`` files (preferring ``src/`` / ``contracts/`` and excluding
dependencies, tests and scripts), bounded to a character budget so the combined
source still fits a model context window.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator, Optional

# Directory names that are never first-party contract scope.
_EXCLUDE_DIRS = {
    "lib",
    "node_modules",
    "out",
    "cache",
    "artifacts",
    "coverage",
    ".git",
    "test",
    "tests",
    "script",
    "scripts",
    "mocks",
    "mock",
}

# Preferred first-party source roots, in priority order.
_PREFERRED_SUBDIRS = ("src", "contracts")

# Default budget for concatenated directory source (characters). Large enough for
# a mid-size protocol, small enough to stay within common local-model contexts.
DEFAULT_MAX_CHARS = 200_000


def iter_scope_files(root: Path) -> Iterator[Path]:
    """Yield first-party, in-scope ``.sol`` files under ``root``.

    Prefers ``src/`` or ``contracts/`` when present; otherwise scans ``root``.
    Skips dependency/test/script directories and ``*.t.sol`` test files.
    """
    bases = [root / sub for sub in _PREFERRED_SUBDIRS if (root / sub).is_dir()]
    if not bases:
        bases = [root]

    for base in bases:
        for path in sorted(base.rglob("*.sol")):
            rel_parts = set(path.relative_to(root).parts[:-1])
            if rel_parts & _EXCLUDE_DIRS:
                continue
            if path.name.endswith(".t.sol"):
                continue
            yield path


def load_contract_source(
    contract_path: str | Path,
    max_chars: int = DEFAULT_MAX_CHARS,
) -> Optional[str]:
    """Return Solidity source text for a file or a project directory.

    - File: returns the file's contents.
    - Directory: concatenates in-scope ``.sol`` files with ``// FILE:`` headers,
      bounded to ``max_chars``.

    Returns ``None`` if nothing readable is found.
    """
    path = Path(contract_path)

    if path.is_file():
        try:
            return path.read_text(encoding="utf-8")
        except Exception:
            return None

    if path.is_dir():
        chunks: list[str] = []
        total = 0
        for sol in iter_scope_files(path):
            try:
                src = sol.read_text(encoding="utf-8")
            except Exception:
                continue
            try:
                rel = sol.relative_to(path)
            except ValueError:
                rel = sol
            block = f"// ===== FILE: {rel} =====\n{src}\n\n"
            if total + len(block) > max_chars and chunks:
                break
            chunks.append(block)
            total += len(block)
        return "".join(chunks) if chunks else None

    return None
