"""
MIESC Finding Baseline & Suppression Engine

Lets MIESC run in CI on an existing codebase by recording the set of findings
that are already known ("the baseline") and, on subsequent runs, suppressing
those known findings so the build fails only on *new* ones.

The baseline keys findings on a **content-based fingerprint** (rule id +
normalized file path + a hash of the normalized message) rather than on line
numbers. This means that inserting or deleting lines above a finding does not
cause it to be re-flagged as new — a property that makes the engine usable on
real, actively-developed codebases.

The on-disk format (``.miesc-baseline.json``) is stable, sorted and
deterministic so it is diffable in version control and golden-file testable.

Author: Fernando Boiero
License: AGPL-3.0
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Union

# Version of the on-disk baseline schema. Bump on breaking format changes.
BASELINE_FORMAT_VERSION = "1.0"

# Default filename written by ``generate_baseline`` / the ``baseline generate``
# command and consumed by the ``--baseline`` CLI flags.
DEFAULT_BASELINE_FILENAME = ".miesc-baseline.json"

# A finding may arrive either as a MIESC ``Finding`` dataclass or as a plain
# dict (the shape persisted in a saved results JSON). We accept both.
FindingLike = Union[Mapping[str, Any], Any]

_WHITESPACE_RE = re.compile(r"\s+")


@dataclass(frozen=True)
class BaselineEntry:
    """Minimal, content-addressable record of a single known finding."""

    fingerprint: str
    rule_id: str
    file: str
    message_hash: str
    severity: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "file": self.file,
            "message_hash": self.message_hash,
            "severity": self.severity,
        }


@dataclass
class Baseline:
    """A set of known findings keyed by content fingerprint."""

    entries: Dict[str, BaselineEntry]
    version: str = BASELINE_FORMAT_VERSION

    def __contains__(self, fingerprint: str) -> bool:
        return fingerprint in self.entries

    def __len__(self) -> int:
        return len(self.entries)

    def to_dict(self) -> Dict[str, Any]:
        """Return a JSON-serializable, deterministically-ordered mapping."""
        return {
            "version": self.version,
            "fingerprint_algorithm": "sha256-content-16",
            "count": len(self.entries),
            "fingerprints": {
                fp: self.entries[fp].to_dict() for fp in sorted(self.entries)
            },
        }

    def to_json(self) -> str:
        """Serialize to stable, sorted, deterministic JSON (trailing newline)."""
        return (
            json.dumps(self.to_dict(), indent=2, sort_keys=True, ensure_ascii=False)
            + "\n"
        )

    def save(self, path: Union[str, Path] = DEFAULT_BASELINE_FILENAME) -> Path:
        """Write the baseline to ``path`` and return the resolved path."""
        out = Path(path)
        out.write_text(self.to_json(), encoding="utf-8")
        return out

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Baseline":
        raw = data.get("fingerprints", {})
        entries: Dict[str, BaselineEntry] = {}
        for fp, meta in raw.items():
            entries[fp] = BaselineEntry(
                fingerprint=fp,
                rule_id=str(meta.get("rule_id", "")),
                file=str(meta.get("file", "")),
                message_hash=str(meta.get("message_hash", "")),
                severity=str(meta.get("severity", "")),
            )
        return cls(entries=entries, version=str(data.get("version", BASELINE_FORMAT_VERSION)))


# ---------------------------------------------------------------------------
# Finding normalization + fingerprinting
# ---------------------------------------------------------------------------


def _get(finding: FindingLike, *keys: str, default: str = "") -> str:
    """Read the first present key from a dict-like or attribute-based finding."""
    if isinstance(finding, Mapping):
        for key in keys:
            if key in finding and finding[key] not in (None, ""):
                return str(finding[key])
        return default
    for key in keys:
        val = getattr(finding, key, None)
        if val not in (None, ""):
            return str(val)
    return default


def _extract_file(finding: FindingLike) -> str:
    """Resolve the source file for a finding across the known shapes."""
    # Nested ``location`` dict (tool-native shape) takes precedence.
    if isinstance(finding, Mapping):
        loc = finding.get("location")
        if isinstance(loc, Mapping):
            file_val = loc.get("file") or loc.get("file_path") or loc.get("filename")
            if file_val:
                return _normalize_path(str(file_val))
    return _normalize_path(_get(finding, "file", "file_path", "filename"))


def _normalize_path(path: str) -> str:
    """Normalize a file path for stable cross-run / cross-machine matching.

    - forward slashes
    - drop a leading ``./``
    - collapse redundant separators via ``PurePosixPath``

    The path is intentionally left relative-or-absolute as given; we do not
    reduce to a basename (that would collide across directories).
    """
    if not path:
        return ""
    normalized = path.replace("\\", "/").strip()
    if normalized.startswith("./"):
        normalized = normalized[2:]
    # Collapse duplicate slashes and ``.`` segments without resolving symlinks.
    parts = [p for p in normalized.split("/") if p not in ("", ".")]
    prefix = "/" if normalized.startswith("/") else ""
    return prefix + "/".join(parts)


def _normalize_message(message: str) -> str:
    """Collapse whitespace so cosmetic reformatting does not change the hash."""
    return _WHITESPACE_RE.sub(" ", message).strip()


def _message_hash(message: str) -> str:
    return hashlib.sha256(_normalize_message(message).encode("utf-8")).hexdigest()[:16]


def normalize_finding(finding: FindingLike) -> Dict[str, str]:
    """Reduce a heterogeneous finding to the canonical fields we fingerprint."""
    rule_id = _get(finding, "type", "rule_id", "check", "title", default="unknown")
    file = _extract_file(finding)
    message = _get(finding, "message", "description", "title", default="")
    severity = _get(finding, "severity", default="").lower()
    return {
        "rule_id": rule_id,
        "file": file,
        "message": message,
        "message_hash": _message_hash(message),
        "severity": severity,
    }


def fingerprint(finding: FindingLike) -> str:
    """Return the content-based fingerprint for a finding (line-shift stable)."""
    norm = normalize_finding(finding)
    content = f"{norm['rule_id']}|{norm['file']}|{norm['message_hash']}"
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]


def _to_entry(finding: FindingLike) -> BaselineEntry:
    norm = normalize_finding(finding)
    return BaselineEntry(
        fingerprint=fingerprint(finding),
        rule_id=norm["rule_id"],
        file=norm["file"],
        message_hash=norm["message_hash"],
        severity=norm["severity"],
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_baseline(findings: Iterable[FindingLike]) -> Baseline:
    """Build a :class:`Baseline` from an iterable of findings.

    Findings that reduce to the same fingerprint are collapsed into a single
    entry (natural deduplication).
    """
    entries: Dict[str, BaselineEntry] = {}
    for finding in findings:
        entry = _to_entry(finding)
        entries.setdefault(entry.fingerprint, entry)
    return Baseline(entries=entries)


def load_baseline(path: Union[str, Path]) -> Baseline:
    """Load a baseline from a ``.miesc-baseline.json`` file."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return Baseline.from_dict(data)


def diff_against_baseline(
    findings: Iterable[FindingLike], baseline: Baseline
) -> Dict[str, List[Any]]:
    """Partition current findings against a baseline.

    Returns a dict with three keys:

    - ``new``   — current findings whose fingerprint is *not* in the baseline.
    - ``known`` — current findings whose fingerprint *is* in the baseline
      (these are the "already accepted" findings to suppress).
    - ``fixed`` — :class:`BaselineEntry` records present in the baseline but not
      seen in the current run (candidates the codebase has resolved).

    ``new`` and ``known`` preserve the original finding objects/dicts; ``fixed``
    yields the baseline entries.
    """
    new: List[Any] = []
    known: List[Any] = []
    seen: set[str] = set()

    for finding in findings:
        fp = fingerprint(finding)
        seen.add(fp)
        if fp in baseline:
            known.append(finding)
        else:
            new.append(finding)

    fixed = [entry for fp, entry in baseline.entries.items() if fp not in seen]

    return {"new": new, "known": known, "fixed": fixed}
