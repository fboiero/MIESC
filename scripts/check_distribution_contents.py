#!/usr/bin/env python3
"""Validate release artifact contents before publishing."""

from __future__ import annotations

import argparse
import re
import sys
import tarfile
import zipfile
from pathlib import Path

BLOCKED_PATTERNS = (
    re.compile(r"(^|/)src/(tests|miesc_tests)(/|$)"),
    re.compile(r"(^|/)src/.* 2(/|\.py$)"),
    re.compile(r"(^|/)miesc-[^/]+\.(dist-info|egg-info)/.* [0-9](\.[^/]+)?$"),
    re.compile(r"(^|/)webapp(/|$)"),
    re.compile(r"(^|/)\.streamlit(/|$)"),
    re.compile(r"(^|/)src/(dashboard|licensing)(/|$)"),
    re.compile(r"(^|/)vscode-extension(/|$)"),
    re.compile(r"(^|/)streamlit_app\.py$"),
)

BLOCKED_METADATA_LINES = (
    re.compile(r"^Provides-Extra:\s+web\s*$", re.IGNORECASE),
    re.compile(r"^Requires-Dist:\s+streamlit\b", re.IGNORECASE),
)


def _artifact_members(path: Path) -> list[str]:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as wheel:
            return wheel.namelist()

    if path.name.endswith(".tar.gz"):
        with tarfile.open(path, "r:gz") as archive:
            return archive.getnames()

    raise ValueError(f"Unsupported artifact type: {path}")


def _artifact_text_member(path: Path, member_name: str) -> str:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as wheel:
            return wheel.read(member_name).decode("utf-8", errors="replace")

    if path.name.endswith(".tar.gz"):
        with tarfile.open(path, "r:gz") as archive:
            extracted = archive.extractfile(member_name)
            if extracted is None:
                return ""
            return extracted.read().decode("utf-8", errors="replace")

    raise ValueError(f"Unsupported artifact type: {path}")


def _blocked_members(path: Path) -> list[str]:
    return [
        member
        for member in _artifact_members(path)
        if any(pattern.search(member) for pattern in BLOCKED_PATTERNS)
    ]


def _blocked_metadata(path: Path) -> list[str]:
    offenders: list[str] = []
    for member in _artifact_members(path):
        if not member.endswith(("METADATA", "PKG-INFO")):
            continue
        text = _artifact_text_member(path, member)
        for line in text.splitlines():
            if any(pattern.search(line) for pattern in BLOCKED_METADATA_LINES):
                offenders.append(f"{member}: {line}")
    return offenders


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Fail if wheel/sdist artifacts include test-only files, duplicated "
            "artifacts, or platform-only components."
        )
    )
    parser.add_argument(
        "dist_dir",
        nargs="?",
        default="dist",
        type=Path,
        help="Directory containing .whl and .tar.gz artifacts.",
    )
    args = parser.parse_args()

    artifacts = sorted(args.dist_dir.glob("*.whl")) + sorted(
        args.dist_dir.glob("*.tar.gz")
    )
    if not artifacts:
        print(f"No release artifacts found in {args.dist_dir}", file=sys.stderr)
        return 1

    failed = False
    for artifact in artifacts:
        print(f"Checking distribution contents: {artifact}")
        blocked = _blocked_members(artifact)
        if blocked:
            failed = True
            print(f"Unexpected files found in {artifact}:", file=sys.stderr)
            for member in blocked:
                print(f"  {member}", file=sys.stderr)
        blocked_metadata = _blocked_metadata(artifact)
        if blocked_metadata:
            failed = True
            print(f"Unexpected metadata found in {artifact}:", file=sys.stderr)
            for line in blocked_metadata:
                print(f"  {line}", file=sys.stderr)

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
