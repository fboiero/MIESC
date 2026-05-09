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
)


def _artifact_members(path: Path) -> list[str]:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as wheel:
            return wheel.namelist()

    if path.name.endswith(".tar.gz"):
        with tarfile.open(path, "r:gz") as archive:
            return archive.getnames()

    raise ValueError(f"Unsupported artifact type: {path}")


def _blocked_members(path: Path) -> list[str]:
    return [
        member
        for member in _artifact_members(path)
        if any(pattern.search(member) for pattern in BLOCKED_PATTERNS)
    ]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fail if wheel/sdist artifacts include test-only or duplicated files."
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

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
