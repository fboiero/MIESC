"""Reusable remediation evidence pipeline.

This module turns the Paper 2 benchmark workflow into a product-facing building
block. It does not own patch generation; it reuses the existing `miesc fix`
patcher and adds the evidence states needed by CLI, API, MCP, and benchmarks.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import cast, Any, Optional

from miesc import __version__ as MIESC_VERSION
from miesc.cli.commands.fix import _collect_fixable_findings, apply_fix

MAX_ERROR_CHARS = 2000
SOLC_DIR = Path.home() / ".solc-select" / "artifacts"


@dataclass
class CompileEvidence:
    """Standalone Solidity compilation evidence."""

    checked: bool
    compiles: Optional[bool] = None
    solc: Optional[str] = None
    returncode: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    failure_class: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RescanEvidence:
    """Post-remediation scan comparison evidence."""

    checked: bool
    high_before: Optional[int] = None
    high_after: Optional[int] = None
    total_before: Optional[int] = None
    total_after: Optional[int] = None
    high_delta: Optional[int] = None
    total_delta: Optional[int] = None
    high_types_before: dict[str, int] = field(default_factory=dict)
    high_types_after: dict[str, int] = field(default_factory=dict)
    new_high_types: dict[str, int] = field(default_factory=dict)
    eliminated: Optional[bool] = None
    no_regression: Optional[bool] = None
    no_regression_bound: int = 2

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RemediationEvidence:
    """Complete remediation artifact state for one contract."""

    status: str
    original_path: str
    patched_path: Optional[str]
    original_sha256: str
    patched_sha256: Optional[str]
    findings_input: int
    fixable_findings: int
    fixes_applied: int
    fixes_skipped: int
    compile: CompileEvidence
    rescan: RescanEvidence
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    miesc_version: str = MIESC_VERSION
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def sha256_file(path: Path) -> str:
    """Return SHA-256 digest for a file."""
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def classify_compile_failure(stderr: str, stdout: str = "") -> str:
    """Classify solc stdout/stderr into the Paper 2 failure taxonomy."""
    text = f"{stderr}\n{stdout}".lower()
    if "source file requires different compiler version" in text:
        return "solidity_version_mismatch"
    if "requires different compiler version" in text:
        return "solidity_version_mismatch"
    if 'source "' in text and "not found" in text:
        return "missing_import_or_dependency"
    if "file not found" in text or "no such file" in text:
        return "missing_import_or_dependency"
    if "undeclared identifier" in text or "identifier not found" in text:
        return "undefined_symbol"
    if "not found or not visible" in text:
        return "undefined_symbol"
    if "parsererror" in text:
        return "parser_or_syntax_error"
    if "typeerror" in text:
        return "type_error"
    if "timeout" in text:
        return "compile_timeout"
    if "not found" in text and "solc" in text:
        return "solc_unavailable"
    return "other_compile_error"


def select_solc(sol_path: Path) -> str:
    """Select a locally installed solc binary from a contract pragma."""
    text = sol_path.read_text(errors="ignore")
    match = re.search(r"pragma solidity\s*([^;]+);", text)
    constraint = match.group(1).strip() if match else ""
    exact = re.fullmatch(r"(\d+\.\d+\.\d+)", constraint)
    if exact:
        candidates = [exact.group(1)]
    else:
        version = re.search(r"(\d+\.\d+)(?:\.(\d+))?", constraint)
        base = version.group(1) if version else "0.4"
        min_patch = int(version.group(2)) if version and version.group(2) else 0
        candidates = [f"{base}.{patch}" for patch in range(99, min_patch - 1, -1)]

    for version in candidates:
        candidate = SOLC_DIR / f"solc-{version}" / f"solc-{version}"
        if candidate.exists():
            return str(candidate)

    fallback = shutil.which("solc")
    if fallback:
        return fallback

    return str(SOLC_DIR / "solc-0.4.26" / "solc-0.4.26")


def compile_contract(sol_path: Path, timeout: int = 15) -> CompileEvidence:
    """Compile a standalone Solidity file with the selected solc."""
    solc = select_solc(sol_path)
    try:
        result = subprocess.run(
            [solc, str(sol_path), "--bin"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        compiles = result.returncode == 0 or "Binary:" in result.stdout
        return CompileEvidence(
            checked=True,
            compiles=compiles,
            solc=solc,
            returncode=result.returncode,
            stdout=result.stdout[:MAX_ERROR_CHARS],
            stderr=result.stderr[:MAX_ERROR_CHARS],
            failure_class=(
                None if compiles else classify_compile_failure(result.stderr, result.stdout)
            ),
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        return CompileEvidence(
            checked=True,
            compiles=False,
            solc=solc,
            stdout=stdout[:MAX_ERROR_CHARS],
            stderr="compile timeout",
            failure_class="compile_timeout",
        )
    except Exception as exc:
        message = str(exc)[:MAX_ERROR_CHARS]
        return CompileEvidence(
            checked=True,
            compiles=False,
            solc=solc,
            stderr=message,
            failure_class=classify_compile_failure(message),
        )


def count_high_findings(scan_result: Optional[dict[str, Any]]) -> int:
    """Count critical/high findings in a MIESC scan result."""
    if not scan_result:
        return 0
    return sum(
        1
        for finding in scan_result.get("findings", [])
        if (finding.get("severity") or "").upper() in {"CRITICAL", "HIGH"}
    )


def summarize_high_finding_types(scan_result: Optional[dict[str, Any]]) -> dict[str, int]:
    """Count HIGH/CRITICAL finding types in a scan result."""
    if not scan_result:
        return {}
    counts: Counter[str] = Counter()
    for finding in scan_result.get("findings", []):
        if (finding.get("severity") or "").upper() not in {"CRITICAL", "HIGH"}:
            continue
        finding_type = (
            finding.get("type")
            or finding.get("title")
            or finding.get("check")
            or finding.get("swc_id")
            or "unknown"
        )
        counts[str(finding_type)] += 1
    return dict(sorted(counts.items()))


def diff_high_finding_types(
    before: dict[str, int],
    after: dict[str, int],
) -> dict[str, int]:
    """Return positive HIGH/CRITICAL finding-type increases after rescan."""
    diff = {
        finding_type: count - before.get(finding_type, 0)
        for finding_type, count in after.items()
        if count > before.get(finding_type, 0)
    }
    return dict(sorted(diff.items()))


def apply_patch_candidates(source: str, findings: list[dict[str, Any]]) -> tuple[str, int, int]:
    """Apply existing MIESC fix candidates and return source plus counters."""
    patched = source
    applied = 0
    skipped = 0

    for finding in findings:
        new_source, changed = apply_fix(patched, finding)
        if changed:
            patched = new_source
            applied += 1
        else:
            skipped += 1

    return patched, applied, skipped


def run_scan(contract_path: Path, output_path: Path, timeout: int = 30) -> Optional[dict[str, Any]]:
    """Run `miesc scan` and return its JSON output when available."""
    env = {
        **os.environ,
        "PYTHONPATH": f"{Path(__file__).parents[2]}:{Path(__file__).parents[2] / 'src'}",
    }
    try:
        subprocess.run(
            [
                sys.executable,
                "-m",
                "miesc.cli.main",
                "scan",
                str(contract_path),
                "-o",
                str(output_path),
                "--quiet",
                "--fp-strictness",
                "low",
            ],
            capture_output=True,
            timeout=timeout,
            env=env,
        )
        if output_path.exists():
            return cast(dict[str, Any] | None, json.loads(output_path.read_text()))
    except Exception:
        return None
    return None


def remediate_contract(
    *,
    contract_path: Path,
    results: dict[str, Any],
    output_path: Path,
    compile_check: bool = False,
    rescan_check: bool = False,
    no_regression_bound: int = 2,
) -> RemediationEvidence:
    """Apply fixes and optionally compile/re-scan the patched artifact."""
    contract_path = contract_path.resolve()
    original_source = contract_path.read_text(encoding="utf-8")
    original_sha = sha256_file(contract_path)
    fixable = _collect_fixable_findings(results)
    input_count = len(results.get("findings", [])) + sum(
        len(item.get("findings", [])) for item in results.get("results", [])
    )

    if not fixable:
        return RemediationEvidence(
            status="no_fixable_findings",
            original_path=str(contract_path),
            patched_path=None,
            original_sha256=original_sha,
            patched_sha256=None,
            findings_input=input_count,
            fixable_findings=0,
            fixes_applied=0,
            fixes_skipped=0,
            compile=CompileEvidence(checked=False),
            rescan=RescanEvidence(checked=False, no_regression_bound=no_regression_bound),
        )

    patched_source, applied, skipped = apply_patch_candidates(original_source, fixable)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(patched_source, encoding="utf-8")
    patched_sha = sha256_file(output_path)

    compile_evidence = (
        compile_contract(output_path) if compile_check else CompileEvidence(checked=False)
    )
    rescan_evidence = RescanEvidence(checked=False, no_regression_bound=no_regression_bound)

    if rescan_check:
        with tempfile.TemporaryDirectory() as tmpdir:
            rescan_out = Path(tmpdir) / "rescan.json"
            rescan = run_scan(output_path, rescan_out)
        high_before = count_high_findings(results)
        high_after = count_high_findings(rescan) if rescan else high_before
        total_before = len(results.get("findings", []))
        total_after = len(rescan.get("findings", [])) if rescan else total_before
        high_types_before = summarize_high_finding_types(results)
        high_types_after = summarize_high_finding_types(rescan)
        rescan_evidence = RescanEvidence(
            checked=True,
            high_before=high_before,
            high_after=high_after,
            total_before=total_before,
            total_after=total_after,
            high_delta=high_after - high_before,
            total_delta=total_after - total_before,
            high_types_before=high_types_before,
            high_types_after=high_types_after,
            new_high_types=diff_high_finding_types(high_types_before, high_types_after),
            eliminated=high_after < high_before,
            no_regression=total_after <= total_before + no_regression_bound,
            no_regression_bound=no_regression_bound,
        )

    status = "patch_applied" if applied else "patch_not_applied"
    if compile_evidence.checked:
        status = "compile_checked"
    if rescan_evidence.checked:
        status = "rescan_checked"

    return RemediationEvidence(
        status=status,
        original_path=str(contract_path),
        patched_path=str(output_path),
        original_sha256=original_sha,
        patched_sha256=patched_sha,
        findings_input=input_count,
        fixable_findings=len(fixable),
        fixes_applied=applied,
        fixes_skipped=skipped,
        compile=compile_evidence,
        rescan=rescan_evidence,
    )
