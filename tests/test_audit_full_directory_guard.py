"""
`audit full` is a single-contract command — the 9-layer orchestrator reads one
source file. Pointing it at a directory used to degrade the whole run silently:
the source read failed with "[Errno 21] Is a directory", the ML/LLM layers got no
code, and the audit produced nothing useful while still exiting 0.

This guard rejects a directory target up front and points the user at
`audit batch`, which iterates the .sol files in a directory.
"""

from __future__ import annotations

from click.testing import CliRunner

from miesc.cli.commands.audit import audit


def test_audit_full_rejects_a_directory_with_guidance(tmp_path):
    (tmp_path / "A.sol").write_text("contract A {}", encoding="utf-8")

    result = CliRunner().invoke(audit, ["full", str(tmp_path)])

    # Collapse whitespace: the Rich console wraps the message at the terminal width,
    # so the phrase can straddle a line break ("is a \ndirectory") under a narrow CI
    # terminal. Normalize before matching so the assertion is width-independent.
    normalized = " ".join(result.output.lower().split())

    assert result.exit_code != 0
    assert "is a directory" in normalized
    assert "audit batch" in normalized
    # It must fail fast — before the banner / pipeline start, never with a raw errno.
    assert "[errno 21]" not in normalized
