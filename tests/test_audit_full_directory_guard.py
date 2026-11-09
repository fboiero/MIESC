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

    assert result.exit_code != 0
    assert "is a directory" in result.output.lower()
    assert "audit batch" in result.output
    # It must fail fast — before the banner / pipeline start, never with a raw errno.
    assert "[Errno 21]" not in result.output
