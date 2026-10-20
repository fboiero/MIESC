"""`miesc report -f pdf` must not claim success when no PDF was produced.

Regression for the silent HTML fallback (exit 0, "OK Report saved") seen in
the 2026-10 new-user walkthrough.
"""

from __future__ import annotations

import json
import sys
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from miesc.cli.commands.report import report


@pytest.fixture
def results_file(tmp_path):
    path = tmp_path / "results.json"
    path.write_text(
        json.dumps(
            {
                "contract": "Vault.sol",
                "findings": [
                    {
                        "title": "Reentrancy in withdraw",
                        "severity": "high",
                        "description": "External call before state update.",
                        "tool": "slither",
                        "line": 42,
                    }
                ],
            }
        )
    )
    return path


def test_pdf_without_backends_exits_1_and_keeps_html(results_file, tmp_path):
    out_pdf = tmp_path / "audit.pdf"
    runner = CliRunner()
    # weasyprint absent (import raises ImportError) and pandoc not on PATH.
    with patch.dict(sys.modules, {"weasyprint": None}):
        with patch("subprocess.run", side_effect=FileNotFoundError("pandoc")):
            result = runner.invoke(report, [str(results_file), "-f", "pdf", "-o", str(out_pdf)])

    assert result.exit_code == 1, result.output
    assert not out_pdf.exists()
    assert (tmp_path / "audit.html").exists()
    assert not (tmp_path / "audit.tmp.html").exists()
    assert "No PDF was produced" in result.output
    assert "miesc[pdf]" in result.output


def test_markdown_output_still_exits_0(results_file, tmp_path):
    out_md = tmp_path / "audit.md"
    result = CliRunner().invoke(report, [str(results_file), "-f", "markdown", "-o", str(out_md)])
    assert result.exit_code == 0, result.output
    assert out_md.exists()
