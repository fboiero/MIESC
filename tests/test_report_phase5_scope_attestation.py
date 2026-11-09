"""Phase 5 — honest Scope data, derived out-of-scope, and a SHA-256 attestation.

These tests lock in three guarantees for ``miesc report -t premium``:

1. §2.2 reports a real line count when the source is locatable and an em-dash
   (never ``0``/``N/A``) when it is not.
2. The report-integrity attestation hashes the *raw bytes* of the input results
   file (so it matches ``shasum -a 256``), states its scope, and claims no
   cryptographic signature.
3. The §2.2 out-of-scope list is derived from what the run did not exercise.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

import miesc
from miesc.cli.commands.report import report

STATIC_SAMPLE = Path(miesc.__file__).parent.parent / "examples" / "contracts" / "results.json"


def _render(results_path: Path, tmp_path: Path) -> str:
    out = tmp_path / "report.md"
    result = CliRunner().invoke(
        report, [str(results_path), "-t", "premium", "-f", "markdown", "-o", str(out)]
    )
    assert result.exit_code == 0, result.output
    return out.read_text(encoding="utf-8")


def _scope_section(text: str) -> str:
    return text.split("## 2.2 Scope")[1].split("## 2.3")[0]


def _integrity_section(text: str) -> str:
    return text.split("### Report Integrity")[1].split("<!-- section-break -->")[0]


# ---------------------------------------------------------------------------
# §2.2 Lines of Code — resolve to a real number, or an em-dash, never 0.
# ---------------------------------------------------------------------------


def test_loc_resolves_to_real_number_for_resolvable_file(tmp_path):
    """A single contract next to the results JSON yields its real line count."""
    src_dir = tmp_path / "proj"
    src_dir.mkdir()
    sol = src_dir / "Foo.sol"
    sol.write_text("// line 1\ncontract Foo {}\n// line 3\n", encoding="utf-8")
    results = {
        "contract": "/elsewhere/Foo.sol",  # stale absolute path; basename resolves
        "summary": {"HIGH": 1},
        "findings": [
            {
                "type": "reentrancy-eth",
                "severity": "high",
                "location": {"file": "Foo.sol", "line": 2},
            }
        ],
    }
    rj = src_dir / "results.json"
    rj.write_text(json.dumps(results), encoding="utf-8")

    scope = _scope_section(_render(rj, tmp_path))
    assert "| `Foo.sol` | 3 |" in scope
    assert "**Total:** 1 files, 3 lines of code" in scope


def test_loc_is_dash_never_zero_when_source_unresolvable(tmp_path):
    """When the source cannot be located, the LOC cell is an em-dash, not 0."""
    results = {
        "contract": "/nowhere/Missing.sol",
        "summary": {"HIGH": 1},
        "findings": [
            {
                "type": "reentrancy-eth",
                "severity": "high",
                "location": {"file": "Missing.sol", "line": 2},
            }
        ],
    }
    rj = tmp_path / "results.json"
    rj.write_text(json.dumps(results), encoding="utf-8")

    scope = _scope_section(_render(rj, tmp_path))
    assert "| 0 |" not in scope  # never a false 0
    assert "| `Missing.sol` | — |" in scope
    assert "lines of code" in scope
    assert "source not available at report time" in scope


def test_static_sample_scope_has_no_zero_loc_cell(tmp_path):
    """The bundled static sample renders a real count (135), no ``0`` cell."""
    if not STATIC_SAMPLE.exists():  # pragma: no cover - sample ships with the repo
        pytest.skip("bundled sample results.json not found")
    scope = _scope_section(_render(STATIC_SAMPLE, tmp_path))
    assert " 0 |" not in scope
    assert "| `VulnerableDeFi.sol` | 135 |" in scope
    assert "**Total:** 1 files, 135 lines of code" in scope


# ---------------------------------------------------------------------------
# Attestation — hash of raw file bytes, scope statement, no signature.
# ---------------------------------------------------------------------------


def test_input_hash_is_of_raw_bytes_not_reserialized(tmp_path):
    """The rendered SHA-256 equals the hash of the file's raw bytes.

    A dict re-serialized with ``json.dumps`` normalises whitespace and key order,
    so its hash differs from the on-disk bytes; the report must use the latter.
    """
    # Odd whitespace + key order so re-serialisation would change the bytes.
    raw = b'{\n   "summary": {"HIGH": 1},\n  "contract": "X.sol",\n "findings": []\n}\n'
    rj = tmp_path / "results.json"
    rj.write_bytes(raw)

    file_hash = hashlib.sha256(raw).hexdigest()
    reserialized_hash = hashlib.sha256(json.dumps(json.loads(raw)).encode("utf-8")).hexdigest()
    assert file_hash != reserialized_hash  # the two really differ for this input

    integrity = _integrity_section(_render(rj, tmp_path))
    assert file_hash in integrity
    assert reserialized_hash not in integrity


def test_static_sample_hash_matches_shasum(tmp_path):
    """Rendered hash equals ``shasum -a 256 examples/contracts/results.json``."""
    if not STATIC_SAMPLE.exists():  # pragma: no cover - sample ships with the repo
        pytest.skip("bundled sample results.json not found")
    expected = hashlib.sha256(STATIC_SAMPLE.read_bytes()).hexdigest()
    integrity = _integrity_section(_render(STATIC_SAMPLE, tmp_path))
    assert expected in integrity


def test_attestation_scope_sentence_present(tmp_path):
    """The attestation states it covers only report↔results correspondence."""
    rj = tmp_path / "results.json"
    rj.write_text(json.dumps({"contract": "X.sol", "summary": {"HIGH": 1}, "findings": []}))
    text = _render(rj, tmp_path)
    assert "recompute it" in text
    assert "attests only the correspondence between this report and that results file" in text
    assert "does not attest that the scan was run correctly" in text


def test_attestation_claims_no_signature(tmp_path):
    """The integrity block never presents a cryptographic signature."""
    rj = tmp_path / "results.json"
    rj.write_text(json.dumps({"contract": "X.sol", "summary": {"HIGH": 1}, "findings": []}))
    integrity = _integrity_section(_render(rj, tmp_path))
    lowered = integrity.lower()
    assert "signature" not in lowered
    assert "signed" not in lowered
    assert "sigstore" not in lowered


# ---------------------------------------------------------------------------
# Out of scope — derived from what did not run.
# ---------------------------------------------------------------------------


def test_out_of_scope_reflects_skipped_tool(tmp_path):
    """A skipped tool surfaces in the derived out-of-scope list, not boilerplate."""
    results = {
        "contract_path": "Vault.sol",
        "summary": {"HIGH": 1},
        "tools_run": ["slither", "wake"],
        "tools_skipped": ["wake"],
        "tool_status": {"slither": "success", "wake": "skipped"},
        "findings": [
            {
                "type": "reentrancy-eth",
                "severity": "high",
                "tool": "slither",
                "location": {"file": "Vault.sol", "line": 1},
            }
        ],
    }
    rj = tmp_path / "results.json"
    rj.write_text(json.dumps(results))
    scope = _scope_section(_render(rj, tmp_path))
    assert "wake" in scope
    assert "not executed or unavailable" in scope
    # Not the old generic boilerplate.
    assert "Frontend/backend applications" not in scope


def test_out_of_scope_reflects_not_available_result_entry(tmp_path):
    """A ``status: not_available`` results[] entry is excluded (symbolic layer)."""
    results = {
        "summary": {"HIGH": 1},
        "results": [
            {
                "tool": "slither",
                "contract": "C.sol",
                "status": "success",
                "findings": [
                    {
                        "type": "reentrancy-eth",
                        "severity": "high",
                        "location": {"file": "C.sol", "line": 1},
                    }
                ],
            },
            {"tool": "mythril", "contract": "C.sol", "status": "not_available", "findings": []},
        ],
    }
    rj = tmp_path / "results.json"
    rj.write_text(json.dumps(results))
    scope = _scope_section(_render(rj, tmp_path))
    assert "Symbolic execution" in scope
    assert "mythril" in scope
