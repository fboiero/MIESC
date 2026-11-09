"""Per-file, recall-safe intelligence enhancement for directory targets.

`enhance_findings` / `context_aware_fp_check` match whole-text over `source_code`
(e.g. ``"ReentrancyGuard" in source_code``). Fed a CONCATENATED multi-file blob
(what a directory target produced through #314/#313's `load_contract_source`), a
guard/import/pragma in one file could suppress a genuine true positive in another
— recall-unsafe. `enhance_findings_by_file` enhances each finding against ONLY its
own file's source, so cross-file contamination cannot happen. For a single file,
behaviour is unchanged.

Note: these tests use a neutrally-named temp dir, not pytest's ``tmp_path`` — the
latter contains ``test_`` which legitimately trips ``context_aware_fp_check``'s
test/mock-file suppression and would confound the cross-file assertions.
"""

from __future__ import annotations

import shutil
import tempfile
from copy import deepcopy
from pathlib import Path

import pytest

from miesc.cli.commands.audit import _enhance_all_results, _intelligence_source_for
from miesc.core.intelligence import (
    context_aware_fp_check,
    enhance_findings,
    enhance_findings_by_file,
)

_VAULT = (
    'import "@openzeppelin/contracts/security/ReentrancyGuard.sol";\n'
    "contract Vault is ReentrancyGuard {\n"
    "    function safeWithdraw() external nonReentrant {}\n"
    "}\n"
)
_BANK = (
    "contract Bank {\n"
    "    mapping(address => uint) bal;\n"
    "    function withdraw() external {\n"
    '        (bool ok, ) = msg.sender.call{value: bal[msg.sender]}("");\n'
    "        require(ok);\n"
    "        bal[msg.sender] = 0;  // state update AFTER the external call\n"
    "    }\n"
    "}\n"
)


def _bank_reentrancy(file_path: str) -> dict:
    return {
        "type": "reentrancy-eth",
        "title": "Reentrancy in Bank.withdraw",
        "severity": "high",
        "location": {"file": file_path, "function": "unknown", "line": 3},
    }


@pytest.fixture
def project():
    """A two-file project (guarded Vault + vulnerable Bank) under a neutral path."""
    root = Path(tempfile.mkdtemp(prefix="miesc_proj_"))
    (root / "src").mkdir()
    (root / "src" / "Vault.sol").write_text(_VAULT, encoding="utf-8")
    (root / "src" / "Bank.sol").write_text(_BANK, encoding="utf-8")
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_concatenated_blob_suppresses_cross_file_true_positive():
    """Documents the #314 regression this change fixes, at the suppression
    primitive: Bank's real reentrancy is kept when checked against Bank alone,
    but SUPPRESSED when a concatenated blob also carries Vault's ReentrancyGuard.
    That cross-file suppression is the behaviour we must not keep."""
    finding = _bank_reentrancy("Bank.sol")

    is_fp_alone, _ = context_aware_fp_check(deepcopy(finding), _BANK, "Bank.sol")
    assert is_fp_alone is False, "Bank's reentrancy is real against its own source"

    blob = _VAULT + "\n" + _BANK
    is_fp_blob, reason = context_aware_fp_check(deepcopy(finding), blob, "project")
    assert is_fp_blob is True, "the concatenated blob wrongly suppresses (the bug)"
    assert "ReentrancyGuard" in (reason or "")


def test_per_file_keeps_cross_file_true_positive(project):
    """The fix: per-file enhancement checks Bank's finding against Bank.sol only,
    so Vault's guard can no longer suppress it."""
    bank = project / "src" / "Bank.sol"
    source_for, scope_files, default_path = _intelligence_source_for(str(project))
    out = enhance_findings_by_file(
        [_bank_reentrancy(str(bank))],
        source_for,
        scope_files=scope_files,
        default_path=default_path,
    )
    bank_findings = [f for f in out if f.get("title") == "Reentrancy in Bank.withdraw"]
    assert bank_findings, "the real reentrancy must survive"
    assert not bank_findings[0].get(
        "fp_suppressed"
    ), "a guard in a DIFFERENT file must not suppress Bank's reentrancy"


def test_single_file_target_is_unchanged():
    """Single-file targets take the existing single-call path verbatim: the
    non-suppressed set matches a direct `enhance_findings` on that file."""
    root = Path(tempfile.mkdtemp(prefix="miesc_single_"))
    try:
        f = root / "Bank.sol"
        f.write_text(_BANK, encoding="utf-8")
        finding = _bank_reentrancy(str(f))

        direct = enhance_findings([deepcopy(finding)], source_code=_BANK, file_path=str(f))
        direct_non_suppressed = [x for x in direct if not x.get("fp_suppressed")]
        assert direct_non_suppressed, "sanity: the finding is NOT suppressed on its own file"

        rebuilt = _enhance_all_results(
            [{"tool": "slither", "status": "success", "findings": [deepcopy(finding)]}],
            str(f),
        )
        engine = [r for r in rebuilt if r.get("tool") == "miesc-intelligence"]
        assert engine, "the intelligence result entry must be present"
        via = engine[0]["findings"]

        assert len(via) == len(direct_non_suppressed)
        assert {x.get("title") for x in via} == {x.get("title") for x in direct_non_suppressed}
    finally:
        shutil.rmtree(root, ignore_errors=True)


def test_different_path_formats_resolve_to_one_canonical_file(project):
    """Grouping is by RESOLVED canonical path: a tool reporting an absolute path
    and a tool reporting the project-relative path resolve to the same file, so
    cross-tool dedup is preserved on a directory target."""
    bank = project / "src" / "Bank.sol"
    source_for, _scope, _default = _intelligence_source_for(str(project))

    canon_abs, src_abs = source_for(str(bank))
    canon_rel, src_rel = source_for("src/Bank.sol")

    assert canon_abs != ""
    assert canon_abs == canon_rel, "both path formats must resolve to one file"
    assert src_abs == src_rel == _BANK


def test_ambiguous_basename_does_not_resolve(project):
    """A bare basename that matches more than one file must NOT resolve (recall-
    safe): no source, so no cross-file suppression. Same rule as reentrancy
    triage's basename guard."""
    (project / "src" / "a").mkdir()
    (project / "src" / "b").mkdir()
    (project / "src" / "a" / "Token.sol").write_text(
        "contract Token { function f() external nonReentrant {} }", encoding="utf-8"
    )
    (project / "src" / "b" / "Token.sol").write_text(
        "contract Token { function f() external {} }", encoding="utf-8"
    )
    source_for, _scope, _default = _intelligence_source_for(str(project))

    canon, src = source_for("Token.sol")
    assert canon == "" and src == ""


def test_unresolved_file_in_dir_is_recall_safe(project):
    """A finding whose file cannot be resolved runs with no source — never
    suppressed by another file's context."""
    source_for, scope_files, default_path = _intelligence_source_for(str(project))
    orphan = {
        "type": "reentrancy-eth",
        "title": "Reentrancy with no resolvable file",
        "severity": "high",
        "location": {"file": "does/not/exist/Ghost.sol", "function": "unknown", "line": 1},
    }
    out = enhance_findings_by_file(
        [orphan], source_for, scope_files=scope_files, default_path=default_path
    )
    kept = [f for f in out if f.get("title") == "Reentrancy with no resolvable file"]
    assert kept and not kept[0].get("fp_suppressed")


def test_relative_path_resolves_under_root_not_cwd(project, monkeypatch):
    """A project-relative path must resolve to the file under the project root,
    never a same-named file under the process CWD — reading the wrong file would
    feed the wrong context (the bug class this change fixes)."""
    decoy = Path(tempfile.mkdtemp(prefix="miesc_decoy_"))
    try:
        (decoy / "src").mkdir()
        (decoy / "src" / "Bank.sol").write_text("contract Decoy {}", encoding="utf-8")
        monkeypatch.chdir(decoy)  # CWD now also has src/Bank.sol, different content

        source_for, _scope, _default = _intelligence_source_for(str(project))
        canon, src = source_for("src/Bank.sol")

        assert canon == str(project / "src" / "Bank.sol")
        assert src == _BANK and "Decoy" not in src
    finally:
        shutil.rmtree(decoy, ignore_errors=True)
