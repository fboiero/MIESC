"""Unit coverage for the pure helpers of ``miesc.poc.foundry_scaffold``.

The existing ``test_foundry_scaffold.py`` covers only the forge-absent short-circuit and a
forge-required real compile (skipped without forge). These exercise the deterministic
filesystem/string helpers — solc detection, import classification, remapping rebasing, vendor
detection, the foundry.toml writer — and the dep-selection branch of ``scaffold_foundry_project``
with ``forge``/``subprocess`` mocked, so the logic is covered without a real toolchain or network.
"""

from __future__ import annotations

import subprocess

from miesc.poc import foundry_scaffold as fs
from miesc.poc.foundry_scaffold import (
    DEFAULT_SOLC,
    REPO_REMAP_PREFIX,
    _detect_imports,
    _detect_solc_version,
    _read_repo_remappings,
    _repo_vendors,
    _write_foundry_toml,
    scaffold_foundry_project,
)


# --- _detect_solc_version ---------------------------------------------------------------------
def test_solc_from_contract_pragma_wins(tmp_path):
    c = tmp_path / "C.sol"
    c.write_text("// SPDX\npragma solidity ^0.8.19;\ncontract C {}")
    (tmp_path / "foundry.toml").write_text('[profile.default]\nsolc = "0.7.6"\n')
    assert _detect_solc_version(c, tmp_path) == "0.8.19"


def test_solc_falls_back_to_repo_foundry_toml(tmp_path):
    c = tmp_path / "C.sol"
    c.write_text("contract C {}")  # no pragma
    (tmp_path / "foundry.toml").write_text('[profile.default]\nsolc_version = "0.6.12"\n')
    assert _detect_solc_version(c, tmp_path) == "0.6.12"


def test_solc_defaults_when_nothing_declares_it(tmp_path):
    c = tmp_path / "C.sol"
    c.write_text("contract C {}")
    assert _detect_solc_version(c, tmp_path) == DEFAULT_SOLC


def test_solc_unreadable_contract_does_not_raise(tmp_path):
    missing = tmp_path / "gone.sol"  # never created -> read_text raises OSError, caught
    assert _detect_solc_version(missing, tmp_path) == DEFAULT_SOLC


# --- _detect_imports --------------------------------------------------------------------------
def test_detect_imports_classifies_known_roots(tmp_path):
    c = tmp_path / "C.sol"
    c.write_text(
        "\n".join(
            [
                'import "./Local.sol";',  # relative -> skipped
                'import "@openzeppelin/contracts-upgradeable/proxy/Initializable.sol";',
                'import "@openzeppelin/contracts/token/ERC20/ERC20.sol";',
                'import "@chainlink/contracts/src/v0.8/AggregatorV3Interface.sol";',
                'import "forge-std/Test.sol";',
                'import "solmate/tokens/ERC20.sol";',
                'import "solady/utils/SafeTransferLib.sol";',
                'import {Foo} from "customlib/Foo.sol";',  # unknown root -> customlib
            ]
        )
    )
    assert _detect_imports(c) == {
        "@openzeppelin/contracts-upgradeable",
        "@openzeppelin/contracts",
        "@chainlink/contracts",
        "forge-std",
        "solmate",
        "solady",
        "customlib",
    }


def test_detect_imports_skips_bare_dot_sol_root_and_unreadable(tmp_path):
    c = tmp_path / "C.sol"
    c.write_text('import "Flat.sol";')  # root ends with .sol -> not an external dep
    assert _detect_imports(c) == set()
    assert _detect_imports(tmp_path / "missing.sol") == set()  # OSError path


# --- _read_repo_remappings --------------------------------------------------------------------
def test_remappings_txt_rebased_to_absolute_and_deduped(tmp_path):
    (tmp_path / "remappings.txt").write_text(
        "# a comment\n\n@oz/=lib/oz/\n@oz/=lib/other/\nsolmate/=/abs/solmate/src/\n"
    )
    out = _read_repo_remappings(tmp_path)
    # first @oz/ wins (dedupe by prefix); relative target rebased onto repo_dir; trailing slash.
    oz = next(r for r in out if r.startswith("@oz/="))
    assert oz == f"@oz/={(tmp_path / 'lib/oz').resolve()}/"
    assert "solmate/=/abs/solmate/src/" in out
    assert sum(r.startswith("@oz/=") for r in out) == 1


def test_remappings_from_foundry_toml_block(tmp_path):
    (tmp_path / "foundry.toml").write_text(
        '[profile.default]\nremappings = [\n    "ds-test/=lib/ds-test/src/",\n]\n'
    )
    out = _read_repo_remappings(tmp_path)
    assert out == [f"ds-test/={(tmp_path / 'lib/ds-test/src').resolve()}/"]


def test_remappings_absent_is_empty(tmp_path):
    assert _read_repo_remappings(tmp_path) == []


# --- _repo_vendors ----------------------------------------------------------------------------
def test_repo_vendors_detects_vendored_dep(tmp_path):
    (tmp_path / "lib" / "solmate").mkdir(parents=True)
    assert _repo_vendors(tmp_path, "solmate") is True


def test_repo_vendors_false_without_lib_or_unknown(tmp_path):
    assert _repo_vendors(tmp_path, "solmate") is False  # no lib/
    (tmp_path / "lib").mkdir()
    assert _repo_vendors(tmp_path, "totally-unknown") is False  # not in KNOWN_DEPS
    assert _repo_vendors(tmp_path, "solmate") is False  # lib/ exists but dep not vendored


# --- _write_foundry_toml ----------------------------------------------------------------------
def test_write_foundry_toml_pins_solc_and_lists_remappings(tmp_path):
    _write_foundry_toml(tmp_path, "0.8.21", ["@repo/=/x/", "solmate/=lib/solmate/src/"])
    toml = (tmp_path / "foundry.toml").read_text()
    assert 'solc = "0.8.21"' in toml and "auto_detect_solc = false" in toml
    assert '"@repo/=/x/",' in toml and '"solmate/=lib/solmate/src/",' in toml


# --- scaffold_foundry_project (forge + subprocess mocked) --------------------------------------
class _FakeRun:
    """Record forge/git invocations; report success (or a chosen rc for forge install)."""

    def __init__(self, install_rc=0):
        self.install_rc = install_rc
        self.calls = []

    def __call__(self, cmd, cwd=None, **kw):
        self.calls.append(list(cmd))
        rc = self.install_rc if cmd[:2] == ["forge", "install"] else 0
        return subprocess.CompletedProcess(cmd, rc, stdout="", stderr="boom" if rc else "")


def _mock_forge(monkeypatch, fake):
    monkeypatch.setattr(fs.shutil, "which", lambda _: "/usr/bin/forge")
    monkeypatch.setattr(fs.subprocess, "run", fake)


def test_scaffold_assembles_remappings_and_selects_missing_deps(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    contract = repo / "src" / "Target.sol"
    contract.write_text(
        'pragma solidity 0.8.17;\nimport "solmate/tokens/ERC20.sol";\ncontract T {}'
    )
    fake = _FakeRun()
    _mock_forge(monkeypatch, fake)

    ws = scaffold_foundry_project(repo, contract)

    assert ws is not None and ws.is_dir()
    toml = (ws / "foundry.toml").read_text()
    assert f'"{REPO_REMAP_PREFIX}={repo.resolve()}/"' in toml  # repo exposed under @repo/
    assert 'solc = "0.8.17"' in toml  # pragma honoured
    assert "solmate/=lib/solmate/src/" in toml  # not vendored -> local remap added
    installed = [c[2] for c in fake.calls if c[:2] == ["forge", "install"]]
    assert "foundry-rs/forge-std" in installed  # always
    assert "transmissions11/solmate" in installed  # the missing dep


def test_scaffold_prefers_repo_vendored_dep_over_reinstall(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "lib" / "solmate").mkdir(parents=True)  # repo vendors solmate
    contract = repo / "src" / "Target.sol"
    contract.write_text(
        'pragma solidity 0.8.17;\nimport "solmate/tokens/ERC20.sol";\ncontract T {}'
    )
    fake = _FakeRun()
    _mock_forge(monkeypatch, fake)

    scaffold_foundry_project(repo, contract)

    installed = [c[2] for c in fake.calls if c[:2] == ["forge", "install"]]
    assert "transmissions11/solmate" not in installed  # vendored -> not reinstalled
    assert "foundry-rs/forge-std" in installed


def test_scaffold_ignores_an_unknown_external_import(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    contract = repo / "src" / "Target.sol"
    # `customlib` is a real external root but not in KNOWN_DEPS: it is left to the repo's own
    # remappings, never forge-installed.
    contract.write_text('pragma solidity 0.8.17;\nimport "customlib/Foo.sol";\ncontract T {}')
    fake = _FakeRun()
    _mock_forge(monkeypatch, fake)

    ws = scaffold_foundry_project(repo, contract)

    installed = [c[2] for c in fake.calls if c[:2] == ["forge", "install"]]
    assert installed == ["foundry-rs/forge-std"]  # only the base dep; customlib not installed
    assert "customlib" not in (ws / "foundry.toml").read_text()


def test_scaffold_survives_a_failed_forge_install(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    contract = repo / "src" / "Target.sol"
    contract.write_text("pragma solidity 0.8.17;\ncontract T {}")
    _mock_forge(monkeypatch, _FakeRun(install_rc=1))  # install fails, non-fatal

    ws = scaffold_foundry_project(repo, contract)
    assert ws is not None and (ws / "foundry.toml").is_file()
