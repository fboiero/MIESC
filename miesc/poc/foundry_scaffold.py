"""
Shared Foundry Scaffold Helper
==============================

Generalizes the temp-Foundry-workspace pattern used by the Slither and Aderyn
adapters (``_create_temp_workspace_with_deps`` / ``_setup_workspace_with_deps``)
into a single helper for the exploit-validation stage.

Given a repository directory and a target contract file, it produces a temporary
Foundry project where an LLM-drafted ``.t.sol`` test can compile *against the real
contracts* at ``repo_dir`` (rather than a scraped interface). The real repository
is exposed under the ``@repo/`` remapping (absolute path), so a drafted test can
``import "@repo/<relative-path>.sol";`` and deploy the genuine contract, and the
repository's own vendored ``lib/`` dependencies (OpenZeppelin, solmate, ...) are
re-remapped so the real contract's nested imports also resolve.

Design contract (see docs/design/exploit_validation_20260709.md §4.4):
- Reuse the proven pattern: ``tempfile.mkdtemp`` workspace + ``foundry.toml``
  (detected solc + remappings) + ``git init`` + ``forge install`` for genuinely
  missing deps.
- Prefer remapping to the repo's existing ``lib/`` over re-installing.
- Guard on ``shutil.which("forge")``: return ``None`` if forge is absent
  (never raise) so callers can degrade to ``status="skipped"``.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: July 2026
Version: 1.0.0
"""

import logging
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)

# Remapping prefix under which the real repository is exposed to the drafted test.
# A drafted exploit imports the target as ``import "@repo/<rel>.sol";``.
REPO_REMAP_PREFIX = "@repo/"

DEFAULT_SOLC = "0.8.20"

# Known external deps -> (forge install target, remapping template).
# The remapping is workspace-local ("lib/...") and only used when the repo does
# NOT already vendor the dependency (we prefer the repo's own lib/).
KNOWN_DEPS: Dict[str, Tuple[str, str]] = {
    "forge-std": ("foundry-rs/forge-std", "forge-std/=lib/forge-std/src/"),
    "@openzeppelin/contracts": (
        "OpenZeppelin/openzeppelin-contracts",
        "@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/",
    ),
    "@openzeppelin/contracts-upgradeable": (
        "OpenZeppelin/openzeppelin-contracts-upgradeable",
        "@openzeppelin/contracts-upgradeable/=" "lib/openzeppelin-contracts-upgradeable/contracts/",
    ),
    "@chainlink/contracts": (
        "smartcontractkit/chainlink",
        "@chainlink/contracts/=lib/chainlink/contracts/",
    ),
    "solmate": ("transmissions11/solmate", "solmate/=lib/solmate/src/"),
    "solady": ("Vectorized/solady", "solady/=lib/solady/src/"),
}


def _detect_solc_version(contract_file: Path, repo_dir: Path) -> str:
    """Detect a concrete solc version.

    Priority: the target contract's ``pragma solidity`` -> the repo's
    ``foundry.toml`` ``solc`` setting -> ``DEFAULT_SOLC``.
    """
    pragma_re = re.compile(r"pragma\s+solidity\s*[\^~>=<]*\s*([0-9]+\.[0-9]+\.[0-9]+)")
    try:
        match = pragma_re.search(contract_file.read_text(encoding="utf-8", errors="ignore"))
        if match:
            return match.group(1)
    except OSError as exc:
        logger.debug("Could not read contract pragma: %s", exc)

    repo_toml = repo_dir / "foundry.toml"
    if repo_toml.is_file():
        try:
            toml_solc = re.search(
                r'solc(?:_version)?\s*=\s*["\']?([0-9]+\.[0-9]+\.[0-9]+)',
                repo_toml.read_text(encoding="utf-8", errors="ignore"),
            )
            if toml_solc:
                return toml_solc.group(1)
        except OSError as exc:
            logger.debug("Could not read repo foundry.toml: %s", exc)

    return DEFAULT_SOLC


def _detect_imports(contract_file: Path) -> Set[str]:
    """Detect external (non-relative) import roots in the target contract."""
    imports: Set[str] = set()
    import_re = re.compile(r'import\s+(?:{[^}]+}\s+from\s+)?["\']([^"\']+)["\']')
    try:
        content = contract_file.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        logger.debug("Could not read contract imports: %s", exc)
        return imports

    for match in import_re.findall(content):
        if match.startswith("."):
            continue  # relative imports resolve against the real file's location
        if match.startswith("@openzeppelin/contracts-upgradeable"):
            imports.add("@openzeppelin/contracts-upgradeable")
        elif match.startswith("@openzeppelin/"):
            imports.add("@openzeppelin/contracts")
        elif match.startswith("@chainlink/"):
            imports.add("@chainlink/contracts")
        elif match.startswith("forge-std/"):
            imports.add("forge-std")
        elif match.startswith("solmate/"):
            imports.add("solmate")
        elif match.startswith("solady/"):
            imports.add("solady")
        else:
            root = match.split("/")[0]
            if root and not root.endswith(".sol"):
                imports.add(root)
    return imports


def _read_repo_remappings(repo_dir: Path) -> List[str]:
    """Collect the repo's own remappings, rebased to absolute paths.

    Reads ``remappings.txt`` and any ``remappings = [...]`` block in the repo's
    ``foundry.toml``. Relative right-hand-side targets are rebased onto
    ``repo_dir`` so they still resolve from the temp workspace.
    """
    raw: List[str] = []

    remap_txt = repo_dir / "remappings.txt"
    if remap_txt.is_file():
        try:
            for line in remap_txt.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if line and "=" in line and not line.startswith("#"):
                    raw.append(line)
        except OSError as exc:
            logger.debug("Could not read remappings.txt: %s", exc)

    repo_toml = repo_dir / "foundry.toml"
    if repo_toml.is_file():
        try:
            toml_text = repo_toml.read_text(encoding="utf-8", errors="ignore")
            block = re.search(r"remappings\s*=\s*\[(.*?)\]", toml_text, re.DOTALL)
            if block:
                for entry in re.findall(r'["\']([^"\']+=[^"\']+)["\']', block.group(1)):
                    raw.append(entry.strip())
        except OSError as exc:
            logger.debug("Could not read repo foundry.toml remappings: %s", exc)

    rebased: List[str] = []
    seen: Set[str] = set()
    for entry in raw:
        prefix, _, target = entry.partition("=")
        prefix, target = prefix.strip(), target.strip()
        if not prefix or not target:
            continue
        target_path = Path(target)
        if not target_path.is_absolute():
            target_path = (repo_dir / target).resolve()
        rebased_entry = f"{prefix}={target_path}"
        if not rebased_entry.endswith("/"):
            rebased_entry += "/"
        if prefix not in seen:
            seen.add(prefix)
            rebased.append(rebased_entry)
    return rebased


def _repo_vendors(repo_dir: Path, import_name: str) -> bool:
    """Whether the repo already vendors a dependency under its own ``lib/``."""
    lib_dir = repo_dir / "lib"
    if not lib_dir.is_dir():
        return False
    # Match by the forge install target's repo name (last path segment).
    install_target = KNOWN_DEPS.get(import_name, (None, None))[0]
    if not install_target:
        return False
    candidate = install_target.split("/")[-1]
    return (lib_dir / candidate).is_dir()


def scaffold_foundry_project(repo_dir, contract_file) -> "Optional[Path]":
    """Create a temp Foundry project for exploit validation.

    Builds a temporary Foundry project where an LLM-drafted ``.t.sol`` test can
    compile against the REAL contracts at ``repo_dir``. The repository is exposed
    under the ``@repo/`` remapping (absolute), the repo's own ``lib/`` remappings
    are re-applied, and any genuinely missing well-known deps are ``forge
    install``ed into the workspace (repo-vendored deps are preferred and not
    reinstalled). ``forge-std`` is installed so drafted tests can extend
    ``forge-std/Test.sol``.

    Args:
        repo_dir: Root of the repository containing the real contracts.
        contract_file: The target ``.sol`` file (used for solc + import detection).

    Returns:
        The temp project directory as a ``Path``, or ``None`` if ``forge`` is not
        available (never raises for the forge-absent case).
    """
    if not shutil.which("forge"):
        logger.debug("forge not available; cannot scaffold Foundry project")
        return None

    repo_dir = Path(repo_dir).resolve()
    contract_file = Path(contract_file).resolve()

    workspace = Path(tempfile.mkdtemp(prefix="miesc_exploit_"))
    logger.debug("Created exploit workspace: %s", workspace)

    # Foundry default layout; src/test kept local so drafted tests land in test/.
    (workspace / "src").mkdir(exist_ok=True)
    (workspace / "test").mkdir(exist_ok=True)

    solc_version = _detect_solc_version(contract_file, repo_dir)

    # Remappings, most specific first.
    remappings: List[str] = [f"{REPO_REMAP_PREFIX}={repo_dir}/"]
    remappings.extend(_read_repo_remappings(repo_dir))

    # forge-std is always needed for the Test base class; install locally.
    deps_to_install: List[Tuple[str, str]] = [KNOWN_DEPS["forge-std"]]

    remapped_prefixes = {r.split("=", 1)[0] for r in remappings}
    for imp in _detect_imports(contract_file):
        if imp not in KNOWN_DEPS:
            logger.debug("Unknown external import '%s' - relying on repo remappings", imp)
            continue
        install_target, local_remap = KNOWN_DEPS[imp]
        local_prefix = local_remap.split("=", 1)[0]
        # Prefer the repo's own vendored dep / existing remapping.
        if _repo_vendors(repo_dir, imp) or local_prefix in remapped_prefixes:
            logger.debug("Dependency '%s' satisfied by repo; not reinstalling", imp)
            continue
        deps_to_install.append((install_target, local_remap))
        remappings.append(local_remap)
        remapped_prefixes.add(local_prefix)

    _write_foundry_toml(workspace, solc_version, remappings)

    # git init (forge install expects a repo unless --no-git; keep parity w/ adapters).
    subprocess.run(
        ["git", "init"],
        cwd=workspace,
        capture_output=True,
        timeout=10,
    )

    for install_target, _remap in deps_to_install:
        logger.debug("Installing dependency: %s", install_target)
        result = subprocess.run(
            ["forge", "install", install_target, "--no-git"],
            cwd=workspace,
            capture_output=True,
            text=True,
            timeout=180,
        )
        if result.returncode != 0:
            # Best-effort: a failed install (e.g. offline) is not fatal here.
            # The drafted test may still compile if it does not need this dep,
            # and the caller's repair/skip loop handles the rest.
            logger.warning(
                "forge install %s failed (non-fatal): %s",
                install_target,
                result.stderr.strip(),
            )

    return workspace


def _write_foundry_toml(workspace: Path, solc_version: str, remappings: List[str]) -> None:
    """Write the workspace ``foundry.toml`` with pinned solc + remappings."""
    lines = [
        "[profile.default]",
        'src = "src"',
        'test = "test"',
        'out = "out"',
        'libs = ["lib"]',
        f'solc = "{solc_version}"',
        "auto_detect_solc = false",
    ]
    if remappings:
        lines.append("remappings = [")
        for remap in remappings:
            lines.append(f'    "{remap}",')
        lines.append("]")
    (workspace / "foundry.toml").write_text("\n".join(lines) + "\n", encoding="utf-8")
    logger.debug("Wrote foundry.toml (solc=%s, %d remappings)", solc_version, len(remappings))


__all__ = ["scaffold_foundry_project", "REPO_REMAP_PREFIX"]
