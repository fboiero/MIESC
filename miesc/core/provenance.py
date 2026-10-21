"""
Run provenance for MIESC result artifacts
=========================================

Every result JSON written by ``miesc scan``, ``miesc audit``, ``miesc evaluate``
and ``miesc fix`` carries a ``provenance`` block built here, so a run can be
cited and re-run: which MIESC (version, git SHA when running from a checkout),
which Python and OS, the version string of every tool that actually executed
(as the binary reports it), the ``solc`` build the Slither adapter selected per
contract, the configuration file in effect and its SHA-256, the reproducibility
environment variables that were set, whether the run used an LLM, and the
exact command line.

Design rules:

* **Never break a run.** Every collector is wrapped; a failing probe yields
  ``"unknown"`` for that field and the block is still written.
* **Probe each tool once per process.** Version probes are cached in
  :data:`_TOOL_VERSION_CACHE` (``reset_tool_versions`` clears it) so a corpus
  evaluation does not shell out once per contract.
* **Record the binary that ran.** Adapters that resolve their executable
  themselves (Slither's priority paths, Mythril's ``.tools`` install) declare
  :meth:`ToolAdapter.version_command`; the probe uses that command so the
  recorded version matches the binary that produced the findings, not whatever
  is first on ``PATH``.

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
"""

from __future__ import annotations

import hashlib
import logging
import os
import platform
import shlex
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from miesc import __version__ as VERSION

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1

#: Seconds allowed for a ``--version`` probe before it is recorded as ``"unknown"``.
PROBE_TIMEOUT_S = 10

#: Environment variables recorded (only when set) because they change results.
TRACKED_ENV_VARS: Sequence[str] = ("MIESC_SEED", "MIESC_LLM_PROVIDER", "MIESC_LLM_MODEL")

#: Result statuses that mean the tool actually executed (vs. not installed / skipped).
EXECUTED_STATUSES = frozenset({"success", "error", "timeout"})

#: Version commands by tool name, used when the adapter does not declare
#: ``version_command()``. Only tools whose version flag is known to be
#: side-effect free are listed; anything else is recorded as ``"unknown"``.
FALLBACK_VERSION_COMMANDS: Dict[str, List[str]] = {
    "slither": ["slither", "--version"],
    "aderyn": ["aderyn", "--version"],
    "solhint": ["solhint", "--version"],
    "wake": ["wake", "--version"],
    "semgrep": ["semgrep", "--version"],
    "echidna": ["echidna", "--version"],
    "medusa": ["medusa", "--version"],
    "foundry": ["forge", "--version"],
    "mythril": ["myth", "version"],
    "manticore": ["manticore", "--version"],
    "halmos": ["halmos", "--version"],
    "certora": ["certoraRun", "--version"],
    "scribble": ["scribble", "--version"],
    "smtchecker": ["solc", "--version"],
    "solcmc": ["solc", "--version"],
}

#: ``installation_cmd`` prefixes that mark an adapter as shipped with MIESC.
_BUILTIN_INSTALL_PREFIXES = ("# built-in", "pip install -e .", "pip install miesc")

_TOOL_VERSION_CACHE: Dict[str, str] = {}

_SOLC_ARTIFACTS = Path("~/.solc-select/artifacts")


# =============================================================================
# Small utilities
# =============================================================================


def sha256_file(path: os.PathLike[str] | str | None) -> Optional[str]:
    """SHA-256 hex digest of ``path``; ``None`` when it cannot be read."""
    if not path:
        return None
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except Exception:
        return None


def _pick_version_line(text: str) -> Optional[str]:
    """The line of a ``--version`` output that carries the version.

    Prefers the first line containing a digit (``solc`` prints a banner line
    before ``Version: 0.8.10+commit...``), else the first non-empty line.
    """
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return None
    for line in lines:
        if any(ch.isdigit() for ch in line):
            return line[:200]
    return lines[0][:200]


def probe_version(command: Sequence[str], timeout: float = PROBE_TIMEOUT_S) -> str:
    """Run ``command`` and return the version line the binary prints.

    Returns ``"not_installed"`` when the executable cannot be found and
    ``"unknown"`` on any other failure (non-zero exit without output, timeout,
    permission error). Never raises.
    """
    if not command:
        return "unknown"
    executable = str(command[0])
    try:
        if not (Path(executable).is_file() or shutil.which(executable)):
            return "not_installed"
    except Exception:  # noqa: BLE001
        return "unknown"
    try:
        completed = subprocess.run(
            list(command), capture_output=True, text=True, timeout=timeout, check=False
        )
        line = _pick_version_line(completed.stdout or "") or _pick_version_line(
            completed.stderr or ""
        )
        return line or "unknown"
    except Exception as exc:  # noqa: BLE001 - a probe must never break a run
        # Includes FileNotFoundError for an installed script whose interpreter is
        # gone (broken shebang): the tool is present but cannot report a version.
        logger.debug("Version probe %s failed: %s", command, exc)
        return "unknown"


# =============================================================================
# Collectors
# =============================================================================


def executed_tools(results: Iterable[Mapping[str, Any]]) -> List[str]:
    """Names of the tools that actually ran, in first-seen order.

    A tool "ran" when any of its result records has a status in
    :data:`EXECUTED_STATUSES`; ``not_available``/``skipped`` records are not
    counted (nothing to cite for a tool that did not execute).
    """
    seen: Dict[str, None] = {}
    for record in results:
        if not isinstance(record, Mapping):
            continue
        tool = record.get("tool")
        if tool and str(record.get("status", "")) in EXECUTED_STATUSES:
            seen.setdefault(str(tool), None)
    return list(seen)


def _adapter_for(tool: str) -> Any:
    """The adapter instance for ``tool`` without loading the whole registry.

    After a scan/audit the ``AdapterLoader`` registry is already populated and
    is used as is. When it is not (``miesc fix``), only the one adapter module is
    imported, so provenance never pays for the 50-adapter import.
    """
    try:
        from miesc.cli.constants import ADAPTER_MAP
        from miesc.cli.utils import AdapterLoader

        if AdapterLoader._loaded:
            return AdapterLoader.get_adapter(tool)
        class_name = ADAPTER_MAP.get(tool)
        if not class_name:
            return None
        import importlib

        module = importlib.import_module(f"miesc.adapters.{tool}_adapter")
        adapter_class = getattr(module, class_name, None)
        return adapter_class() if adapter_class else None
    except Exception:  # noqa: BLE001
        return None


#: Pseudo-tools the CLI adds to a run that are MIESC code, not external binaries.
_BUILTIN_TOOL_NAMES = frozenset({"access-control-semantic"})


def _is_builtin(tool: str, adapter: Any) -> bool:
    if tool.startswith("miesc") or tool in _BUILTIN_TOOL_NAMES:
        return True
    if adapter is None:
        return False
    try:
        install_cmd = str(getattr(adapter.get_metadata(), "installation_cmd", "") or "")
    except Exception:  # noqa: BLE001
        return False
    return install_cmd.strip().lower().startswith(_BUILTIN_INSTALL_PREFIXES)


def _version_command_for(tool: str, adapter: Any) -> Optional[List[str]]:
    declared = getattr(adapter, "version_command", None)
    if callable(declared):
        try:
            command = declared()
            if command:
                return [str(part) for part in command]
        except Exception:  # noqa: BLE001
            pass
    fallback = FALLBACK_VERSION_COMMANDS.get(tool)
    return list(fallback) if fallback else None


def tool_version(tool: str) -> str:
    """Version string of ``tool`` as its binary reports it, probed once per process."""
    if tool in _TOOL_VERSION_CACHE:
        return _TOOL_VERSION_CACHE[tool]
    version = "unknown"
    try:
        adapter = _adapter_for(tool)
        command = _version_command_for(tool, adapter)
        if command:
            version = probe_version(command)
        elif _is_builtin(tool, adapter):
            version = f"built-in (miesc {VERSION})"
    except Exception as exc:  # noqa: BLE001
        logger.debug("Could not resolve version of %s: %s", tool, exc)
    _TOOL_VERSION_CACHE[tool] = version
    return version


def collect_tool_versions(tools: Iterable[str]) -> Dict[str, str]:
    """``{tool: version}`` for every tool name given (see :func:`tool_version`)."""
    return {tool: tool_version(tool) for tool in tools}


def reset_tool_versions() -> None:
    """Forget cached tool versions so the next collection probes again."""
    _TOOL_VERSION_CACHE.clear()


def git_info() -> Dict[str, Any]:
    """Git SHA and dirty flag of the checkout MIESC runs from; ``None`` for a wheel."""
    info: Dict[str, Any] = {"sha": None, "dirty": None}
    try:
        root = Path(__file__).resolve().parent.parent.parent
        if not (root / ".git").exists():  # a file in worktrees, a dir in clones
            return info
        base = ["git", "-C", str(root)]
        sha = subprocess.run(
            base + ["rev-parse", "HEAD"], capture_output=True, text=True, timeout=2, check=False
        )
        if sha.returncode == 0 and sha.stdout.strip():
            info["sha"] = sha.stdout.strip()
        status = subprocess.run(
            base + ["status", "--porcelain", "--untracked-files=no"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if status.returncode == 0:
            info["dirty"] = bool(status.stdout.strip())
    except Exception as exc:  # noqa: BLE001
        logger.debug("git provenance unavailable: %s", exc)
    return info


def config_info() -> Dict[str, Any]:
    """Path and SHA-256 of the configuration file in effect.

    Uses :class:`miesc.core.config_loader.MIESCConfig`, which honours the
    ``MIESC_CONFIG`` override and per-project ``miesc.yaml`` files, so the
    recorded path is the one whose adapter/layer settings shaped the run.
    """
    try:
        from miesc.core.config_loader import get_config

        path = get_config().config_path
        return {
            "path": str(path),
            "exists": path.exists(),
            "sha256": sha256_file(path) if path.exists() else None,
        }
    except Exception as exc:  # noqa: BLE001
        logger.debug("config provenance unavailable: %s", exc)
        return {"path": None, "exists": False, "sha256": None}


#: Python distributions whose release moves results (library-backed adapters have
#: no binary to probe). Recorded only when installed.
TRACKED_PACKAGES: Sequence[str] = (
    "slither-analyzer",
    "crytic-compile",
    "solc-select",
    "scikit-learn",
    "numpy",
    "mythril",
    "manticore",
    "halmos",
    "eth-wake",
    "semgrep",
    "z3-solver",
    "torch",
)


def python_packages(names: Iterable[str] = TRACKED_PACKAGES) -> Dict[str, str]:
    """``{distribution: version}`` for the installed ones among ``names``."""
    from importlib import metadata

    found: Dict[str, str] = {}
    for name in names:
        try:
            found[name] = metadata.version(name)
        except Exception:  # noqa: BLE001 - PackageNotFoundError and odd metadata alike
            continue
    return found


def tracked_env() -> Dict[str, str]:
    """The reproducibility variables of :data:`TRACKED_ENV_VARS` that are set."""
    return {name: os.environ[name] for name in TRACKED_ENV_VARS if os.environ.get(name)}


def _solc_from_results(results: Iterable[Mapping[str, Any]]) -> Dict[str, str]:
    """``{contract: solc_version}`` recorded by the Slither adapter in its metadata."""
    selected: Dict[str, str] = {}
    for record in results:
        if not isinstance(record, Mapping) or record.get("tool") != "slither":
            continue
        metadata = record.get("metadata") or {}
        version = metadata.get("solc_version") if isinstance(metadata, Mapping) else None
        contract = record.get("contract") or (
            metadata.get("contract_analyzed") if isinstance(metadata, Mapping) else None
        )
        if version and contract:
            selected[str(contract)] = str(version)
    return selected


def _solc_via_adapter(contracts: Iterable[str]) -> Dict[str, str]:
    """Re-run the Slither adapter's solc selection for contracts lacking a record."""
    selected: Dict[str, str] = {}
    adapter = _adapter_for("slither")
    detect = getattr(adapter, "_detect_solidity_version", None)
    if not callable(detect):
        try:
            from miesc.adapters.slither_adapter import SlitherAdapter

            detect = SlitherAdapter()._detect_solidity_version
        except Exception:  # noqa: BLE001
            return selected
    for contract in contracts:
        try:
            if Path(contract).is_file():
                selected[str(contract)] = str(detect(str(contract)))
        except Exception:  # noqa: BLE001
            continue
    return selected


def solc_info(
    results: Iterable[Mapping[str, Any]], contracts: Optional[Iterable[str]] = None
) -> Dict[str, Any]:
    """Which ``solc`` compiled each contract, and what those binaries report.

    ``per_contract`` is the version the Slither adapter selected for the file's
    pragma (from its result metadata when present, otherwise recomputed with
    the same selection code). ``binaries`` maps each distinct selected version
    to the ``--version`` line of the solc-select artifact that Slither is
    pointed at, or ``"not_installed"`` when the artifact is missing.
    ``path_default`` is the ``solc`` on ``PATH`` (used when no artifact exists).
    """
    records = list(results)
    per_contract = _solc_from_results(records)
    wanted = [str(c) for c in (contracts or [])]
    missing = [c for c in wanted if c not in per_contract]
    if missing:
        per_contract.update(_solc_via_adapter(missing))

    binaries: Dict[str, str] = {}
    artifacts = Path(os.path.expanduser(str(_SOLC_ARTIFACTS)))
    for version in sorted(set(per_contract.values())):
        binary = artifacts / f"solc-{version}" / f"solc-{version}"
        cache_key = f"solc:{version}"
        if cache_key not in _TOOL_VERSION_CACHE:
            _TOOL_VERSION_CACHE[cache_key] = (
                probe_version([str(binary), "--version"]) if binary.is_file() else "not_installed"
            )
        binaries[version] = _TOOL_VERSION_CACHE[cache_key]

    if "solc:PATH" not in _TOOL_VERSION_CACHE:
        _TOOL_VERSION_CACHE["solc:PATH"] = probe_version(["solc", "--version"])

    return {
        "per_contract": per_contract,
        "binaries": binaries,
        "path_default": _TOOL_VERSION_CACHE["solc:PATH"],
    }


def _llm_tools() -> set[str]:
    try:
        from miesc.cli.utils import AdapterLoader

        return set(AdapterLoader.llm_tools())
    except Exception:  # noqa: BLE001
        return set()


# =============================================================================
# Block builder
# =============================================================================


def build_provenance(
    results: Iterable[Mapping[str, Any]],
    *,
    command: str,
    contracts: Optional[Iterable[str]] = None,
    llm_free: Optional[bool] = None,
    llm_used: Optional[bool] = False,
    argv: Optional[Sequence[str]] = None,
    extra: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Build the ``provenance`` block for one run.

    Args:
        results: Per-tool result records of the run (``run_tool`` shape: ``tool``,
            ``status``, ``contract``, ``metadata``). Only tools that executed are
            probed for a version.
        command: The MIESC subcommand (``"scan"``, ``"audit full"``, ...).
        contracts: Contract paths of the run, for the per-contract solc record.
        llm_free: Explicit LLM-free flag (``evaluate --no-llm``). When ``None`` it
            is derived: no executed tool requires an LLM and ``llm_used`` is False.
        llm_used: Set by callers that invoke an LLM outside the adapters
            (``--llm-enhance``, ``--model``, ``--verify-model``). ``None`` means
            the caller cannot tell; ``llm_free`` is then recorded as ``null``.
        argv: Command line to record; defaults to ``sys.argv``.
        extra: Command-specific facts stored under ``"extra"``.

    Never raises: a collector that fails leaves ``"unknown"``/``None`` in its
    field, and a failure of the builder itself still returns a minimal block.
    """
    records = [r for r in results if isinstance(r, Mapping)]
    argv_list = [str(part) for part in (argv if argv is not None else sys.argv)]
    block: Dict[str, Any] = {
        "schema": SCHEMA_VERSION,
        "command": command,
        "argv": argv_list,
        "command_line": shlex.join(argv_list),
        "cwd": None,
        "timestamp": datetime.now().isoformat(),
        "miesc": {"version": VERSION, "git_sha": None, "git_dirty": None},
        "python": {
            "version": platform.python_version(),
            "implementation": platform.python_implementation(),
            "executable": sys.executable,
        },
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "tools": {},
        "python_packages": {},
        "solc": {"per_contract": {}, "binaries": {}, "path_default": "unknown"},
        "config": {"path": None, "exists": False, "sha256": None},
        "env": {},
        "llm_free": None,
    }
    try:
        block["cwd"] = str(Path.cwd())
    except Exception:  # noqa: BLE001
        pass
    try:
        git = git_info()
        block["miesc"]["git_sha"] = git.get("sha")
        block["miesc"]["git_dirty"] = git.get("dirty")
    except Exception:  # noqa: BLE001
        pass
    tools_run: List[str] = []
    try:
        tools_run = executed_tools(records)
        block["tools"] = collect_tool_versions(tools_run)
    except Exception as exc:  # noqa: BLE001
        logger.debug("tool version provenance failed: %s", exc)
    try:
        block["python_packages"] = python_packages()
    except Exception as exc:  # noqa: BLE001
        logger.debug("package provenance failed: %s", exc)
    try:
        block["solc"] = solc_info(records, contracts)
    except Exception as exc:  # noqa: BLE001
        logger.debug("solc provenance failed: %s", exc)
    try:
        block["config"] = config_info()
    except Exception:  # noqa: BLE001
        pass
    try:
        block["env"] = tracked_env()
    except Exception:  # noqa: BLE001
        pass
    try:
        if llm_free is None and llm_used is not None:
            llm_free = not llm_used and not (set(tools_run) & _llm_tools())
        block["llm_free"] = None if llm_free is None else bool(llm_free)
    except Exception:  # noqa: BLE001
        block["llm_free"] = bool(llm_free) if llm_free is not None else None
    if extra:
        block["extra"] = dict(extra)
    return block


# =============================================================================
# Comparison support (``miesc evaluate compare``)
# =============================================================================


def provenance_summary(data: Mapping[str, Any]) -> Dict[str, str]:
    """Flatten a stored run into ``{label: value}`` rows for side-by-side display.

    Runs written before this block existed (the paper artifacts) fall back to
    their top-level ``version`` and ``experiment_card``/``reproducibility``
    fields; everything they did not record reads ``"n/a (pre-provenance artifact)"``.
    """
    na = "n/a (pre-provenance artifact)"
    prov = data.get("provenance") if isinstance(data, Mapping) else None
    card = data.get("experiment_card", {}) if isinstance(data, Mapping) else {}
    repro = data.get("reproducibility", {}) if isinstance(data, Mapping) else {}
    card = card if isinstance(card, Mapping) else {}
    repro = repro if isinstance(repro, Mapping) else {}

    def _env(name: str) -> str:
        return str(repro.get(name)) if repro.get(name) not in (None, "not_set") else "not set"

    if not isinstance(prov, Mapping):
        rows: Dict[str, str] = {
            "MIESC version": str(data.get("version") or card.get("version") or "?"),
            "Git SHA": na,
            "Python": str(card.get("python_version") or na),
            "OS / arch": str(card.get("platform") or na),
            "Tool versions": na,
            "solc builds": na,
            "Config sha256": na,
            "MIESC_SEED": _env("seed"),
            "MIESC_LLM_PROVIDER": _env("llm_provider"),
            "MIESC_LLM_MODEL": _env("llm_model"),
            "LLM-free": str(card.get("llm_free", na)),
            "Command": str(repro.get("command") or na),
        }
        return rows

    miesc = prov.get("miesc", {}) or {}
    python = prov.get("python", {}) or {}
    plat = prov.get("platform", {}) or {}
    env = prov.get("env", {}) or {}
    solc = prov.get("solc", {}) or {}
    tools = prov.get("tools", {}) or {}
    sha = miesc.get("git_sha")
    sha_text = (
        "not a checkout"
        if not sha
        else str(sha)[:12] + (" (dirty)" if miesc.get("git_dirty") else "")
    )
    rows = {
        "MIESC version": str(miesc.get("version", "?")),
        "Git SHA": sha_text,
        "Python": str(python.get("version", "?")),
        "OS / arch": f"{plat.get('system', '?')} {plat.get('release', '')} {plat.get('machine', '')}".strip(),
    }
    for tool in sorted(tools):
        rows[f"tool: {tool}"] = str(tools[tool])
    if not tools:
        rows["Tool versions"] = "none executed"
    packages = prov.get("python_packages", {}) or {}
    for name in sorted(packages):
        rows[f"pkg: {name}"] = str(packages[name])
    binaries = solc.get("binaries", {}) or {}
    rows["solc builds"] = ", ".join(sorted(binaries)) if binaries else "none selected"
    config = prov.get("config", {}) or {}
    rows["Config sha256"] = str(config.get("sha256") or "n/a")[:16]
    for name in TRACKED_ENV_VARS:
        rows[name] = str(env.get(name, "not set"))
    rows["LLM-free"] = str(prov.get("llm_free"))
    rows["Command"] = str(prov.get("command_line") or " ".join(prov.get("argv", [])) or "?")
    return rows


def provenance_rows(
    data_a: Mapping[str, Any], data_b: Mapping[str, Any]
) -> List[tuple[str, str, str]]:
    """``(label, value_a, value_b)`` rows covering both runs, same order for both."""
    summary_a = provenance_summary(data_a)
    summary_b = provenance_summary(data_b)
    labels: List[str] = list(summary_a)
    for label in summary_b:
        if label not in summary_a:
            labels.append(label)
    # Keep tool rows together and the trailing rows (env, LLM-free, Command) last.
    tail = [
        lbl
        for lbl in labels
        if lbl in ("solc builds", "Config sha256", *TRACKED_ENV_VARS, "LLM-free", "Command")
    ]
    head = [lbl for lbl in labels if lbl not in tail]
    ordered = head + [
        lbl
        for lbl in ("solc builds", "Config sha256", *TRACKED_ENV_VARS, "LLM-free", "Command")
        if lbl in tail
    ]
    return [(lbl, summary_a.get(lbl, "—"), summary_b.get(lbl, "—")) for lbl in ordered]


__all__ = [
    "SCHEMA_VERSION",
    "TRACKED_ENV_VARS",
    "FALLBACK_VERSION_COMMANDS",
    "build_provenance",
    "collect_tool_versions",
    "config_info",
    "executed_tools",
    "git_info",
    "probe_version",
    "provenance_rows",
    "provenance_summary",
    "python_packages",
    "reset_tool_versions",
    "sha256_file",
    "solc_info",
    "tool_version",
    "tracked_env",
]
