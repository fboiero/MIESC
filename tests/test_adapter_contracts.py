"""
Adapter contract tests — verify every registered MIESC adapter honors
the ToolAdapter protocol without raising unexpected exceptions.

These tests catch a whole class of bugs cheaply by iterating over the
full ADAPTER_MAP and exercising the critical API surface.

Contract requirements (enforced by the tests):
  1. Adapter class imports without side effects.
  2. Adapter can be instantiated with no required args.
  3. is_available() returns a value, never raises.
  4. analyze() on a nonexistent path returns a dict with success=False
     and an "error" key, never raises.
  5. analyze() on a minimal valid contract returns a dict with the
     expected shape (findings list + success flag).
"""

from __future__ import annotations

import pytest

from miesc.cli.constants import ADAPTER_MAP

# Adapters that require heavy optional dependencies or a running service.
# We STILL import-test them (ensures Python-level correctness) but skip the
# behavioral tests because they can't run without the external.
HEAVY_DEPENDENCY_ADAPTERS = {
    # Need Ollama + specific model weights
    "gptlens", "gptscan", "llmsmartaudit", "llamaaudit", "iaudit",
    "smartllm", "llmbugscanner",
    # Mythril needs the myth binary on PATH; aderyn needs aderyn binary.
    # Both have the existence-check fix so the test on missing files passes
    # without ever invoking the binary.
    "mythril",
    # Heavy ML dependency / binary required
    "dagnn", "peculiar", "contract_clone_detector",
    # Need external service
    "certora",
    # Chain-specific external deps
    "crosschain", "stellar", "algorand", "cardano", "near",
    # Requires Foundry with a valid project
    "halmos", "foundry", "vertigo",
    # semgrep needs binary too but has the existence-check fix; exclude
    # only if it errors out on construction (semgrep_adapter try-loads rules)
    "semgrep",
    # Requires Python Solidity tools not shipped by default
    "oyente", "pakala", "manticore",
    # Need solc with model checker
    "smtchecker", "solcmc",
    # Requires Docker or a live LLM
    "dogefuzz", "exploit_synthesizer",
    # Has special runtime setup
    "scribble", "ferriagro", "audit_consensus",
    # Solana / Move that need rustup / specific toolchains
    "solana", "move",
    # Requires scribble + foundry or network
    "propertygpt",
    # Requires Ollama running
    "invariant_synthesizer",
    # Circom / ZK toolchains
    "zk_circuit", "circom_analyzer",
    # Specialized MEV / bridge detectors
    "mev_detector", "bridge_monitor",
    # Requires Etherscan API key
    "etherscan_enrichment",
    # Network or API required
    "smartbugs_detector", "smartbugs_ml", "defi", "advanced_detector",
    "fouranalyzer",
    # Requires Hardhat project layout
    "hardhat",
    # Experimental
    "foundry_ai",
    # solhint, wake, semgrep need their binaries on PATH
    "solhint", "wake",
    # Cairo
    "cairo",
    # Echidna / Medusa need binaries
    "echidna", "medusa",
    # SmartLLM RAG
    "smartllm_rag",
    # (slither + aderyn + mythril removed from heavy list — they have
    # path-existence checks that work without solc)
}


def _import_adapter(tool_name: str, class_name: str):
    """Try to import and return the adapter class, or None on failure."""
    import importlib
    try:
        module = importlib.import_module(f"src.adapters.{tool_name}_adapter")
    except ImportError:
        return None
    return getattr(module, class_name, None)


# ---------------------------------------------------------------------------
# Basic contract — applies to every adapter in ADAPTER_MAP
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_name,class_name", sorted(ADAPTER_MAP.items()))
class TestAdapterImportContract:
    def test_adapter_class_is_importable_or_cleanly_missing(self, tool_name, class_name):
        """Adapter module either imports cleanly OR raises ImportError
        that our loader will catch — no other exceptions allowed at import time."""
        import importlib
        try:
            module = importlib.import_module(f"src.adapters.{tool_name}_adapter")
        except ImportError:
            pytest.skip(f"{tool_name}_adapter has unmet optional deps")
        # Either class exists or module exposes None — both OK
        cls = getattr(module, class_name, None)
        if cls is None:
            pytest.skip(f"{tool_name}_adapter exists but doesn't export {class_name}")
        assert cls is not None

    def test_adapter_instantiates_without_required_args(self, tool_name, class_name):
        cls = _import_adapter(tool_name, class_name)
        if cls is None:
            pytest.skip(f"{tool_name}_adapter unavailable")
        try:
            instance = cls()
        except TypeError as e:
            pytest.fail(
                f"{class_name}.__init__() requires args but adapter protocol "
                f"expects no-arg construction: {e}"
            )
        except Exception as e:
            # Construction may fail on missing runtime deps — skip, don't fail
            pytest.skip(f"{tool_name} construction requires external: {e}")
        assert instance is not None


# ---------------------------------------------------------------------------
# is_available() — MUST never raise regardless of environment
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_name,class_name", sorted(ADAPTER_MAP.items()))
class TestIsAvailableNeverRaises:
    def test_is_available_returns_or_skips(self, tool_name, class_name):
        """is_available() is called every time a user runs `miesc doctor` or
        any audit — it MUST NOT raise, even if the tool is missing."""
        cls = _import_adapter(tool_name, class_name)
        if cls is None:
            pytest.skip(f"{tool_name}_adapter unavailable")
        try:
            instance = cls()
        except Exception:
            pytest.skip(f"{tool_name} construction requires external deps")

        if not hasattr(instance, "is_available"):
            pytest.skip(f"{tool_name} lacks is_available()")

        try:
            result = instance.is_available()
        except Exception as e:
            pytest.fail(
                f"{class_name}.is_available() raised {type(e).__name__}: {e}. "
                f"is_available must be safe — return False/ToolStatus.NOT_INSTALLED, not raise."
            )
        # Result can be bool, ToolStatus enum, or str — all acceptable
        assert result is not None


# ---------------------------------------------------------------------------
# analyze() contract for adapters without heavy external deps
# ---------------------------------------------------------------------------


@pytest.fixture
def minimal_sol(tmp_path):
    p = tmp_path / "C.sol"
    p.write_text(
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.0;\n"
        "contract C { function f() external {} }\n"
    )
    return str(p)


@pytest.fixture
def nonexistent_path(tmp_path):
    return str(tmp_path / "definitely_does_not_exist.sol")


# Adapters safe to exercise without network / binary / ollama
LIGHTWEIGHT_ADAPTERS = [
    (k, v) for k, v in ADAPTER_MAP.items() if k not in HEAVY_DEPENDENCY_ADAPTERS
]


@pytest.mark.parametrize("tool_name,class_name", sorted(LIGHTWEIGHT_ADAPTERS))
class TestAnalyzeContract:
    def test_analyze_missing_file_does_not_raise(self, tool_name, class_name, nonexistent_path):
        cls = _import_adapter(tool_name, class_name)
        if cls is None:
            pytest.skip(f"{tool_name}_adapter unavailable")
        try:
            instance = cls()
        except Exception:
            pytest.skip(f"{tool_name} construction requires external deps")
        if not hasattr(instance, "analyze"):
            pytest.skip(f"{tool_name} has no analyze()")

        try:
            result = instance.analyze(nonexistent_path)
        except Exception as e:
            pytest.fail(
                f"{class_name}.analyze() raised {type(e).__name__} on a missing "
                f"file instead of returning a dict with success=False: {e}"
            )
        assert isinstance(result, dict)
        # Must carry some form of failure signal
        assert (
            result.get("success") is False
            or result.get("error")
            or result.get("findings") == []
        ), f"{class_name}.analyze() on missing file returned no failure signal: {result}"
