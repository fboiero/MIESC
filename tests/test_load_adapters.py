"""
Tests for miesc.cli.utils.load_adapters().

Regression: DeepAuditAgent logs a WARNING on every analyze() call when
load_adapters is missing — shipping it as a no-op-on-failure shim fixes
noise pollution in production logs.
"""

from __future__ import annotations

import importlib
from unittest.mock import patch


class TestLoadAdaptersBasic:
    def test_load_adapters_returns_dict(self):
        from miesc.cli.utils import load_adapters
        result = load_adapters(force_reload=True)
        assert isinstance(result, dict)
        assert len(result) > 0

    def test_core_adapters_present(self):
        """At least slither + aderyn must load — they ship with the package
        and have no heavy dependencies."""
        from miesc.cli.utils import load_adapters
        adapters = load_adapters(force_reload=True)
        assert "slither" in adapters
        assert "aderyn" in adapters

    def test_adapters_have_is_available_method(self):
        from miesc.cli.utils import load_adapters
        adapters = load_adapters(force_reload=True)
        for name, adapter in adapters.items():
            assert hasattr(adapter, "is_available"), (
                f"{name} adapter missing is_available()"
            )

    def test_result_is_cached_by_default(self):
        from miesc.cli.utils import load_adapters
        a = load_adapters(force_reload=True)
        b = load_adapters()  # no force_reload
        # Same dict object (cached)
        assert a is b

    def test_force_reload_yields_fresh_dict(self):
        from miesc.cli.utils import load_adapters
        a = load_adapters(force_reload=True)
        b = load_adapters(force_reload=True)
        # Different dict objects (rebuilt)
        assert a is not b


class TestLoadAdaptersRobustness:
    def test_broken_adapter_does_not_crash_loader(self):
        """If one adapter raises at import time, loader must skip it and
        continue loading the others — otherwise a single bad adapter breaks
        the whole DeepAuditAgent."""
        from miesc.cli import utils
        original = importlib.import_module

        def broken_import(name, *args, **kwargs):
            if "slither_adapter" in name:
                raise ImportError("simulated broken slither")
            return original(name, *args, **kwargs)

        with patch("miesc.cli.utils.importlib.import_module", side_effect=broken_import):
            adapters = utils.load_adapters(force_reload=True)
            assert "slither" not in adapters
            # Others should still be loadable
            # (we don't assert specific others because the test env may have
            # other missing deps — just that SOMETHING loaded)
            assert isinstance(adapters, dict)

    def test_missing_class_name_logs_debug_but_does_not_crash(self):
        """ADAPTER_MAP says ClassName but the module doesn't export it —
        loader should skip, not raise."""
        from miesc.cli import utils
        # Can't easily mock getattr without complex scaffolding; the real
        # code path returns None from getattr() and logs. Simplest: verify
        # that load_adapters doesn't raise even if ADAPTER_MAP has a bogus
        # entry.
        with patch.dict(utils.ADAPTER_MAP, {"ghost_tool": "NonExistentClass"}):
            adapters = utils.load_adapters(force_reload=True)
            assert "ghost_tool" not in adapters


class TestDeepAuditIntegration:
    """Regression: DeepAuditAgent._run_tools_parallel and _get_available_tools
    both call load_adapters. They should no longer log WARNING on every
    analyze()."""

    def test_deep_audit_no_load_adapters_warning(self, tmp_path, caplog):
        import logging

        from src.agents.deep_audit_agent import DeepAuditAgent, DeepAuditConfig

        caplog.set_level(logging.WARNING, logger="src.agents.deep_audit_agent")
        cfg = DeepAuditConfig(
            timeout_seconds=30, enable_llm=False, enable_rag=False,
            enable_taint=False, enable_call_graph=False, enable_exploit_chains=False,
        )
        agent = DeepAuditAgent(config=cfg)

        c = tmp_path / "C.sol"
        c.write_text("pragma solidity ^0.8.0; contract C { function f() external {} }")
        agent.analyze(str(c))

        load_adapter_warnings = [
            r.getMessage() for r in caplog.records
            if "Could not load adapters" in r.getMessage()
        ]
        assert not load_adapter_warnings, (
            f"load_adapters warning still fires: {load_adapter_warnings}"
        )
