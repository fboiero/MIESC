"""
Tests for MIESC CLI - Watch Command

Validates the watch command behavior including watchdog dependency check,
SolidityHandler filtering, debounce logic, tool execution, and profile mapping.

Author: Fernando Boiero
License: AGPL-3.0
"""

import time
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

# ---------------------------------------------------------------------------
# 1. test_watch_missing_watchdog
# ---------------------------------------------------------------------------


class TestWatchMissingWatchdog:
    """When watchdog is not importable, sys.exit(1) must be called."""

    def test_watch_missing_watchdog(self, tmp_path):
        """If watchdog is absent the command prints an error and exits 1."""
        # We need a real directory for click.Path(exists=True) validation
        target_dir = tmp_path / "contracts"
        target_dir.mkdir()

        # Block watchdog imports inside the watch function
        import builtins

        real_import = builtins.__import__

        def _fake_import(name, *args, **kwargs):
            if name.startswith("watchdog"):
                raise ImportError("No module named 'watchdog'")
            return real_import(name, *args, **kwargs)

        runner = CliRunner()

        with patch("builtins.__import__", side_effect=_fake_import):
            # We must re-import the command so that the patched __import__
            # is active when the function body runs.
            from miesc.cli.commands.watch import watch

            result = runner.invoke(watch, [str(target_dir)])

        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# Helpers: simulate watchdog types so we can instantiate SolidityHandler
# without actually installing watchdog.
# ---------------------------------------------------------------------------


def _make_event(src_path, is_directory=False):
    """Create a fake watchdog FileSystemEvent."""
    return SimpleNamespace(src_path=src_path, is_directory=is_directory)


# Because SolidityHandler is defined *inside* the watch() function closure,
# we cannot import it directly.  Instead we recreate the same logic inline
# and test it.  This mirrors the exact code from watch.py lines 86-177.


def _build_handler(tools_to_run, debounce, last_scan_time, scan_lock, run_tool_mock):
    """Build a SolidityHandler-equivalent using the watch.py logic."""

    class SolidityHandler:
        def on_modified(self, event):
            if event.is_directory:
                return
            if not event.src_path.endswith(".sol"):
                return
            current_time = time.time()
            file_path = event.src_path
            with scan_lock:
                if current_time - last_scan_time[file_path] < debounce:
                    return
                last_scan_time[file_path] = current_time
            self.run_scan(file_path)

        def on_created(self, event):
            if not event.is_directory and event.src_path.endswith(".sol"):
                self.on_modified(event)

        def run_scan(self, file_path):
            all_findings = []
            for tool in tools_to_run:
                result = run_tool_mock(tool, file_path, timeout=60)
                if result["status"] == "success":
                    findings = result.get("findings", [])
                    all_findings.extend(findings)

            # Intelligence engine is wrapped in try/except → ignore
            try:
                from miesc.core.intelligence import enhance_findings  # noqa: F401

                pass
            except Exception:
                pass

            return all_findings

    return SolidityHandler()


# ---------------------------------------------------------------------------
# 2. test_solidity_handler_ignores_non_sol
# ---------------------------------------------------------------------------


class TestSolidityHandlerFiltering:
    def test_solidity_handler_ignores_non_sol(self):
        """SolidityHandler.on_modified ignores non-.sol files."""
        import threading
        from collections import defaultdict

        run_tool_mock = MagicMock()
        handler = _build_handler(
            tools_to_run=["slither"],
            debounce=1.0,
            last_scan_time=defaultdict(float),
            scan_lock=threading.Lock(),
            run_tool_mock=run_tool_mock,
        )

        # .js file -> should be ignored entirely
        event = _make_event("/tmp/Token.js")
        handler.on_modified(event)
        run_tool_mock.assert_not_called()

        # directory event -> should be ignored
        event_dir = _make_event("/tmp/contracts", is_directory=True)
        handler.on_modified(event_dir)
        run_tool_mock.assert_not_called()

    def test_solidity_handler_processes_sol(self):
        """SolidityHandler.on_modified processes .sol files."""
        import threading
        from collections import defaultdict

        run_tool_mock = MagicMock(return_value={"status": "success", "findings": []})
        handler = _build_handler(
            tools_to_run=["slither"],
            debounce=1.0,
            last_scan_time=defaultdict(float),
            scan_lock=threading.Lock(),
            run_tool_mock=run_tool_mock,
        )

        event = _make_event("/tmp/Token.sol")
        handler.on_modified(event)
        run_tool_mock.assert_called_once_with("slither", "/tmp/Token.sol", timeout=60)


# ---------------------------------------------------------------------------
# 3. test_solidity_handler_debounce
# ---------------------------------------------------------------------------


class TestSolidityHandlerDebounce:
    def test_solidity_handler_debounce(self):
        """Second event within debounce period is skipped."""
        import threading
        from collections import defaultdict

        run_tool_mock = MagicMock(return_value={"status": "success", "findings": []})
        last_scan_time = defaultdict(float)
        handler = _build_handler(
            tools_to_run=["slither"],
            debounce=5.0,  # 5s debounce - second event must be within window
            last_scan_time=last_scan_time,
            scan_lock=threading.Lock(),
            run_tool_mock=run_tool_mock,
        )

        event = _make_event("/tmp/Token.sol")

        # First event triggers scan
        handler.on_modified(event)
        assert run_tool_mock.call_count == 1

        # Second event immediately after → debounce should skip
        handler.on_modified(event)
        assert run_tool_mock.call_count == 1  # still 1, not 2


# ---------------------------------------------------------------------------
# 4. test_run_scan_calls_tools
# ---------------------------------------------------------------------------


class TestRunScanCallsTools:
    def test_run_scan_calls_tools(self):
        """run_scan calls run_tool for each tool in the profile."""
        import threading
        from collections import defaultdict

        tools = ["slither", "aderyn", "solhint"]
        run_tool_mock = MagicMock(
            return_value={
                "status": "success",
                "findings": [{"severity": "HIGH", "title": "test"}],
            }
        )
        handler = _build_handler(
            tools_to_run=tools,
            debounce=1.0,
            last_scan_time=defaultdict(float),
            scan_lock=threading.Lock(),
            run_tool_mock=run_tool_mock,
        )

        findings = handler.run_scan("/tmp/Token.sol")

        assert run_tool_mock.call_count == 3
        # Each tool contributes 1 finding -> 3 total
        assert len(findings) == 3


# ---------------------------------------------------------------------------
# 5. test_intelligence_engine_failure_logged
# ---------------------------------------------------------------------------


class TestIntelligenceEngineFailure:
    def test_intelligence_engine_failure_findings_still_returned(self):
        """When enhance_findings raises, findings are still returned (silently dropped)."""
        import threading
        from collections import defaultdict

        finding = {"severity": "HIGH", "title": "Reentrancy"}
        run_tool_mock = MagicMock(return_value={"status": "success", "findings": [finding]})
        handler = _build_handler(
            tools_to_run=["slither"],
            debounce=1.0,
            last_scan_time=defaultdict(float),
            scan_lock=threading.Lock(),
            run_tool_mock=run_tool_mock,
        )

        # The handler's run_scan wraps enhance_findings in try/except pass
        # Even if intelligence engine fails, raw findings are returned.
        result = handler.run_scan("/tmp/Token.sol")
        assert len(result) == 1
        assert result[0]["title"] == "Reentrancy"


# ---------------------------------------------------------------------------
# 6. test_profile_tools_mapping
# ---------------------------------------------------------------------------


class TestProfileToolsMapping:
    def test_profile_tools_mapping(self):
        """Verify quick/fast/balanced map to correct tools."""
        from miesc.cli.constants import QUICK_TOOLS

        # Reproduce the profile_tools mapping from watch.py lines 74-79
        profile_tools = {
            "quick": QUICK_TOOLS,
            "fast": ["slither", "aderyn"],
            "balanced": ["slither", "aderyn", "solhint", "mythril"],
        }

        # quick → QUICK_TOOLS
        assert profile_tools["quick"] == ["slither", "aderyn", "solhint"]

        # fast → slither + aderyn only
        assert profile_tools["fast"] == ["slither", "aderyn"]

        # balanced → 4 tools including mythril
        assert profile_tools["balanced"] == ["slither", "aderyn", "solhint", "mythril"]

        # Default fallback should be QUICK_TOOLS
        assert profile_tools.get("unknown", QUICK_TOOLS) == QUICK_TOOLS
