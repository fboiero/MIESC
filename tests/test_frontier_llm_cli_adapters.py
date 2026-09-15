import json
import subprocess
from unittest.mock import patch

import pytest

from miesc.adapters.frontier_llm_adapter import FrontierLLMAdapter
from miesc.core.tool_protocol import ToolStatus


def test_subscription_cli_availability_dispatch():
    with patch("shutil.which", return_value="/usr/bin/cli"):
        assert FrontierLLMAdapter("claude_code").is_available() == ToolStatus.AVAILABLE
        assert FrontierLLMAdapter("codex_cli").is_available() == ToolStatus.AVAILABLE


def test_claude_code_analysis_parses_findings():
    adapter = FrontierLLMAdapter("claude_code")
    findings = json.dumps([{"title": "Reentrancy", "severity": "High"}])
    completed = subprocess.CompletedProcess(
        ["claude"], 0, json.dumps({"is_error": False, "result": findings}), ""
    )
    with patch("subprocess.run", return_value=completed):
        assert adapter._analyze_claude_code("contract C {}")[0]["title"] == "Reentrancy"


def test_codex_analysis_parses_findings():
    adapter = FrontierLLMAdapter("codex_cli")
    findings = json.dumps([{"title": "Access Control", "severity": "Critical"}])

    def fake_run(cmd, **kwargs):
        output_path = cmd[cmd.index("-o") + 1]
        with open(output_path, "w", encoding="utf-8") as output_file:
            output_file.write(findings)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    with patch("subprocess.run", side_effect=fake_run):
        assert adapter._analyze_codex_cli("contract C {}")[0]["title"] == "Access Control"


def test_cli_analysis_surfaces_transport_errors():
    completed = subprocess.CompletedProcess(["codex"], 1, "", "rate limit exceeded")
    with (
        patch("subprocess.run", return_value=completed),
        pytest.raises(RuntimeError, match="rate limited"),
    ):
        FrontierLLMAdapter("codex_cli")._analyze_codex_cli("contract C {}")
