import json
import subprocess
from unittest.mock import patch

import pytest

from miesc.llm.cli_subscription import (
    call_claude_cli,
    call_claude_cli_agentic,
    call_codex_cli,
    check_claude_cli,
    check_codex_cli,
    classify_cli_error,
)


def test_cli_availability_uses_path():
    with patch("shutil.which", return_value="/usr/bin/cli"):
        assert check_claude_cli()
        assert check_codex_cli()
    with patch("shutil.which", return_value=None):
        assert not check_claude_cli()
        assert not check_codex_cli()


@pytest.mark.parametrize(
    ("output", "expected"),
    [
        ("ERROR: usage limit reached; try tomorrow", "usage limit reached"),
        ("ERROR: rate limit exceeded", "rate limited"),
        ("ERROR: not logged in", "not authenticated"),
        ("unexpected failure", "CLI failed"),
    ],
)
def test_cli_error_classification(output, expected):
    assert expected in classify_cli_error(output, "Codex")


def test_call_claude_cli_returns_result():
    completed = subprocess.CompletedProcess(
        ["claude"], 0, json.dumps({"is_error": False, "result": "OK"}), ""
    )
    with patch("subprocess.run", return_value=completed):
        assert call_claude_cli("ping") == "OK"


def test_call_claude_cli_agentic_enables_tools_and_cwd():
    completed = subprocess.CompletedProcess(
        ["claude"], 0, json.dumps({"is_error": False, "result": "[]"}), ""
    )
    with patch("subprocess.run", return_value=completed) as mock_run:
        result = call_claude_cli_agentic("audit this repo", cwd="/tmp/protocol")
    assert result == "[]"
    kwargs = mock_run.call_args.kwargs
    cmd = mock_run.call_args.args[0]
    assert kwargs["cwd"] == "/tmp/protocol"
    assert "Read,Grep,Glob" in cmd
    assert "Bash" not in "".join(cmd)


def test_call_claude_cli_default_has_no_tools():
    completed = subprocess.CompletedProcess(
        ["claude"], 0, json.dumps({"is_error": False, "result": "OK"}), ""
    )
    with patch("subprocess.run", return_value=completed) as mock_run:
        call_claude_cli("ping")
    cmd = mock_run.call_args.args[0]
    tools_index = cmd.index("--tools")
    assert cmd[tools_index + 1] == ""


def test_call_claude_cli_reports_missing_binary():
    with (
        patch("subprocess.run", side_effect=FileNotFoundError()),
        pytest.raises(RuntimeError, match="claude CLI not found"),
    ):
        call_claude_cli("ping")


def test_call_codex_cli_reads_output_file():
    def fake_run(cmd, **kwargs):
        output_path = cmd[cmd.index("-o") + 1]
        with open(output_path, "w", encoding="utf-8") as output_file:
            output_file.write("OK")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    with patch("subprocess.run", side_effect=fake_run):
        assert call_codex_cli("ping") == "OK"


def test_call_codex_cli_classifies_failure():
    completed = subprocess.CompletedProcess(["codex"], 1, "", "rate limit exceeded")
    with (
        patch("subprocess.run", return_value=completed),
        pytest.raises(RuntimeError, match="rate limited"),
    ):
        call_codex_cli("ping")
