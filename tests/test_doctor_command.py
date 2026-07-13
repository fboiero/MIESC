import asyncio
import os
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from click.testing import CliRunner

from miesc.cli.commands.doctor import _deepseek_doctor_status, doctor
from miesc.cli.constants import LAYERS


def test_doctor_uses_dynamic_tool_total_and_full_status_text():
    total_tools = sum(len(layer["tools"]) for layer in LAYERS.values())

    def fake_tool_status(tool):
        if tool == "iaudit":
            return {"available": False, "status": "configuration_error"}
        return {"available": True, "status": "available"}

    fake_completed = SimpleNamespace(stdout="tool version 1.0\n", stderr="")

    with (
        patch("miesc.cli.commands.doctor.print_banner"),
        patch("miesc.cli.commands.doctor.info"),
        patch("miesc.cli.commands.doctor.subprocess.run", return_value=fake_completed),
        patch(
            "miesc.cli.commands.doctor._deepseek_doctor_status",
            return_value=("[green]ready[/green]", "deepseek-v4-flash available"),
        ),
        patch(
            "miesc.cli.commands.doctor.AdapterLoader.check_tool_status",
            side_effect=fake_tool_status,
        ),
    ):
        result = CliRunner().invoke(doctor)

    assert result.exit_code == 0
    assert f"Security Tools ({total_tools} Total)" in result.output
    assert f"{total_tools - 1}/{total_tools}" in result.output
    assert "configuration_error" in result.output
    assert "configuration_…" not in result.output


def test_deepseek_doctor_status_no_key():
    with patch.dict(os.environ, {}, clear=True):
        status, details = _deepseek_doctor_status()

    assert status == "[dim]not set[/dim]"
    assert "DEEPSEEK_API_KEY" in details


def test_deepseek_doctor_status_ready():
    with (
        patch.dict(
            os.environ,
            {
                "DEEPSEEK_API_KEY": "test-key",
                "DEEPSEEK_BASE_URL": "https://api.deepseek.example",
                "MIESC_LLM_PROVIDER": "deepseek",
                "MIESC_LLM_MODEL": "deepseek-v4-pro",
            },
            clear=True,
        ),
        patch(
            "miesc.cli.commands.doctor.fetch_openai_compatible_model_ids",
            new_callable=AsyncMock,
            return_value={"deepseek-v4-flash", "deepseek-v4-pro"},
        ) as mock_fetch,
    ):
        status, details = _deepseek_doctor_status()

    assert status == "[green]ready[/green]"
    assert details == "deepseek-v4-pro available"
    mock_fetch.assert_awaited_once_with(
        "https://api.deepseek.example",
        "test-key",
        timeout=3,
        provider_name="DeepSeek",
    )


def test_deepseek_doctor_status_model_missing():
    with (
        patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test-key"}, clear=True),
        patch(
            "miesc.cli.commands.doctor.fetch_openai_compatible_model_ids",
            new_callable=AsyncMock,
            return_value={"deepseek-v4-pro"},
        ),
    ):
        status, details = _deepseek_doctor_status()

    assert status == "[yellow]model missing[/yellow]"
    assert details == "deepseek-v4-flash not listed (1 models)"


def test_deepseek_doctor_status_unavailable():
    with (
        patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test-key"}, clear=True),
        patch(
            "miesc.cli.commands.doctor.fetch_openai_compatible_model_ids",
            new_callable=AsyncMock,
            return_value=set(),
        ),
    ):
        status, details = _deepseek_doctor_status()

    assert status == "[yellow]unavailable[/yellow]"
    assert details == "/v1/models unreachable or unauthorized"


def test_deepseek_doctor_status_inside_active_event_loop_does_not_fetch():
    async def run_test():
        with (
            patch.dict(os.environ, {"DEEPSEEK_API_KEY": "test-key"}, clear=True),
            patch(
                "miesc.cli.commands.doctor.fetch_openai_compatible_model_ids",
                new_callable=AsyncMock,
            ) as mock_fetch,
        ):
            status, details = _deepseek_doctor_status()

        assert status == "[yellow]configured[/yellow]"
        assert details == "deepseek-v4-flash configured; run outside active event loop"
        mock_fetch.assert_not_called()

    asyncio.run(run_test())


def test_doctor_shows_install_hints_for_missing_tools():
    """Missing tools with an install_cmd appear in the 'Install missing tools' section."""

    def fake_tool_status(tool):
        if tool == "wake":
            return {
                "available": False,
                "status": "not_installed",
                "install_cmd": "pip install eth-wake",
            }
        return {"available": True, "status": "available", "install_cmd": ""}

    fake_completed = SimpleNamespace(stdout="tool version 1.0\n", stderr="")
    with (
        patch("miesc.cli.commands.doctor.print_banner"),
        patch("miesc.cli.commands.doctor.info"),
        patch("miesc.cli.commands.doctor.subprocess.run", return_value=fake_completed),
        patch(
            "miesc.cli.commands.doctor._deepseek_doctor_status",
            return_value=("[green]ready[/green]", "ok"),
        ),
        patch(
            "miesc.cli.commands.doctor.AdapterLoader.check_tool_status",
            side_effect=fake_tool_status,
        ),
    ):
        result = CliRunner().invoke(doctor)

    assert result.exit_code == 0
    assert "Install missing tools" in result.output
    assert "pip install eth-wake" in result.output


def test_check_tool_status_includes_install_cmd():
    from miesc.cli.utils import AdapterLoader

    status = AdapterLoader.check_tool_status("mythril")
    assert "install_cmd" in status
    assert "mythril" in status["install_cmd"].lower()
