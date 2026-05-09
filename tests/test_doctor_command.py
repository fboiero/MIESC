from types import SimpleNamespace
from unittest.mock import patch

from click.testing import CliRunner

from miesc.cli.commands.doctor import doctor
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
