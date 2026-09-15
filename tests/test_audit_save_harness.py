import json
from types import SimpleNamespace

import pytest
from click import ClickException

from miesc.cli.commands.audit import _save_foundry_harness


def test_save_foundry_harness_exports_replayable_files_without_overwrite(tmp_path):
    contract = tmp_path / "src" / "Vault.sol"
    contract.parent.mkdir()
    contract.write_text("contract Vault {}\n", encoding="utf-8")
    campaign = {
        "status": "counterexample",
        "compiled": True,
        "tests_run": 1,
        "tests_failed": 1,
        "calls_executed": 5,
        "seed": "0x1234",
        "counterexamples": [["deposit", "withdraw"]],
        "coverage": {"lines": 100},
        "harness": 'import {Vault} from "@repo/src/Vault.sol";\ncontract Test {}\n',
    }
    result = SimpleNamespace(raw_findings=[{"foundry_campaign": campaign}])
    destination = tmp_path / "test" / "generated"

    harness_path, metadata_path = _save_foundry_harness(result, str(contract), destination)

    assert 'from "../../src/Vault.sol"' in harness_path.read_text(encoding="utf-8")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert metadata["seed"] == "0x1234"
    assert metadata["counterexamples"] == [["deposit", "withdraw"]]
    assert metadata["contract"] == "../../src/Vault.sol"
    assert metadata["harness"] == "MIESCGeneratedInvariant.t.sol"
    assert "@repo" not in metadata_path.read_text(encoding="utf-8")
    with pytest.raises(ClickException, match="Refusing to overwrite"):
        _save_foundry_harness(result, str(contract), destination)
