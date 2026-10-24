"""miesc audit address: verified source from Etherscan V2, written to disk, then audit deep.
Every HTTP call is mocked; nothing here reaches the network."""

import io
import json
import urllib.parse
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from miesc.agents.deep_audit_agent import DeepAuditAgent
from miesc.cli.commands.audit import audit
from miesc.core.block_explorer import (
    BlockExplorerError,
    FetchedContract,
    NotVerifiedError,
    fetch_verified_source,
    parse_source_payload,
    write_contract_to_dir,
)
from miesc.core.chain_abstraction import ChainType

ADDRESS = "0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984"

STANDARD_JSON = {
    "language": "Solidity",
    "sources": {
        "src/Token.sol": {"content": 'import "@openzeppelin/contracts/ERC20.sol";\ncontract T {}'},
        "lib/openzeppelin-contracts/contracts/ERC20.sol": {"content": "contract ERC20 {}"},
    },
    "settings": {"remappings": ["@openzeppelin/=lib/openzeppelin-contracts/"]},
}


def _explorer(result=None, status="1", message=None):
    """Patch urlopen with one Etherscan reply; returns the mock to inspect the request."""
    body = {"status": status, "result": message if message is not None else [result]}
    return patch("urllib.request.urlopen", return_value=io.BytesIO(json.dumps(body).encode()))


def _contract(files, remappings=()):
    return FetchedContract(ADDRESS, ChainType.ETHEREUM, "T", "v0.8.20", files, list(remappings))


def test_plain_and_standard_json_payloads():
    assert parse_source_payload("contract T {}", "T") == ({"T.sol": "contract T {}"}, [])

    wrapped = "{" + json.dumps(STANDARD_JSON) + "}"
    files, remappings = parse_source_payload(wrapped, "T")
    assert sorted(files) == ["lib/openzeppelin-contracts/contracts/ERC20.sol", "src/Token.sol"]
    assert remappings == ["@openzeppelin/=lib/openzeppelin-contracts/"]
    assert parse_source_payload(json.dumps(STANDARD_JSON), "T")[0] == files  # no double braces


def test_fetch_sends_chain_id_and_key(monkeypatch):
    monkeypatch.delenv("ETHERSCAN_API_KEY", raising=False)
    reply = {"SourceCode": "contract T {}", "ContractName": "T", "CompilerVersion": "v0.8.20"}
    with _explorer(reply) as urlopen:
        contract = fetch_verified_source(ADDRESS, ChainType.ARBITRUM, api_key="k")

    query = urllib.parse.parse_qs(urllib.parse.urlparse(urlopen.call_args.args[0]).query)
    assert query["chainid"] == ["42161"] and query["apikey"] == ["k"]
    assert query["address"] == [ADDRESS]
    assert contract.files == {"T.sol": "contract T {}"}


@pytest.mark.parametrize(
    "address, kwargs, error",
    [
        ("0x123", {"api_key": "k"}, "Not an address"),
        (ADDRESS, {}, "ETHERSCAN_API_KEY"),
        (ADDRESS, {"api_key": "k", "chain": ChainType.SOLANA}, "Unsupported chain"),
    ],
)
def test_fetch_rejects_bad_input_before_any_request(address, kwargs, error, monkeypatch):
    monkeypatch.delenv("ETHERSCAN_API_KEY", raising=False)
    with patch("urllib.request.urlopen") as urlopen, pytest.raises(BlockExplorerError, match=error):
        fetch_verified_source(address, **kwargs)
    urlopen.assert_not_called()


def test_fetch_reports_explorer_errors_and_unverified_contracts():
    with (
        _explorer(status="0", message="Invalid API Key"),
        pytest.raises(BlockExplorerError, match="Invalid API Key"),
    ):
        fetch_verified_source(ADDRESS, api_key="k")
    with _explorer({"SourceCode": ""}), pytest.raises(NotVerifiedError):
        fetch_verified_source(ADDRESS, api_key="k")
    with (
        _explorer({"SourceCode": "x", "CompilerVersion": "vyper:0.3.10"}),
        pytest.raises(BlockExplorerError, match="Vyper"),
    ):
        fetch_verified_source(ADDRESS, api_key="k")


def test_written_sources_compile_against_their_own_dependencies(tmp_path):
    files, remappings = parse_source_payload(json.dumps(STANDARD_JSON), "T")
    root = write_contract_to_dir(
        _contract({**files, "@chainlink/A.sol": "x"}, remappings), tmp_path
    )

    assert (root / "src/Token.sol").exists()
    assert (root / "lib/openzeppelin-contracts/contracts/ERC20.sol").exists()
    assert (root / "lib/@chainlink/A.sol").exists()
    toml = (root / "foundry.toml").read_text()
    assert '"@openzeppelin/=lib/openzeppelin-contracts/"' in toml
    assert '"@chainlink/=lib/@chainlink/"' in toml


def test_deployer_absolute_paths_lose_their_common_prefix(tmp_path):
    repo = "/Users/dev/Repositories/org/stablecoin"
    files = {
        f"{repo}/contracts/v1/Token.sol": 'import "../util/Lib.sol";',
        f"{repo}/contracts/util/Lib.sol": "library Lib {}",
        "@openzeppelin/contracts/math/SafeMath.sol": "library SafeMath {}",
    }
    root = write_contract_to_dir(_contract(files), tmp_path)

    written = sorted(p.relative_to(root).as_posix() for p in root.rglob("*.sol"))
    assert written == [
        "lib/@openzeppelin/contracts/math/SafeMath.sol",
        "util/Lib.sol",  # still ../util/Lib.sol from v1/Token.sol
        "v1/Token.sol",
    ]
    assert (root / "foundry.toml").exists()


def test_contract_deployed_from_a_dependency_moves_to_the_root(tmp_path):
    # The tools leave out findings under lib/, where the deployer's repo keeps this one.
    files = {
        "lib/pool-core/src/instances/PoolInstance.sol": "contract PoolInstance is Pool {}",
        "lib/pool-core/lib/oz/Address.sol": "library Address {}",
        "lib/helpers/src/H.sol": "library H {}",
    }
    remappings = ["oz/=lib/pool-core/lib/oz/", "lib/pool-core/:h/=lib/helpers/src/"]
    contract = FetchedContract(ADDRESS, ChainType.ETHEREUM, "PoolInstance", "", files, remappings)

    root = write_contract_to_dir(contract, tmp_path)

    written = sorted(p.relative_to(root).as_posix() for p in root.rglob("*.sol"))
    assert written == [
        "lib/helpers/src/H.sol",
        "pool-core/lib/oz/Address.sol",
        "pool-core/src/instances/PoolInstance.sol",
    ]
    toml = (root / "foundry.toml").read_text()
    assert '"oz/=pool-core/lib/oz/"' in toml and '"pool-core/:h/=lib/helpers/src/"' in toml


def test_single_file_contract_gets_no_foundry_toml(tmp_path):
    root = write_contract_to_dir(_contract({"T.sol": "contract T {}"}), tmp_path)
    assert sorted(p.name for p in root.iterdir()) == ["T.sol"]


def test_source_path_escaping_the_target_writes_nothing(tmp_path):
    target = tmp_path / "out"
    contract = _contract({"ok.sol": "x", "../../evil.sol": "x"})
    with pytest.raises(BlockExplorerError, match="outside the target"):
        write_contract_to_dir(contract, target)
    assert not (tmp_path / "evil.sol").exists() and not (target / "ok.sol").exists()

    root = write_contract_to_dir(_contract({"/abs/A.sol": "x"}), target)
    assert (root / "A.sol").exists()  # an absolute path stays inside


def test_cli_fetches_then_runs_audit_deep_on_the_sources():
    seen = {}

    def analyze(self, contract_path, **kwargs):
        root = Path(contract_path)
        seen["files"] = sorted(p.relative_to(root).as_posix() for p in root.rglob("*.sol"))
        seen["enable_llm"] = self.config.enable_llm
        return {"findings": [], "summary": {}}

    reply = {"SourceCode": "{" + json.dumps(STANDARD_JSON) + "}", "ContractName": "T"}
    with _explorer(reply), patch.object(DeepAuditAgent, "analyze", analyze):
        result = CliRunner().invoke(audit, ["address", ADDRESS, "--api-key", "k", "--no-llm"])

    assert result.exit_code == 0, result.output
    assert seen == {
        "files": ["lib/openzeppelin-contracts/contracts/ERC20.sol", "src/Token.sol"],
        "enable_llm": False,
    }


def test_cli_exits_1_on_explorer_error():
    with _explorer(status="0", message="Max rate limit reached"):
        result = CliRunner().invoke(audit, ["address", ADDRESS, "--api-key", "k"])
    assert result.exit_code == 1
    assert "Max rate limit reached" in result.output
