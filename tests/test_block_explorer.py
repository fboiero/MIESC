"""Tests for miesc.core.block_explorer - fetching verified source from
Etherscan-compatible block explorer APIs. All network calls are mocked;
nothing here makes a real HTTP request."""

import json
from unittest.mock import MagicMock, patch

import pytest

from miesc.core.block_explorer import (
    BlockExplorerError,
    NotVerifiedError,
    _parse_source_payload,
    _resolve_api_key,
    fetch_verified_source,
    write_contract_to_dir,
)
from miesc.core.chain_abstraction import ChainType


def _etherscan_response(result: dict, status: str = "1") -> MagicMock:
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.json = MagicMock(return_value={"status": status, "result": [result]})
    return resp


class TestResolveApiKey:
    def test_explicit_key_wins(self, monkeypatch):
        monkeypatch.setenv("ETHERSCAN_API_KEY", "env-key")
        assert _resolve_api_key("explicit-key") == "explicit-key"

    def test_falls_back_to_env_var(self, monkeypatch):
        monkeypatch.setenv("ETHERSCAN_API_KEY", "env-key")
        assert _resolve_api_key(None) == "env-key"

    def test_raises_when_neither_present(self, monkeypatch):
        monkeypatch.delenv("ETHERSCAN_API_KEY", raising=False)
        with pytest.raises(BlockExplorerError, match="ETHERSCAN_API_KEY"):
            _resolve_api_key(None)


class TestParseSourcePayload:
    def test_single_file_plain_text(self):
        files = _parse_source_payload("contract Foo {}", "Foo")
        assert files == {"Foo.sol": "contract Foo {}"}

    def test_multi_file_double_brace_wrapped(self):
        inner = {
            "sources": {
                "src/Foo.sol": {"content": "contract Foo {}"},
                "src/IFoo.sol": {"content": "interface IFoo {}"},
            }
        }
        wrapped = "{" + json.dumps(inner) + "}"
        files = _parse_source_payload(wrapped, "Foo")
        assert files == {"src/Foo.sol": "contract Foo {}", "src/IFoo.sol": "interface IFoo {}"}

    def test_multi_file_without_double_brace(self):
        payload = json.dumps({"sources": {"Foo.sol": {"content": "contract Foo {}"}}})
        files = _parse_source_payload(payload, "Foo")
        assert files == {"Foo.sol": "contract Foo {}"}


class TestFetchVerifiedSource:
    def test_unsupported_chain_raises(self):
        with pytest.raises(BlockExplorerError, match="No chain id configured"):
            fetch_verified_source("0xabc", chain=ChainType.SOLANA, api_key="k")

    @patch("miesc.core.block_explorer.requests.get")
    def test_not_verified_raises(self, mock_get):
        mock_get.return_value = _etherscan_response({"SourceCode": "", "ContractName": ""})
        with pytest.raises(NotVerifiedError):
            fetch_verified_source("0xabc", chain=ChainType.ETHEREUM, api_key="k")

    @patch("miesc.core.block_explorer.requests.get")
    def test_api_error_status_raises(self, mock_get):
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.json = MagicMock(return_value={"status": "0", "result": "Invalid API Key"})
        mock_get.return_value = resp
        with pytest.raises(BlockExplorerError, match="Invalid API Key"):
            fetch_verified_source("0xabc", chain=ChainType.ETHEREUM, api_key="bad-key")

    @patch("miesc.core.block_explorer.requests.get")
    def test_verified_single_file_contract(self, mock_get):
        mock_get.return_value = _etherscan_response(
            {
                "SourceCode": "contract Vault {}",
                "ContractName": "Vault",
                "CompilerVersion": "v0.8.20+commit.a1b79de6",
            }
        )
        contract = fetch_verified_source("0xabc", chain=ChainType.ETHEREUM, api_key="k")
        assert contract.contract_name == "Vault"
        assert contract.compiler_version.startswith("v0.8.20")
        assert contract.files == {"Vault.sol": "contract Vault {}"}

    @patch("miesc.core.block_explorer.requests.get")
    def test_sends_expected_query_params(self, mock_get):
        mock_get.return_value = _etherscan_response(
            {"SourceCode": "contract A {}", "ContractName": "A"}
        )
        fetch_verified_source("0xabc", chain=ChainType.ETHEREUM, api_key="k")
        _, kwargs = mock_get.call_args
        assert kwargs["params"] == {
            "chainid": 1,
            "module": "contract",
            "action": "getsourcecode",
            "address": "0xabc",
            "apikey": "k",
        }


class TestWriteContractToDir:
    def test_writes_single_file(self, tmp_path):
        from miesc.core.block_explorer import FetchedContract

        contract = FetchedContract(
            address="0xabc",
            chain=ChainType.ETHEREUM,
            contract_name="Vault",
            compiler_version="v0.8.20",
            files={"Vault.sol": "contract Vault {}"},
        )
        out = write_contract_to_dir(contract, tmp_path / "fetched")
        assert (out / "Vault.sol").read_text() == "contract Vault {}"

    def test_preserves_multi_file_directory_structure(self, tmp_path):
        from miesc.core.block_explorer import FetchedContract

        contract = FetchedContract(
            address="0xabc",
            chain=ChainType.ETHEREUM,
            contract_name="Vault",
            compiler_version="v0.8.20",
            files={
                "src/Vault.sol": "contract Vault {}",
                "src/interfaces/IVault.sol": "interface IVault {}",
            },
        )
        out = write_contract_to_dir(contract, tmp_path / "fetched")
        assert (out / "src" / "Vault.sol").exists()
        assert (out / "src" / "interfaces" / "IVault.sol").exists()

    def test_normalizes_leading_slash(self, tmp_path):
        from miesc.core.block_explorer import FetchedContract

        contract = FetchedContract(
            address="0xabc",
            chain=ChainType.ETHEREUM,
            contract_name="Vault",
            compiler_version="",
            files={"/Vault.sol": "contract Vault {}"},
        )
        out = write_contract_to_dir(contract, tmp_path / "fetched")
        assert (out / "Vault.sol").exists()
