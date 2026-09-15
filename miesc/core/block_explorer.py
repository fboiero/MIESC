"""Fetch verified contract source via the Etherscan V2 unified API.

Opt-in only: never called unless the user explicitly runs `miesc audit address`.
Requires the user's own API key (env var or --api-key) - never bundled, same
policy as every other third-party network call in MIESC (see MEJORAS docs on
Solodit MCP / frontier LLM gating).

Etherscan retired its per-chain domains (api.polygonscan.com, api.arbiscan.io,
...) each with their own key, in favor of one API (api.etherscan.io/v2/api)
selecting the chain via `chainid`, with a single key valid across all of them
(https://docs.etherscan.io/v2-migration) - found by actually running this
against a real mainnet address, not by trusting the old per-chain-domain
convention other Etherscan-clone docs still describe.

Solidity only for now: block explorers verify Vyper far less consistently and
several return a different payload shape for it - out of scope for this first
pass, not silently mishandled.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional

import requests

from miesc.core.chain_abstraction import ChainType

V2_BASE_URL = "https://api.etherscan.io/v2/api"

CHAIN_IDS: Dict[ChainType, int] = {
    ChainType.ETHEREUM: 1,
    ChainType.POLYGON: 137,
    ChainType.ARBITRUM: 42161,
    ChainType.OPTIMISM: 10,
    ChainType.BSC: 56,
    ChainType.AVALANCHE: 43114,
}

API_KEY_ENV = "ETHERSCAN_API_KEY"


class NotVerifiedError(Exception):
    """The explorer has no verified source for this address."""


class BlockExplorerError(Exception):
    """The explorer API call itself failed (network, auth, rate limit, unsupported chain)."""


@dataclass
class FetchedContract:
    address: str
    chain: ChainType
    contract_name: str
    compiler_version: str
    files: Dict[str, str]  # relative path -> source text


def _resolve_api_key(api_key: Optional[str]) -> str:
    if api_key:
        return api_key
    key = os.environ.get(API_KEY_ENV)
    if not key:
        raise BlockExplorerError(f"No API key. Pass --api-key or set {API_KEY_ENV}.")
    return key


def _parse_source_payload(source_code: str, contract_name: str) -> Dict[str, str]:
    """Etherscan wraps multi-file (standard-json-input) sources in doubled
    braces `{{...}}`; a single-file contract's SourceCode is plain Solidity
    text with no wrapping at all."""
    stripped = source_code.strip()
    if stripped.startswith("{{") and stripped.endswith("}}"):
        parsed = json.loads(stripped[1:-1])
        sources = parsed.get("sources", {})
        return {path: entry.get("content", "") for path, entry in sources.items()}
    if stripped.startswith("{") and '"sources"' in stripped:
        # A couple of Etherscan-compatible clones skip the double-brace wrapper.
        parsed = json.loads(stripped)
        sources = parsed.get("sources", parsed)
        return {
            path: (entry.get("content", "") if isinstance(entry, dict) else entry)
            for path, entry in sources.items()
        }
    return {f"{contract_name or 'Contract'}.sol": source_code}


def fetch_verified_source(
    address: str,
    chain: ChainType = ChainType.ETHEREUM,
    api_key: Optional[str] = None,
    timeout: int = 20,
) -> FetchedContract:
    """Fetch an address's verified Solidity source via Etherscan's V2
    `getsourcecode` API. Raises NotVerifiedError if the explorer has no
    verified source, BlockExplorerError for any other failure (bad key,
    rate limit, unsupported chain, network error)."""
    if chain not in CHAIN_IDS:
        supported = ", ".join(c.value for c in CHAIN_IDS)
        raise BlockExplorerError(
            f"No chain id configured for {chain.value}. Supported: {supported}."
        )

    resolved_key = _resolve_api_key(api_key)
    try:
        resp = requests.get(
            V2_BASE_URL,
            params={
                "chainid": CHAIN_IDS[chain],
                "module": "contract",
                "action": "getsourcecode",
                "address": address,
                "apikey": resolved_key,
            },
            timeout=timeout,
        )
        resp.raise_for_status()
        payload = resp.json()
    except requests.RequestException as e:
        raise BlockExplorerError(f"Block explorer request failed: {e}") from e

    if payload.get("status") != "1":
        raise BlockExplorerError(payload.get("result", "Unknown block explorer error"))

    result = (payload.get("result") or [{}])[0]
    source_code = result.get("SourceCode", "")
    if not source_code:
        raise NotVerifiedError(
            f"{address} on {chain.value} has no verified source on this explorer."
        )

    contract_name = result.get("ContractName", "Contract")
    files = _parse_source_payload(source_code, contract_name)
    return FetchedContract(
        address=address,
        chain=chain,
        contract_name=contract_name,
        compiler_version=result.get("CompilerVersion", ""),
        files=files,
    )


def write_contract_to_dir(contract: FetchedContract, target_dir: Path) -> Path:
    """Write a fetched contract's files to disk, preserving their relative
    paths (import resolution for a multi-file contract depends on it)."""
    target_dir.mkdir(parents=True, exist_ok=True)
    for rel_path, content in contract.files.items():
        # Etherscan multi-file entries sometimes carry a leading "./" or
        # absolute-looking path — normalize so it stays inside target_dir.
        safe_rel = Path(rel_path.lstrip("/")).as_posix()
        dest = target_dir / safe_rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")
    return target_dir
