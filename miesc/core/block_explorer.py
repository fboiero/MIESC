"""Fetch a deployed contract's verified Solidity source through the Etherscan V2 API.

Opt-in only: called by `miesc audit address`, never by any other command, and it
needs the user's own API key (--api-key or ETHERSCAN_API_KEY), never bundled.
Etherscan V2 is one endpoint for every chain, selected by `chainid`, with one key
for all of them (https://docs.etherscan.io/v2-migration).

Solidity only: explorers verify Vyper less consistently and return it in other
payload shapes.
"""

import json
import os
import posixpath
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from miesc.core.chain_abstraction import ChainType

V2_BASE_URL = "https://api.etherscan.io/v2/api"
API_KEY_ENV = "ETHERSCAN_API_KEY"
ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")

# Build-configuration files are never taken from the payload: they are the deployer's, and the
# analyzers (crytic-compile/forge) honour a foundry.toml/hardhat.config found walking up from the
# contract, so a payload one with its own `out`/`cache_path` would steer the build to write and
# clean outside our temp dir. We always generate the build config ourselves; the payload supplies
# sources only. Matched case-insensitively by basename, at any depth.
_CONFIG_BASENAMES = frozenset(
    {"foundry.toml", "foundry.lock", "truffle-config.js", "truffle.js", "remappings.txt"}
)
_CONFIG_RE = re.compile(r"^(hardhat\.config\.[cm]?[jt]s|truffle-config\.[cm]?js)$", re.I)


def _is_config_file(rel_path: str) -> bool:
    base = posixpath.basename(rel_path).lower()
    return base in _CONFIG_BASENAMES or bool(_CONFIG_RE.match(base))


CHAIN_IDS: Dict[ChainType, int] = {
    ChainType.ETHEREUM: 1,
    ChainType.POLYGON: 137,
    ChainType.ARBITRUM: 42161,
    ChainType.OPTIMISM: 10,
    ChainType.BSC: 56,
    ChainType.AVALANCHE: 43114,
}


class BlockExplorerError(Exception):
    """The address, the key or the explorer call itself failed."""


class NotVerifiedError(BlockExplorerError):
    """The explorer has no verified source for this address."""


@dataclass
class FetchedContract:
    address: str
    chain: ChainType
    contract_name: str
    compiler_version: str
    files: Dict[str, str]  # relative path -> source
    remappings: List[str]  # the ones the contract was compiled with


def parse_source_payload(source_code: str, contract_name: str) -> Tuple[Dict[str, str], List[str]]:
    """Files and remappings of an Etherscan `SourceCode` field.

    A standard-json input comes wrapped in double braces `{{...}}` (some explorers
    send it with single braces); a single-file contract is plain Solidity.
    """
    stripped = source_code.strip()
    if stripped.startswith("{{") and stripped.endswith("}}"):
        stripped = stripped[1:-1]
    if stripped.startswith("{") and '"sources"' in stripped:
        payload = json.loads(stripped)
        files = {path: entry.get("content", "") for path, entry in payload["sources"].items()}
        return files, list(payload.get("settings", {}).get("remappings", []))
    return {f"{contract_name or 'Contract'}.sol": source_code}, []


def fetch_verified_source(
    address: str,
    chain: ChainType = ChainType.ETHEREUM,
    api_key: Optional[str] = None,
    timeout: int = 20,
) -> FetchedContract:
    """Verified source of `address` on `chain`.

    Raises NotVerifiedError when the explorer has none, BlockExplorerError for a bad
    address, a missing key, an unsupported chain or a failed call.
    """
    if not ADDRESS_RE.match(address):
        raise BlockExplorerError(f"Not an address: {address!r} (expected 0x + 40 hex digits).")
    if chain not in CHAIN_IDS:
        supported = ", ".join(c.value for c in CHAIN_IDS)
        raise BlockExplorerError(f"Unsupported chain {chain.value}. Supported: {supported}.")
    key = api_key or os.environ.get(API_KEY_ENV)
    if not key:
        raise BlockExplorerError(f"No API key. Pass --api-key or set {API_KEY_ENV}.")

    query = urllib.parse.urlencode(
        {
            "chainid": CHAIN_IDS[chain],
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
            "apikey": key,
        }
    )
    try:
        with urllib.request.urlopen(f"{V2_BASE_URL}?{query}", timeout=timeout) as resp:
            payload = json.load(resp)
    except (urllib.error.URLError, TimeoutError, ValueError) as e:
        # URLError's text never includes the query string, so the key does not leak.
        raise BlockExplorerError(f"Block explorer request failed: {e}") from e

    if payload.get("status") != "1":
        raise BlockExplorerError(str(payload.get("result") or "Unknown block explorer error"))
    # The explorer's payload is untrusted: a malformed `result`/`SourceCode` must surface as a
    # BlockExplorerError (clean exit), not as a raw traceback out of the CLI handler.
    try:
        results = payload.get("result")
        result = results[0] if isinstance(results, list) and results else {}
        if not isinstance(result, dict):
            raise BlockExplorerError(f"Unexpected explorer payload for {address}.")
        if not result.get("SourceCode"):
            raise NotVerifiedError(f"{address} has no verified source on {chain.value}.")
        if "vyper" in str(result.get("CompilerVersion", "")).lower():
            raise BlockExplorerError(f"{address} is a Vyper contract; only Solidity is supported.")
        name = result.get("ContractName") or "Contract"
        files, remappings = parse_source_payload(result["SourceCode"], name)
    except BlockExplorerError:
        raise
    except (ValueError, KeyError, TypeError, AttributeError, IndexError) as e:
        raise BlockExplorerError(f"Malformed source payload for {address}: {e}") from e
    return FetchedContract(
        address=address,
        chain=chain,
        contract_name=name,
        compiler_version=result.get("CompilerVersion", ""),
        files=files,
        remappings=remappings,
    )


def write_contract_to_dir(contract: FetchedContract, target_dir: Path) -> Path:
    """Write the files under `target_dir`, keeping their paths (imports depend on them).

    The paths come from the explorer. Absolute ones (the deployer's own checkout, e.g.
    `/Users/dev/repo/contracts/X.sol`) lose their common prefix, which keeps the
    relative imports between them and puts the project root, with its foundry.toml,
    close enough for the adapters to find it. A path that would still land outside
    `target_dir` (`../x`) is rejected before anything is written.
    A package path (`@openzeppelin/...`) goes under lib/ like a Foundry dependency, and
    a foundry.toml carries its remapping plus the contract's own, so the tools compile
    against these exact sources instead of installing the latest version of each one.
    """
    root = target_dir.resolve()
    remappings = list(contract.remappings)
    absolute = [p for p in contract.files if p.startswith("/")]
    prefix = posixpath.commonpath([posixpath.dirname(p) for p in absolute]) if absolute else "/"
    sources = {}
    for rel_path, content in contract.files.items():
        if _is_config_file(rel_path):
            continue  # never honour deployer build config; we generate our own below
        if rel_path.startswith("/"):
            rel_path = posixpath.relpath(rel_path, prefix)
        if rel_path.startswith("@"):
            scope = rel_path.split("/", 1)[0]
            rel_path = f"lib/{rel_path}"
            if not any(r.startswith(f"{scope}/") for r in remappings):
                remappings.append(f"{scope}/=lib/{scope}/")
        sources[rel_path] = content

    # The deployed contract can itself be a dependency of the deployer's repo (Aave's
    # PoolInstance is under lib/aave-v3-origin-private/), and the tools leave out what
    # is under lib/: that package moves to the root, and its remappings with it.
    defines = re.compile(rf"\bcontract\s+{re.escape(contract.contract_name)}\b")
    deployed = next((p for p, src in sources.items() if defines.search(src)), "")
    dirs = deployed.split("/")[:-1]
    if dirs[:-1] and "lib" in dirs[:-1]:
        last_lib = max(i for i, d in enumerate(dirs[:-1]) if d == "lib")
        package, moved = "/".join(dirs[: last_lib + 2]) + "/", dirs[last_lib + 1] + "/"
        sources = {
            moved + p[len(package) :] if p.startswith(package) else p: src
            for p, src in sources.items()
        }
        # `context:prefix=target`: the package can be the context or the target.
        remappings = [
            re.sub(rf"(^|=){re.escape(package)}", rf"\g<1>{moved}", r) for r in remappings
        ]

    files = {}
    for rel_path, content in sources.items():
        dest = (root / rel_path).resolve()
        if not dest.is_relative_to(root):
            raise BlockExplorerError(f"Refusing source path outside the target: {rel_path!r}")
        files[dest] = content
    for dest, content in files.items():
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")

    # We always write the build config ourselves (never the payload's), pinning out/cache inside
    # the temp dir so the analyzers' build and `forge clean` cannot touch anything outside it.
    if remappings:
        (root / "foundry.toml").write_text(
            '[profile.default]\nsrc = "."\nlibs = []\nout = "out"\ncache_path = "cache"\n'
            "remappings = " + json.dumps(remappings) + "\n",
            encoding="utf-8",
        )
    return root
