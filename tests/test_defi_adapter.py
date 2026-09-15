"""
Tests for DeFiAdapter (src/adapters/defi_adapter.py).

Pure wrapper around the in-tree DeFiDetectorEngine (regex detection of flash-loan /
oracle-manipulation / MEV patterns). No external deps; driven with a triggering
contract plus the file/source/exception paths.
"""

import sys

from miesc.adapters.defi_adapter import DeFiAdapter
from miesc.core.tool_protocol import ToolStatus

# Triggers flash-loan (executeOperation/flashLoan) + oracle (getReserves) detectors.
DEFI = (
    "pragma solidity ^0.8.0;\n"
    "interface IUniswapV2Pair { function getReserves() external view returns (uint112,uint112,uint32); }\n"
    "contract Pool {\n"
    "  address pair;\n"
    "  function executeOperation(address asset, uint256 amount) external returns (bool) {\n"
    "    (uint112 r0, uint112 r1,) = IUniswapV2Pair(pair).getReserves();\n"
    "    return true;\n"
    "  }\n"
    "  function flashLoan(uint256 amt) external {}\n"
    "}\n"
)


def _a():
    return DeFiAdapter()


# --------------------------------------------------------------------------- #
# availability / metadata / layer info
# --------------------------------------------------------------------------- #
def test_is_available():
    assert _a().is_available() == ToolStatus.AVAILABLE


def test_is_available_not_installed(monkeypatch):
    monkeypatch.setitem(sys.modules, "miesc.detectors.defi_detectors", None)
    assert _a().is_available() == ToolStatus.NOT_INSTALLED


def test_metadata_and_layer_info():
    a = _a()
    assert a.get_metadata().name == a.name
    info = a.get_layer_info()
    assert isinstance(info, dict)


# --------------------------------------------------------------------------- #
# analyze (file)
# --------------------------------------------------------------------------- #
def test_analyze_file_not_found():
    out = _a().analyze("/nonexistent/C.sol")
    assert out["success"] is False
    assert "not found" in out["error"]


def test_analyze_triggers_findings(tmp_path):
    a = _a()
    sol = tmp_path / "Pool.sol"
    sol.write_text(DEFI)
    out = a.analyze(str(sol))
    assert out["success"] is True
    assert out["tool"] == a.name
    assert out["findings"]
    f = out["findings"][0]
    assert f["id"].startswith("DEFI-")
    assert f["swc_id"]
    assert f["location"]["file"] == str(sol)


def test_analyze_handles_engine_exception(tmp_path, monkeypatch):
    a = _a()
    sol = tmp_path / "C.sol"
    sol.write_text("contract C {}")
    monkeypatch.setattr(
        a.engine,
        "analyze_file",
        lambda *args, **k: (_ for _ in ()).throw(RuntimeError("defi boom")),
    )
    out = a.analyze(str(sol))
    assert out["success"] is False
    assert "defi boom" in out["error"]


# --------------------------------------------------------------------------- #
# analyze_source
# --------------------------------------------------------------------------- #
def test_analyze_source_triggers_findings():
    out = _a().analyze_source(DEFI)
    assert out["success"] is True
    assert out["findings"]


def test_analyze_source_handles_exception(monkeypatch):
    a = _a()
    monkeypatch.setattr(
        a.engine, "analyze", lambda *args, **k: (_ for _ in ()).throw(ValueError("src boom"))
    )
    out = a.analyze_source("contract C {}")
    assert out["success"] is False
    assert "src boom" in out["error"]


def test_analyze_source_clean_contract():
    out = _a().analyze_source("contract Empty { uint x; }")
    assert out["success"] is True
    assert isinstance(out["findings"], list)


# --------------------------------------------------------------------------- #
# engine detector branches (exercised through the adapter)
# --------------------------------------------------------------------------- #
def _cats(out):
    return " ".join(f["title"] + f["description"] for f in out["findings"]).lower()


def test_chainlink_without_staleness_check():
    src = (
        "contract Oracle {\n"
        "  AggregatorV3Interface feed;\n"
        "  function getPrice() public returns (int) {\n"
        "    (, int price, , ,) = feed.latestRoundData();\n"
        "    return price;\n"
        "  }\n"
        "}\n"
    )
    out = _a().analyze_source(src)
    assert out["success"] is True
    assert "staleness" in _cats(out)  # missing staleness + deviation checks flagged


def test_zero_slippage_and_missing_deadline():
    src = (
        "contract Dex {\n"
        "  function doSwap() public {\n"
        "    uint amountOutMin = 0;\n"
        "    router.swapExactTokensForTokens(amountOutMin);\n"
        "  }\n"
        "}\n"
    )
    out = _a().analyze_source(src)
    assert out["success"] is True
    text = _cats(out)
    assert "slippage" in text or "deadline" in text


def test_mev_liquidation_pattern():
    src = (
        "contract Lending {\n" "  function liquidate(address user) public { _seize(user); }\n" "}\n"
    )
    out = _a().analyze_source(src)
    assert out["success"] is True
    assert "mev" in _cats(out) or "liquidation" in _cats(out)


def test_price_calc_reserve_ratio():
    src = (
        "contract Amm {\n"
        "  function price() public view returns (uint) {\n"
        "    return reserve0 / reserve1;\n"
        "  }\n"
        "}\n"
    )
    out = _a().analyze_source(src)
    assert out["success"] is True
    assert out["findings"]  # reserve-ratio price manipulation flagged


# --------------------------------------------------------------------------- #
# MEJORAS3.md item 2: rounding (divide-before-multiply library chains) and
# fee-on-transfer (missing balance-before/after) detectors.
# --------------------------------------------------------------------------- #
def test_divide_before_multiply_library_chain_flagged():
    # Real pattern from y2k-finance/src/Vault.sol (M-04, ground truth
    # category "rounding"): a solmate-style divWadDown() chained straight
    # into mulDivDown() truncates in the division before the multiply runs.
    src = (
        "contract Vault {\n"
        "  function withdraw(uint256 amount, uint256 total) public returns (uint256) {\n"
        "    return amount.divWadDown(total).mulDivDown(1e18, 1);\n"
        "  }\n"
        "}\n"
    )
    out = _a().analyze_source(src)
    assert out["success"] is True
    findings = [f for f in out["findings"] if f["category"] == "rounding"]
    assert findings
    assert findings[0]["type"] == "rounding"


def test_single_muldivdown_call_not_flagged_as_rounding():
    # mulDivDown(a, b, c) alone is the *correct* safe pattern (multiply
    # before dividing) — must not be flagged.
    src = (
        "contract Vault {\n"
        "  function withdraw(uint256 amount, uint256 total) public returns (uint256) {\n"
        "    return amount.mulDivDown(1e18, total);\n"
        "  }\n"
        "}\n"
    )
    out = _a().analyze_source(src)
    assert not [f for f in out["findings"] if f["category"] == "rounding"]


def test_fee_on_transfer_missing_balance_check_flagged():
    # Real pattern from y2k-finance/src/SemiFungibleVault.sol (M-02):
    # shares are computed from the requested amount before transferFrom
    # runs, never validated against the actual balance received.
    src = (
        "contract Vault {\n"
        "  function deposit(uint256 assets) public returns (uint256 shares) {\n"
        "    shares = previewDeposit(assets);\n"
        "    asset.safeTransferFrom(msg.sender, address(this), assets);\n"
        "    _mint(msg.sender, shares);\n"
        "  }\n"
        "}\n"
    )
    out = _a().analyze_source(src)
    findings = [f for f in out["findings"] if f["category"] == "fee_on_transfer"]
    assert findings
    assert findings[0]["type"] == "fee_on_transfer"


def test_fee_on_transfer_not_flagged_when_balance_checked():
    src = (
        "contract Vault {\n"
        "  function deposit(uint256 assets) public returns (uint256 shares) {\n"
        "    uint256 before = token.balanceOf(address(this));\n"
        "    asset.safeTransferFrom(msg.sender, address(this), assets);\n"
        "    shares = token.balanceOf(address(this)) - before;\n"
        "    _mint(msg.sender, shares);\n"
        "  }\n"
        "}\n"
    )
    out = _a().analyze_source(src)
    assert not [f for f in out["findings"] if f["category"] == "fee_on_transfer"]


def test_fee_on_transfer_ignores_nft_safe_transfer_from():
    # ERC721/ERC1155 safeTransferFrom moves a tokenId, not an amount —
    # fee-on-transfer is an ERC20-only concept.
    src = (
        "contract Auction {\n"
        "  function settle(address token, address winner, uint256 tokenId) public {\n"
        "    IERC721(token).safeTransferFrom(address(this), winner, tokenId);\n"
        "  }\n"
        "}\n"
    )
    out = _a().analyze_source(src)
    assert not [f for f in out["findings"] if f["category"] == "fee_on_transfer"]


def test_all_findings_carry_a_type_field_matching_category():
    # Regression: DeFiAdapter used to omit "type", so evaluate.py's
    # _normalize_category (which reads f.get("type") first) fell back to
    # fuzzy title/description keyword matching — which could collide with
    # an unrelated category's alias (e.g. a "rounding" finding whose title
    # mentions "divide-before-multiply" was misclassified as "arithmetic",
    # since that's an existing alias for a *different* canonical category).
    out = _a().analyze_source(DEFI)
    assert out["findings"]
    for f in out["findings"]:
        assert f["type"] == f["category"]
