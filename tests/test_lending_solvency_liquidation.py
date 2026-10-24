"""
Unit tests for the deterministic lending solvency/liquidation market-model miner (SDD Phase 1).

Covers accounting-field categorization, market-parameter and price-dependency detection, the
lending precision gate, source anchoring, the parser round-trip, and the advisory contract.
"""

from __future__ import annotations

from pathlib import Path

from miesc.llm.lending_solvency_liquidation import (
    LendingMarket,
    LendingSolvencyLiquidationPlan,
    mine_lending_solvency_liquidation,
    parse_lending_solvency_plans,
)

LENDING = """
contract Lending {
    mapping(address => uint256) public collateralBalance;
    mapping(address => uint256) public debt;
    uint256 public totalReserves;
    uint256 public borrowIndex;
    uint256 public collateralFactor;
    uint256 public liquidationThreshold;
    uint256 public closeFactor;
    uint256 public liquidationBonus;
    IPriceOracle public oracle;

    function supply(uint256 amt) external onlyOwner { }
    function borrow(uint256 amt) external { uint256 p = oracle.getPrice(); }
    function repay(uint256 amt) external { }
    function accrueInterest() public { }
    function liquidate(address user) external { }
}
"""


def _plan(src, path=None):
    plans = mine_lending_solvency_liquidation(src, path)
    return plans[0] if plans else None


class TestMarketModel:
    def test_accounting_fields(self):
        p = _plan(LENDING)
        assert {"collateral", "debt", "reserves", "indexes"} <= set(p.accounting_fields)

    def test_solvency_functions(self):
        p = _plan(LENDING)
        assert {"supply", "borrow", "repay", "accrueInterest", "liquidate"} <= set(
            p.solvency_functions
        )

    def test_market_parameters(self):
        m = _plan(LENDING).markets[0]
        assert m.collateral_factor and "collateralfactor" in m.collateral_factor.lower()
        assert m.liquidation_threshold and "liquidationthreshold" in m.liquidation_threshold.lower()
        assert m.close_factor and "closefactor" in m.close_factor.lower()
        assert m.liquidation_bonus and "liquidationbonus" in m.liquidation_bonus.lower()

    def test_price_dependency(self):
        p = _plan(LENDING)
        assert any("oracle" in d or "getprice" in d for d in p.price_dependencies)

    def test_configuration_actors(self):
        # supply() is onlyOwner -> owner is a configuration actor
        assert "owner" in _plan(LENDING).configuration_actors


class TestPrecisionGate:
    def test_non_lending_contract_is_skipped(self):
        # has a function that matches 'supply'? no. no accounting fields -> empty
        src = "contract Token { function transfer(address to, uint256 v) public {} }"
        assert mine_lending_solvency_liquidation(src) == []

    def test_accounting_without_solvency_fn_skipped(self):
        src = "contract C { uint256 public collateral; function readOnly() public view {} }"
        assert mine_lending_solvency_liquidation(src) == []

    def test_empty_source(self):
        assert mine_lending_solvency_liquidation("") == []


class TestAdvisoryAndAnchors:
    def test_returns_plans_not_findings(self):
        p = _plan(LENDING)
        assert isinstance(p, LendingSolvencyLiquidationPlan)
        assert not hasattr(p, "severity")
        d = p.to_dict()
        assert d["promotion"]["state"] == "hypothesis"
        assert d["metadata"]["capability"] == "lending_solvency_liquidation_hardening"
        assert "market_model" in d

    def test_anchor_uses_file_name(self):
        p = _plan(LENDING, Path("/x/Lending.sol"))
        assert p.markets[0].source_anchors[0].startswith("Lending.sol:")


class TestParserRoundTrip:
    def test_round_trip(self):
        plan = _plan(LENDING)
        parsed = parse_lending_solvency_plans(
            {"lending_solvency_liquidation_plans": [plan.to_dict()]}
        )
        assert len(parsed) == 1
        assert set(parsed[0].accounting_fields) == set(plan.accounting_fields)
        assert parsed[0].markets[0].collateral_factor == plan.markets[0].collateral_factor

    def test_parser_rejects_garbage(self):
        assert parse_lending_solvency_plans("nope") == []
        assert parse_lending_solvency_plans(5) == []
        assert parse_lending_solvency_plans({"plans": "x"}) == []

    def test_parser_skips_empty_objective(self):
        good = LendingSolvencyLiquidationPlan(
            id="p", objective="o", markets=[LendingMarket(id="m")]
        )
        parsed = parse_lending_solvency_plans({"plans": [good.to_dict(), {"objective": ""}]})
        assert len(parsed) == 1


ERC4626_VAULT = """
contract Vault is ERC20 {
    IERC20 public asset;
    function deposit(uint256 assets, address receiver) external returns (uint256 shares) { shares = assets; }
    function withdraw(uint256 assets, address receiver, address owner) external returns (uint256 shares) { }
    function totalAssets() public view returns (uint256) { return asset.balanceOf(address(this)); }
}
"""

TOKEN_WITH_RESERVE_STRING = """
contract Token {
    uint256 private _supply;
    mapping(address => uint256) private b;
    function totalSupply() external view returns (uint256) { return _supply; }
    function transfer(address to, uint256 v) external { require(b[msg.sender] >= v, "reserve too low"); b[to] += v; }
}
"""

STAKING_POOL = """
contract Staking {
    mapping(address => uint256) public shares;
    uint256 public totalShares;
    function deposit(uint256 amt) external { shares[msg.sender] += amt; totalShares += amt; }
    function withdraw(uint256 amt) external { shares[msg.sender] -= amt; totalShares -= amt; }
}
"""

COMPOUND_LIKE = """
contract CToken {
    uint public borrowIndex;
    uint public totalBorrows;
    uint public totalReserves;
    uint public reserveFactorMantissa;
    PriceOracle public oracle;
    uint public collateralFactorMantissa;
    function accrueInterest() public returns (uint) { }
    function borrow(uint amount) external { }
    function repayBorrow(uint amount) external { }
    function liquidateBorrow(address borrower, uint repayAmount, address cTokenCollateral) external {
        uint price = oracle.getUnderlyingPrice(cTokenCollateral);
    }
}
"""


class TestGateIsDebtAndCollateral:
    def test_erc4626_vault_is_not_a_lending_market(self):
        assert mine_lending_solvency_liquidation(ERC4626_VAULT, Path("Vault.sol")) == []

    def test_token_with_reserve_in_a_string_is_not_a_lending_market(self):
        assert mine_lending_solvency_liquidation(TOKEN_WITH_RESERVE_STRING, Path("T.sol")) == []

    def test_staking_pool_is_not_a_lending_market(self):
        assert mine_lending_solvency_liquidation(STAKING_POOL, Path("S.sol")) == []

    def test_compound_like_market_still_passes_with_its_parameters(self):
        plans = mine_lending_solvency_liquidation(COMPOUND_LIKE, Path("CToken.sol"))
        assert len(plans) == 1
        d = plans[0].to_dict()["market_model"]
        assert {"borrow", "repayBorrow", "liquidateBorrow", "accrueInterest"} <= set(
            d["solvency_functions"]
        )
        assert {"collateral", "debt", "reserves", "indexes"} <= set(d["accounting_fields"])
        m = d["markets"][0]
        assert m["collateral_factor"] == "collateralFactorMantissa"
        assert m["interest_index"] == "borrowIndex"
        assert m["price_source"] == "getUnderlyingPrice"

    def test_anchor_points_at_a_declaration_not_line_one(self):
        plans = mine_lending_solvency_liquidation(COMPOUND_LIKE, Path("CToken.sol"))
        anchor = plans[0].to_dict()["market_model"]["markets"][0]["source_anchors"][0]
        line = int(anchor.rsplit(":", 1)[1])
        # borrowIndex is declared on line 3 of the fixture; line 1 is the blank before `contract`
        assert line == 3
