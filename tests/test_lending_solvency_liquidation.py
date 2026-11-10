"""
Unit tests for the deterministic lending solvency/liquidation market-model miner (SDD Phase 1).

Covers accounting-field categorization, market-parameter and price-dependency detection, the
lending precision gate, source anchoring, the parser round-trip, and the advisory contract.
"""

from __future__ import annotations

from pathlib import Path

from miesc.llm.lending_solvency_liquidation import (
    _HYPOTHESIS_CATEGORIES,
    LendingMarket,
    LendingSolvencyLiquidationPlan,
    SolvencyHypothesis,
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


# --------------------------------------------------------------------------------------
# Phase 2: solvency hypotheses (guard-gap, advisory). Each fixture pair shares a market shape;
# the UNSAFE variant lacks the disproving guard in-body, the SAFE variant has it, and the SAFE
# variant must emit nothing for that category. A hypothesis is never a Finding.
# --------------------------------------------------------------------------------------
MARKET_UNSAFE = """
contract Market {
    mapping(address => uint256) collateral;
    mapping(address => uint256) debt;
    uint256 public collateralFactor;
    uint256 public liquidationBonus;
    uint256 public borrowIndex;
    IOracle oracle;
    function borrow(uint256 amt) external { debt[msg.sender] += amt; }
    function withdraw(uint256 amt) external { collateral[msg.sender] -= amt; }
    function liquidate(address u) external { collateral[u] = 0; }
    function accrueInterest() public { }
}
"""

MARKET_SAFE = """
contract Market {
    mapping(address => uint256) collateral;
    mapping(address => uint256) debt;
    uint256 public collateralFactor;
    uint256 public liquidationBonus;
    uint256 public closeFactor;
    uint256 public borrowIndex;
    IOracle oracle;
    function borrow(uint256 amt) external {
        accrueInterest();
        require(healthFactor(msg.sender) >= 1e18, "unsafe");
        debt[msg.sender] += amt;
    }
    function withdraw(uint256 amt) external {
        accrueInterest();
        require(healthFactor(msg.sender) >= 1e18, "unsafe");
        collateral[msg.sender] -= amt;
    }
    function liquidate(address u) external {
        accrueInterest();
        require(shortfall(u) > 0, "not underwater");
        uint256 maxRepay = debt[u] * closeFactor / 1e18;
        collateral[u] -= maxRepay;
    }
    function healthFactor(address u) public view returns (uint256) { return collateralFactor; }
    function shortfall(address u) public view returns (uint256) { return 0; }
    function accrueInterest() public { }
}
"""

# borrow routes its solvency check to an external comptroller, as Compound does.
MARKET_DELEGATED = """
contract Market {
    mapping(address => uint256) collateral;
    mapping(address => uint256) debt;
    uint256 public collateralFactor;
    IComptroller comptroller;
    function borrow(uint256 amt) external {
        comptroller.borrowAllowed(address(this), msg.sender, amt);
        debt[msg.sender] += amt;
    }
    function repay(uint256 amt) external { debt[msg.sender] -= amt; }
    function accrueInterest() public { }
}
"""

PRICE_UNSAFE = """
contract Market {
    mapping(address => uint256) collateral;
    mapping(address => uint256) debt;
    uint256 public collateralFactor;
    IOracle oracle;
    function borrow(uint256 amt) external {
        uint256 p = oracle.getUnderlyingPrice(address(this));
        comptroller.borrowAllowed(msg.sender, p);
        debt[msg.sender] += amt;
    }
    function repay(uint256 amt) external { }
}
"""

PRICE_SAFE = """
contract Market {
    mapping(address => uint256) collateral;
    mapping(address => uint256) debt;
    uint256 public collateralFactor;
    IOracle oracle;
    function borrow(uint256 amt) external {
        (uint256 p, uint256 updatedAt) = oracle.latestRoundData();
        require(block.timestamp - updatedAt < 3600, "stale");
        require(healthFactor(msg.sender) >= 1e18, "unsafe");
        debt[msg.sender] += amt;
    }
    function repay(uint256 amt) external { }
    function healthFactor(address u) public view returns (uint256) { return collateralFactor; }
}
"""


def _categories(src, path=None):
    plans = mine_lending_solvency_liquidation(src, path)
    if not plans:
        return set()
    return {h["category"] for h in plans[0].to_dict()["solvency_hypotheses"]}


class TestSolvencyHypotheses:
    def test_unsafe_market_fires_expected_categories(self):
        cats = _categories(MARKET_UNSAFE, Path("Market.sol"))
        assert {
            "insolvent_borrow",
            "unsafe_withdraw",
            "liquidation_bypass",
            "liquidation_over_seizure",
            "interest_accrual_gap",
        } <= cats

    def test_safe_market_suppresses_all_guard_gaps(self):
        # every solvency-critical function carries its disproving guard in-body
        cats = _categories(MARKET_SAFE, Path("Market.sol"))
        assert cats == set()

    def test_delegated_check_suppresses_insolvent_borrow(self):
        # the solvency check lives in an external comptroller, not this file
        assert "insolvent_borrow" not in _categories(MARKET_DELEGATED, Path("Market.sol"))

    def test_stale_price_fires_without_freshness_check(self):
        assert "stale_price_solvency" in _categories(PRICE_UNSAFE, Path("Market.sol"))

    def test_stale_price_suppressed_by_freshness_check(self):
        assert "stale_price_solvency" not in _categories(PRICE_SAFE, Path("Market.sol"))

    def test_over_seizure_needs_a_liquidation_bonus(self):
        # MARKET_DELEGATED has no liquidation bonus and no liquidate fn -> no over-seizure
        assert "liquidation_over_seizure" not in _categories(MARKET_DELEGATED, Path("M.sol"))

    def test_every_hypothesis_has_a_negative_check(self):
        plan = mine_lending_solvency_liquidation(MARKET_UNSAFE, Path("Market.sol"))[0]
        assert plan.solvency_hypotheses
        for h in plan.to_dict()["solvency_hypotheses"]:
            assert h["negative_checks"], f"{h['category']} has no negative check"

    def test_categories_are_within_the_enum(self):
        for src in (MARKET_UNSAFE, PRICE_UNSAFE, COMPOUND_LIKE):
            for cat in _categories(src, Path("x.sol")):
                assert cat in _HYPOTHESIS_CATEGORIES

    def test_hypotheses_are_anchored(self):
        for h in mine_lending_solvency_liquidation(MARKET_UNSAFE, Path("Market.sol"))[0].to_dict()[
            "solvency_hypotheses"
        ]:
            assert h["source_anchors"]
            assert all(a.startswith("Market.sol:") for a in h["source_anchors"])

    def test_hypotheses_are_not_findings(self):
        plan = mine_lending_solvency_liquidation(MARKET_UNSAFE, Path("Market.sol"))[0]
        for h in plan.solvency_hypotheses:
            assert not hasattr(h, "severity")
        assert plan.to_dict()["promotion"]["state"] == "hypothesis"

    def test_non_lending_contract_has_no_hypotheses(self):
        # gate rejects the contract before Phase 2 runs
        assert (
            mine_lending_solvency_liquidation("contract T { function transfer() public {} }") == []
        )


class TestHypothesisParserRoundTrip:
    def test_round_trip_preserves_hypotheses(self):
        plan = mine_lending_solvency_liquidation(MARKET_UNSAFE, Path("Market.sol"))[0]
        parsed = parse_lending_solvency_plans(
            {"lending_solvency_liquidation_plans": [plan.to_dict()]}
        )
        assert len(parsed) == 1
        assert {h.category for h in parsed[0].solvency_hypotheses} == {
            h.category for h in plan.solvency_hypotheses
        }
        for h in parsed[0].solvency_hypotheses:
            assert h.negative_checks

    def test_parser_accepts_sdd_singular_key(self):
        raw = {
            "plans": [
                {
                    "objective": "o",
                    "solvency_hypothesis": {
                        "category": "insolvent_borrow",
                        "unsafe_state_transition": "t",
                        "negative_checks": ["the borrow checks health"],
                    },
                }
            ]
        }
        parsed = parse_lending_solvency_plans(raw)
        assert len(parsed) == 1
        assert [h.category for h in parsed[0].solvency_hypotheses] == ["insolvent_borrow"]

    def test_parser_drops_unknown_category(self):
        raw = {
            "plans": [
                {
                    "objective": "o",
                    "solvency_hypotheses": [
                        {"category": "made_up_category", "negative_checks": ["x"]}
                    ],
                }
            ]
        }
        assert parse_lending_solvency_plans(raw)[0].solvency_hypotheses == []

    def test_parser_drops_hypothesis_without_negative_check(self):
        raw = {
            "plans": [
                {
                    "objective": "o",
                    "solvency_hypotheses": [
                        {"category": "insolvent_borrow", "negative_checks": []}
                    ],
                }
            ]
        }
        assert parse_lending_solvency_plans(raw)[0].solvency_hypotheses == []

    def test_hypothesis_to_dict_normalizes_bad_category(self):
        h = SolvencyHypothesis(category="nonsense", negative_checks=["x"])
        assert h.to_dict()["category"] == "unclassified"


# Fixtures for the suppression refinements (entrypoint-only, view/pure skip, delegated guards).
BORROW_UNCHECKED = """
contract M {
    mapping(address => uint256) collateral;
    mapping(address => uint256) debt;
    function borrow(uint256 a) external { unchecked { debt[msg.sender] += a; } }
    function repay(uint256 a) external { debt[msg.sender] -= a; }
}
"""

INTERNAL_BORROW_HELPER = """
contract M {
    mapping(address => uint256) collateral;
    mapping(address => uint256) debt;
    function supply(uint256 a) external { collateral[msg.sender] += a; }
    function borrowInternal(uint256 a) internal { debt[msg.sender] += a; }
    function repay(uint256 a) external { debt[msg.sender] -= a; }
}
"""

VIEW_AND_LIQUIDATABLE = """
contract M {
    mapping(address => uint256) collateral;
    mapping(address => uint256) debt;
    uint256 public constant MAX_BORROW = 100;
    function maxBorrowLimit() external view returns (uint256) { return MAX_BORROW; }
    function liquidate(address u) external { require(isLiquidatable(u), "healthy"); debt[u] = 0; }
    function isLiquidatable(address u) public view returns (bool) { return debt[u] > collateral[u]; }
    function repay(uint256 a) external { debt[msg.sender] -= a; }
}
"""

LOGIC_DELEGATION = """
contract M {
    mapping(address => uint256) collateral;
    mapping(address => uint256) debt;
    function borrow(uint256 a) external { BorrowLogic.executeBorrow(debt, msg.sender, a); }
    function repay(uint256 a) external { debt[msg.sender] -= a; }
}
"""

VALIDATE_DELEGATION = """
contract M {
    mapping(address => uint256) collateral;
    mapping(address => uint256) debt;
    function borrow(uint256 a) external { validateBorrow(msg.sender, a); debt[msg.sender] += a; }
    function validateBorrow(address u, uint256 a) internal view { }
    function repay(uint256 a) external { debt[msg.sender] -= a; }
}
"""


class TestPhase2Refinements:
    def test_unchecked_block_is_not_a_guard(self):
        # regression: the `check` verb must not match `unchecked {}`
        assert "insolvent_borrow" in _categories(BORROW_UNCHECKED, Path("M.sol"))

    def test_internal_borrow_helper_is_not_an_entrypoint(self):
        # borrowInternal is internal -> not attack surface -> no hypothesis
        assert "insolvent_borrow" not in _categories(INTERNAL_BORROW_HELPER, Path("M.sol"))

    def test_view_getter_with_borrow_in_name_does_not_fire(self):
        # maxBorrowLimit is a view getter, not a state transition
        assert "insolvent_borrow" not in _categories(VIEW_AND_LIQUIDATABLE, Path("M.sol"))

    def test_is_liquidatable_suppresses_liquidation_bypass(self):
        assert "liquidation_bypass" not in _categories(VIEW_AND_LIQUIDATABLE, Path("M.sol"))

    def test_logic_library_delegation_suppresses(self):
        # Aave-style: borrow delegates the whole op (incl. its checks) to a *Logic library
        assert "insolvent_borrow" not in _categories(LOGIC_DELEGATION, Path("M.sol"))

    def test_validate_call_suppresses(self):
        assert "insolvent_borrow" not in _categories(VALIDATE_DELEGATION, Path("M.sol"))
