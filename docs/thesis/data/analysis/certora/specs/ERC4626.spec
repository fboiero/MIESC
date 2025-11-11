/*
 * Certora Formal Verification Spec for ERC-4626 Vault
 * Tests: InflationAttack.sol
 *
 * Verifies properties that should hold in a secure ERC-4626 implementation
 */

using SimpleERC20 as asset;

methods {
    function deposit(uint256, address) external returns (uint256);
    function redeem(uint256, address, address) external returns (uint256);
    function totalAssets() external returns (uint256) envfree;
    function totalSupply() external returns (uint256) envfree;
    function balanceOf(address) external returns (uint256) envfree;
    function convertToShares(uint256) external returns (uint256) envfree;
    function convertToAssets(uint256) external returns (uint256) envfree;

    // Asset token methods
    function asset.balanceOf(address) external returns (uint256) envfree;
    function asset.totalSupply() external returns (uint256) envfree;
}

/**
 * Rule: Deposit should always mint non-zero shares for non-zero assets
 * Status: FAILS in vulnerable vault after inflation attack
 */
rule depositMintsShares(uint256 assets, address receiver) {
    env e;
    require assets > 0;
    require assets < asset.totalSupply();

    uint256 sharesBefore = balanceOf(receiver);

    uint256 shares = deposit(e, assets, receiver);

    uint256 sharesAfter = balanceOf(receiver);

    assert shares > 0,
        "Deposit should mint non-zero shares";
    assert sharesAfter == sharesBefore + shares,
        "Shares should be added to receiver";
}

/**
 * Rule: Share price should not increase dramatically between deposits
 * Status: FAILS if inflation attack possible
 */
rule noPriceManipulation() {
    uint256 assets = 1000;
    require totalSupply() > 0;

    uint256 sharesBefore = convertToShares(assets);

    // Some action happens (deposit, transfer, etc.)
    env e;
    uint256 depositAmount;
    address receiver;
    deposit(e, depositAmount, receiver);

    uint256 sharesAfter = convertToShares(assets);

    // Share price shouldn't change more than 10% in single transaction
    assert sharesAfter * 110 >= sharesBefore * 100 &&
           sharesBefore * 110 >= sharesAfter * 100,
        "Share price should be stable";
}

/**
 * Rule: Total assets should back total supply value
 * Status: Should always PASS
 */
invariant assetsBacking()
    totalSupply() == 0 ||
    totalAssets() >= convertToAssets(totalSupply())
    {
        preserved deposit(uint256 assets, address receiver) with (env e) {
            require assets > 0;
        }
    }

/**
 * Rule: Conversion symmetry
 * Status: Should PASS in both implementations
 */
rule conversionSymmetry(uint256 assets) {
    require assets > 0;
    require totalSupply() > 0;

    uint256 shares = convertToShares(assets);
    uint256 assetsBack = convertToAssets(shares);

    // Allow small rounding error
    assert assetsBack >= assets - 100 && assetsBack <= assets + 100,
        "Conversion should be symmetric";
}

/**
 * Rule: Redeem should be proportional to shares
 * Status: Should PASS
 */
rule proportionalRedeem(address owner, uint256 shares) {
    env e;
    require e.msg.sender == owner;
    require balanceOf(owner) >= shares;
    require shares > 0;

    uint256 expectedAssets = convertToAssets(shares);
    uint256 assets = redeem(e, shares, owner, owner);

    // Allow 1% deviation for rounding
    assert assets * 101 >= expectedAssets * 100 &&
           expectedAssets * 101 >= assets * 100,
        "Redeem should be proportional";
}

/**
 * Rule: First depositor cannot steal from subsequent depositors
 * Status: FAILS in vulnerable vault
 */
rule noFirstDepositorAdvantage() {
    env e1; env e2;
    address alice; address bob;
    require alice != bob;

    // Alice deposits first
    uint256 aliceDeposit = 1;
    uint256 aliceShares = deposit(e1, aliceDeposit, alice);

    // Snapshot state
    uint256 aliceSharesBefore = balanceOf(alice);
    uint256 totalAssetsBefore = totalAssets();

    // Bob deposits larger amount
    uint256 bobDeposit = 1000;
    uint256 bobShares = deposit(e2, bobDeposit, bob);

    // Alice's shares should not increase
    assert balanceOf(alice) == aliceSharesBefore,
        "Alice shares should not change on Bob's deposit";

    // Bob should receive fair share
    assert bobShares > aliceShares,
        "Larger deposit should receive more shares";
}

/**
 * Rule: Total supply should never decrease from deposit
 * Status: Should PASS
 */
rule depositIncreasesSupply(uint256 assets, address receiver) {
    env e;
    uint256 supplyBefore = totalSupply();

    deposit(e, assets, receiver);

    uint256 supplyAfter = totalSupply();

    assert supplyAfter >= supplyBefore,
        "Deposit should not decrease total supply";
}
