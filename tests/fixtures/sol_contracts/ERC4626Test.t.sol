// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../contracts/vulnerable/erc4626/InflationAttack.sol";

/// @title ERC4626Test - Tests for ERC-4626 inflation attack
contract ERC4626Test is Test {
    SimpleERC20 public asset;
    VulnerableVault public vulnerableVault;
    SecureVault public secureVault;
    InflationAttacker public attacker;

    address alice = address(0x1);
    address bob = address(0x2);
    address eve = address(0x3); // attacker

    function setUp() public {
        // Deploy asset token
        asset = new SimpleERC20();

        // Deploy vaults
        vulnerableVault = new VulnerableVault(IERC20(address(asset)));
        secureVault = new SecureVault(IERC20(address(asset)));

        // Deploy attacker
        attacker = new InflationAttacker(address(vulnerableVault));

        // Fund users
        asset.transfer(alice, 100000 * 10**18);
        asset.transfer(bob, 100000 * 10**18);
        asset.transfer(eve, 100000 * 10**18);
        asset.transfer(address(attacker), 100000 * 10**18);

        vm.label(alice, "Alice");
        vm.label(bob, "Bob");
        vm.label(eve, "Eve (Attacker)");
    }

    /// @notice Test normal deposit/withdraw flow
    function testNormalFlow() public {
        vm.startPrank(alice);
        asset.approve(address(vulnerableVault), 1000 * 10**18);
        uint256 shares = vulnerableVault.deposit(1000 * 10**18, alice);

        assertGt(shares, 0, "Should receive shares");
        assertEq(vulnerableVault.balanceOf(alice), shares);

        uint256 redeemed = vulnerableVault.redeem(shares, alice, alice);
        assertEq(redeemed, 1000 * 10**18, "Should redeem full amount");
        vm.stopPrank();
    }

    /// @notice Test inflation attack on vulnerable vault
    function testInflationAttack() public {
        console.log("=== Inflation Attack Test ===");

        // Step 1: Attacker becomes first depositor
        vm.startPrank(eve);
        asset.approve(address(attacker), type(uint256).max);
        attacker.attack();
        vm.stopPrank();

        uint256 attackerShares = vulnerableVault.balanceOf(address(attacker));
        console.log("Attacker shares:", attackerShares);
        console.log("Vault total assets:", vulnerableVault.totalAssets());
        console.log("Share price:", vulnerableVault.convertToAssets(1e18));

        // Step 2: Victim (Bob) tries to deposit
        vm.startPrank(bob);
        asset.approve(address(vulnerableVault), 5000 * 10**18);

        uint256 bobSharesBefore = vulnerableVault.balanceOf(bob);
        uint256 bobShares = vulnerableVault.deposit(5000 * 10**18, bob);

        console.log("Bob deposited: 5000 tokens");
        console.log("Bob received shares:", bobShares);

        // Bob should receive 0 or very few shares due to rounding!
        assertLt(bobShares, 100, "Bob should receive very few shares");
        vm.stopPrank();

        // Step 3: Attacker redeems for profit
        vm.prank(eve);
        attacker.drain();

        uint256 attackerProfit = asset.balanceOf(eve);
        console.log("Attacker final balance:", attackerProfit);

        // Attacker profited from Bob's deposit
        assertGt(attackerProfit, 10000 * 10**18, "Attacker should profit");
    }

    /// @notice Test secure vault prevents inflation attack
    function testSecureVaultPreventsAttack() public {
        // Try same attack on secure vault
        vm.startPrank(eve);
        asset.approve(address(secureVault), type(uint256).max);

        // First deposit with minimum amount
        secureVault.deposit(1, eve);

        // Try to donate to inflate price
        asset.transfer(address(secureVault), 10000 * 10**18);
        vm.stopPrank();

        // Victim deposits
        vm.startPrank(bob);
        asset.approve(address(secureVault), 5000 * 10**18);
        uint256 bobShares = secureVault.deposit(5000 * 10**18, bob);
        vm.stopPrank();

        // Bob should receive fair amount of shares due to virtual shares
        assertGt(bobShares, 1000, "Bob should receive fair shares");

        console.log("Secure vault - Bob shares:", bobShares);
    }

    /// @notice Fuzz test: Deposits should always receive proportional shares
    function testFuzz_ProportionalShares(uint96 amount1, uint96 amount2) public {
        vm.assume(amount1 > 1000 && amount1 < 1000000 * 10**18);
        vm.assume(amount2 > 1000 && amount2 < 1000000 * 10**18);

        // Alice deposits first
        vm.startPrank(alice);
        asset.approve(address(secureVault), type(uint256).max);
        uint256 aliceShares = secureVault.deposit(amount1, alice);
        vm.stopPrank();

        // Bob deposits second
        vm.startPrank(bob);
        asset.approve(address(secureVault), type(uint256).max);
        uint256 bobShares = secureVault.deposit(amount2, bob);
        vm.stopPrank();

        // Shares should be proportional to deposits
        uint256 expectedRatio = (amount2 * 1e18) / amount1;
        uint256 actualRatio = (bobShares * 1e18) / aliceShares;

        // Allow 1% deviation due to rounding
        assertApproxEqRel(actualRatio, expectedRatio, 0.01e18, "Shares should be proportional");
    }

    /// @notice Invariant: Total assets >= total supply value
    function invariant_TotalAssets() public {
        if (vulnerableVault.totalSupply() > 0) {
            uint256 totalAssets = vulnerableVault.totalAssets();
            uint256 totalValue = vulnerableVault.convertToAssets(vulnerableVault.totalSupply());

            assertGe(totalAssets, totalValue, "Total assets should back all shares");
        }
    }

    /// @notice Test convertToShares and convertToAssets symmetry
    function testConversionSymmetry() public {
        vm.startPrank(alice);
        asset.approve(address(secureVault), 1000 * 10**18);
        secureVault.deposit(1000 * 10**18, alice);
        vm.stopPrank();

        uint256 assets = 500 * 10**18;
        uint256 shares = secureVault.convertToShares(assets);
        uint256 assetsBack = secureVault.convertToAssets(shares);

        // Should be approximately equal (allowing for rounding)
        assertApproxEqAbs(assetsBack, assets, 100, "Conversion should be symmetric");
    }
}
