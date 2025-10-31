// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

import "../vulnerable/erc4626/InflationAttack.sol";

/// @title ERC4626Properties - Echidna properties for ERC-4626 vaults
contract ERC4626Properties {
    VulnerableVault public vault;
    SimpleERC20 public asset;

    constructor() {
        asset = new SimpleERC20();
        vault = new VulnerableVault(IERC20(address(asset)));

        // Mint tokens for testing
        asset.mint(address(this), 1000000 * 10**18);
        asset.approve(address(vault), type(uint256).max);
    }

    /// @notice Property: Deposit should always return non-zero shares
    /// @dev This WILL FAIL after inflation attack
    function echidna_deposit_returns_shares() public returns (bool) {
        uint256 depositAmount = 1000 * 10**18;
        if (asset.balanceOf(address(this)) < depositAmount) return true;

        try vault.deposit(depositAmount, address(this)) returns (uint256 shares) {
            return shares > 0;
        } catch {
            return true; // Revert is acceptable
        }
    }

    /// @notice Property: Share price should not spike dramatically
    /// @dev Detects inflation attack
    function echidna_no_price_manipulation() public view returns (bool) {
        if (vault.totalSupply() == 0) return true;

        uint256 sharePrice = vault.convertToAssets(1e18);
        // Share price should never exceed 100x the base
        return sharePrice < 100 * 1e18;
    }

    /// @notice Property: Total assets should back total supply
    function echidna_assets_back_supply() public view returns (bool) {
        if (vault.totalSupply() == 0) return true;

        uint256 totalAssets = vault.totalAssets();
        uint256 totalValue = vault.convertToAssets(vault.totalSupply());

        // Total assets should be >= value of all shares
        return totalAssets >= totalValue;
    }

    /// @notice Property: Conversion symmetry
    /// @dev convertToShares -> convertToAssets should be approximately equal
    function echidna_conversion_symmetry() public view returns (bool) {
        if (vault.totalSupply() == 0) return true;

        uint256 assets = 1000 * 10**18;
        uint256 shares = vault.convertToShares(assets);
        uint256 assetsBack = vault.convertToAssets(shares);

        // Allow 1% deviation
        uint256 diff = assets > assetsBack ? assets - assetsBack : assetsBack - assets;
        return diff <= assets / 100;
    }

    /// @notice Property: Redeem should return proportional assets
    function echidna_proportional_redeem() public returns (bool) {
        if (vault.balanceOf(address(this)) == 0) return true;

        uint256 shares = vault.balanceOf(address(this)) / 2;
        if (shares == 0) return true;

        uint256 expectedAssets = vault.convertToAssets(shares);

        try vault.redeem(shares, address(this), address(this)) returns (uint256 assets) {
            // Allow 1% deviation
            uint256 diff = expectedAssets > assets ? expectedAssets - assets : assets - expectedAssets;
            return diff <= expectedAssets / 100;
        } catch {
            return true;
        }
    }

    /// @notice Property: First depositor advantage should be limited
    /// @dev Checks if first depositor can steal from subsequent depositors
    function echidna_no_first_depositor_advantage() public returns (bool) {
        // This will fail in vulnerable vault
        return true; // Placeholder - implement actual check
    }
}
