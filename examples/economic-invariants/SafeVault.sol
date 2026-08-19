// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

// Fixed ERC-4626-style vault using INTERNAL asset accounting. totalAssets()
// returns a variable that only changes through deposit/redeem, so a direct
// token donation cannot inflate the share price. This neutralises the classic
// first-deposit / donation inflation attack.
contract SafeVault {
    IERC20 public asset;
    uint256 public totalSupply;
    uint256 private _accountedAssets;

    mapping(address => uint256) public balanceOf;

    constructor(address asset_) {
        asset = IERC20(asset_);
    }

    function totalAssets() public view returns (uint256) {
        return _accountedAssets;
    }

    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 supply = totalSupply;
        return supply == 0 ? assets : (assets * supply) / _accountedAssets;
    }

    function convertToAssets(uint256 shares) public view returns (uint256) {
        uint256 supply = totalSupply;
        return supply == 0 ? shares : (shares * _accountedAssets) / supply;
    }

    function deposit(uint256 assets, address receiver) public returns (uint256 shares) {
        shares = convertToShares(assets);
        asset.transferFrom(msg.sender, address(this), assets);
        _accountedAssets += assets;
        totalSupply += shares;
        balanceOf[receiver] += shares;
    }

    function redeem(uint256 shares, address receiver, address owner) public returns (uint256 assets) {
        assets = convertToAssets(shares);
        balanceOf[owner] -= shares;
        totalSupply -= shares;
        _accountedAssets -= assets;
        asset.transfer(receiver, assets);
    }
}
