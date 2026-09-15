// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.0;

interface IComptroller {
    /// @notice Claim all the comp accrued by holder in the specified markets
    /// @param holder The address to claim COMP for
    /// @param cTokens The list of markets to claim COMP in
    function claimComp(address holder, address[] memory cTokens) external;

    function claimComp(address[] memory holders, address[] memory cTokens, bool borrowers, bool suppliers) external;

    function markets(address target) external returns (bool isListed, uint256 collateralFactorMantissa, bool isComped);

    function oracle() external returns (address);
}
