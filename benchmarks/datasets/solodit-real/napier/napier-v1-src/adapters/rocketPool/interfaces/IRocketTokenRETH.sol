// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.0;

import {IERC20} from "@openzeppelin/contracts@4.9.3/token/ERC20/IERC20.sol";

interface IRocketTokenRETH is IERC20 {
    /// @notice Get the amount of ETH backing each rETH
    /// @param _rethAmount The amount of rETH to get the ETH value of
    function getEthValue(uint256 _rethAmount) external view returns (uint256);

    /// @notice Get the amount of rETH backing each ETH
    /// @param _ethAmount The amount of ETH to get the rETH value of
    function getRethValue(uint256 _ethAmount) external view returns (uint256);

    /// @notice Get the current ETH : rETH exchange rate
    /// Returns the amount of ETH backing 1 rETH
    function getExchangeRate() external view returns (uint256);

    /// @notice Get the total amount of collateral available
    /// Includes rETH contract balance & excess deposit pool balance
    function getTotalCollateral() external view returns (uint256);

    /// @notice Burn rETH for ETH
    /// @param _rethAmount The amount of rETH to burn
    /// @dev Revert if Rocket Pool does not have enough ETH to cover the burn
    function burn(uint256 _rethAmount) external;
}
