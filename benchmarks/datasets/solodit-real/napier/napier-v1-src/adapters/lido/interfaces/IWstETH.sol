// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.0;

import {IERC20} from "@openzeppelin/contracts@4.9.3/token/ERC20/IERC20.sol";

/// @notice Interface for deployed wstETH. WSstETH is a StETH token wrapper with static balances.
/// @author Taken from https://github.com/lidofinance/lido-dao/blob/98c4821638ceab0ce84dbd3b7fdc7c1f83f07622/contracts/0.6.12/WstETH.sol
interface IWstETH is IERC20 {
    /// @notice Exchanges wstETH to stETH
    function unwrap(uint256 _wstETHAmount) external returns (uint256);

    /// @notice Exchanges stETH to wstETH
    function wrap(uint256 _stETHAmount) external returns (uint256);

    /**
     * @notice Get amount of wstETH for a one stETH
     * @return Amount of wstETH for a 1 stETH
     */
    function tokensPerStEth() external view returns (uint256);

    /**
     * @notice Get amount of stETH for a one wstETH
     * @return Amount of stETH for 1 wstETH
     */
    function stEthPerToken() external view returns (uint256);

    /// @notice Returns amount of wstETH for a given amount of stETH
    function getWstETHByStETH(uint256 _stETHAmount) external view returns (uint256);

    /// @notice Returns amount of stETH for a given amount of wstETH
    function getStETHByWstETH(uint256 _wstETHAmount) external view returns (uint256);
}
