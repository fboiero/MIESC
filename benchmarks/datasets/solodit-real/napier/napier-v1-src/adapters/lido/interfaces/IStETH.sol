// SPDX-License-Identifier: GPL-3.0

pragma solidity ^0.8.0;

import {IERC20} from "@openzeppelin/contracts@4.9.3/token/ERC20/IERC20.sol";

/// @notice Interface for deployed stETH.
/// @author https://github.com/lidofinance/lido-dao/blob/331ecec7fe3c8d57841fd73ccca7fb1cc9bc174e/contracts/0.4.24/Lido.sol
interface IStETH is IERC20 {
    // @notice stETH / wstETH
    function getPooledEthByShares(uint256 _sharesAmount) external view returns (uint256);

    function getSharesByPooledEth(uint256 _pooledEthAmount) external view returns (uint256);

    /**
     * @notice Send funds to the pool with optional _referral parameter
     * @dev This function is alternative way to submit funds. Supports optional referral address.
     * @return Amount of StETH shares generated
     */
    function submit(address _referral) external payable returns (uint256);

    /// @dev Returns the amount of buffered ether in stETH contract
    function getBufferedEther() external view returns (uint256);

    function getTotalShares() external view returns (uint256);

    function getTotalPooledEther() external view returns (uint256);

    /**
     * @notice Returns how much Ether can be staked in the current block
     * @dev Special return values:
     * - 2^256 - 1 if staking is unlimited;
     * - 0 if staking is paused or if limit is exhausted.
     */
    function getCurrentStakeLimit() external view returns (uint256);
}
