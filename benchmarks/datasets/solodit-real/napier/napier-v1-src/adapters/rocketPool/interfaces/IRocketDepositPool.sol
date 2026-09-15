// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.0;

/// @notice Taken from https://github.com/rocket-pool/rocketpool/blob/9710596d82189c54f0dc35be3501cda13a155f4d/contracts/contract/deposit/RocketDepositPool.sol#L90
/// @notice Interface for the Rocket Deposit Pool contract
interface IRocketDepositPool {
    /// @notice Deposit ETH into the pool
    /// @dev Deposit fee is deducted from the amount deposited
    /// - the fee is determined by Rocket Pool DAO protocol settings (see RocketDAOProtocolSettingsDeposit.sol)
    /// - minimum deposit size is determined by Rocket Pool DAO protocol settings (see RocketDAOProtocolSettingsDeposit.sol)
    /// - if deposit cap is reached, the deposit will be rejected
    function deposit() external payable;

    /// @notice Returns the maximum amount that can be accepted into the deposit pool at this time in wei
    function getMaximumDepositAmount() external view returns (uint256);
}
