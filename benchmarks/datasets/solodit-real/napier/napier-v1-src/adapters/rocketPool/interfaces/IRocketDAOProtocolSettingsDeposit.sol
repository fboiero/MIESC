// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.0;

interface IRocketDAOProtocolSettingsDeposit {
    /// @notice Returns the minimum deposit size
    function getMinimumDeposit() external view returns (uint256);

    /// @notice Returns the current fee paid on user deposits
    function getDepositFee() external view returns (uint256);
}
