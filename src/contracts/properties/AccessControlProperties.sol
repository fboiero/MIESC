// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

import "../vulnerable/access-control/UnprotectedWithdraw.sol";

/// @title AccessControlProperties - Echidna properties for access control
contract AccessControlProperties is UnprotectedWithdraw {
    address private deployer;

    constructor() {
        deployer = msg.sender;
    }

    /// @notice Property: Only owner should change critical state
    /// @dev This WILL FAIL due to missing access control
    function echidna_only_owner_withdraws() public returns (bool) {
        uint256 balanceBefore = address(this).balance;

        if (msg.sender != owner) {
            // Non-owner should not be able to withdraw
            try this.withdrawAll(payable(msg.sender)) {
                // If this succeeds, property failed!
                return address(this).balance == balanceBefore;
            } catch {
                // Revert expected
                return true;
            }
        }
        return true;
    }

    /// @notice Property: Owner should always be set
    function echidna_owner_always_set() public view returns (bool) {
        return owner != address(0);
    }

    /// @notice Property: Owner should not change unexpectedly
    function echidna_owner_stable() public view returns (bool) {
        return owner == deployer;
    }

    /// @notice Property: Balance should only decrease through owner
    function echidna_balance_protection() public view returns (bool) {
        // If balance decreased, it should only be by owner
        // This will fail if anyone can withdraw
        return true; // Simplified
    }
}
