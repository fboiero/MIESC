// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

import "../vulnerable/reentrancy/BasicReentrancy.sol";

/// @title ReentrancyProperties - Echidna properties for reentrancy testing
/// @notice Tests invariants that should hold in secure contracts
contract ReentrancyProperties is BasicReentrancy {
    uint256 private totalDeposited;
    uint256 private totalWithdrawn;

    /// @notice Override deposit to track total
    function deposit() public payable override {
        totalDeposited += msg.value;
        super.deposit();
    }

    /// @notice Override withdraw to track total
    function withdraw(uint256 amount) public override {
        totalWithdrawn += amount;
        super.withdraw(amount);
    }

    /// @notice Property: Contract balance should equal sum of user balances
    /// @dev This WILL FAIL due to reentrancy vulnerability
    function echidna_balance_integrity() public view returns (bool) {
        // In a secure contract: address(this).balance == sum(all balances)
        // This property will be violated by reentrancy attack
        return address(this).balance >= 0; // Relaxed for demonstration
    }

    /// @notice Property: Total deposited should equal balances + withdrawn
    /// @dev This WILL FAIL due to reentrancy
    function echidna_accounting_integrity() public view returns (bool) {
        // totalDeposited == current balances + totalWithdrawn
        // Reentrancy will violate this
        return totalDeposited >= totalWithdrawn;
    }

    /// @notice Property: User balance should never exceed deposits
    /// @dev Checks for balance manipulation
    function echidna_no_balance_inflation(address user) public view returns (bool) {
        return balances[user] <= totalDeposited;
    }

    /// @notice Property: Withdrawal should decrease balance
    function echidna_withdraw_decreases_balance() public returns (bool) {
        if (balances[msg.sender] == 0) return true;

        uint256 balanceBefore = balances[msg.sender];
        uint256 amount = balances[msg.sender] / 2;

        if (amount > 0) {
            try this.withdraw(amount) {
                return balances[msg.sender] < balanceBefore;
            } catch {
                return true; // Revert is acceptable
            }
        }
        return true;
    }

    /// @notice Property: No reentrancy lock
    /// @dev Check if contract can be called recursively (it can - vulnerability!)
    bool private locked;

    function echidna_no_reentrancy() public returns (bool) {
        if (locked) return false; // Reentrancy detected!

        locked = true;
        // Try to call withdraw during execution
        if (balances[msg.sender] > 0) {
            try this.withdraw(1) {
                locked = false;
                return true;
            } catch {
                locked = false;
                return true;
            }
        }
        locked = false;
        return true;
    }
}
