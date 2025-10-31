// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @title VulnerableBank - Demo contract with intentional vulnerabilities
/// @notice DO NOT USE IN PRODUCTION - For educational purposes only
/// @dev This contract contains 6 deliberate vulnerabilities for MIESC demo
contract VulnerableBank {
    mapping(address => uint256) public balances;
    address public owner;
    uint256 public totalDeposits;

    constructor() {
        owner = msg.sender;
    }

    /// @notice Deposit ETH into the bank
    function deposit() public payable {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }

    /// @notice Withdraw ETH - VULNERABLE TO REENTRANCY!
    /// @dev CRITICAL: External call before state update (SWC-107)
    function withdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        // ❌ CRITICAL: External call before state update
        // This allows reentrancy attacks!
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // ❌ State update happens AFTER external call
        balances[msg.sender] = 0; // Too late!
    }

    /// @notice Update user balance - HIGH: Missing access control!
    /// @dev HIGH: Anyone can call this and manipulate balances
    function setBalance(address user, uint256 amount) public {
        // ❌ HIGH: No access control! Anyone can set any balance
        balances[user] = amount;
    }

    /// @notice Get contract balance
    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }

    /// @notice Emergency withdraw - HIGH: Unsafe transfer
    /// @dev MEDIUM: No checks on recipient address
    function emergencyWithdraw(address payable recipient) public {
        require(msg.sender == owner, "Not owner");

        // ❌ MEDIUM: No check if recipient is a contract
        // ❌ HIGH: Using transfer() which has 2300 gas limit
        recipient.transfer(address(this).balance);
    }

    /// @notice Transfer ownership - MEDIUM: No zero address check
    function transferOwnership(address newOwner) public {
        require(msg.sender == owner, "Not owner");

        // ❌ MEDIUM: No check for zero address
        owner = newOwner;
    }

    /// @notice Batch transfer - LOW: No event emission
    function batchTransfer(address[] memory recipients, uint256[] memory amounts) public {
        require(msg.sender == owner, "Not owner");
        require(recipients.length == amounts.length, "Length mismatch");

        for (uint256 i = 0; i < recipients.length; i++) {
            balances[recipients[i]] += amounts[i];
            // ❌ LOW: No event emitted for state change
        }
    }

    // ❌ INFO: Missing receive() function
    // ❌ INFO: No events defined
    // ❌ INFO: Gas optimization opportunities
}

/*
 * EXPECTED MIESC FINDINGS:
 *
 * 🔴 CRITICAL (1):
 *    - Reentrancy vulnerability in withdraw() function (Line 28-31)
 *      SWC-107, CWE-841, OWASP SC-01
 *      Tools: Slither, Mythril, Manticore
 *
 * 🟠 HIGH (2):
 *    - Missing access control on setBalance() (Line 40)
 *      Anyone can manipulate balances
 *      Tools: Slither, Aderyn
 *
 *    - Unsafe transfer in emergencyWithdraw() (Line 54)
 *      Using transfer() with 2300 gas limit
 *      Tools: Slither
 *
 * 🟡 MEDIUM (3):
 *    - No check on recipient address in emergencyWithdraw() (Line 54)
 *      Could send to address(0) or malicious contract
 *      Tools: Slither, Mythril
 *
 *    - Missing zero address check in transferOwnership() (Line 63)
 *      Could lose contract ownership
 *      Tools: Slither
 *
 *    - Unchecked return value (potential)
 *      Tools: Slither
 *
 * 🟢 LOW (5):
 *    - Missing events for state changes (Line 73)
 *    - No receive() or fallback() function
 *    - Gas optimization opportunities
 *    - Naming conventions
 *    - Documentation improvements
 *
 * ℹ️  INFORMATIONAL (20+):
 *    - Solidity version pragma too loose
 *    - Public vs external function optimization
 *    - Variable naming conventions
 *    - etc.
 *
 * BEFORE MIESC: 147 findings (including duplicates and false positives)
 * AFTER MIESC:  6 actionable findings (AI-filtered and ranked)
 *
 * TIME SAVED: ~4 hours of manual triage → 5 minutes
 */
