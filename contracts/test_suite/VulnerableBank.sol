// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableBank
 * @notice Test contract with REENTRANCY vulnerability
 * @dev For MIESC testing purposes - DO NOT USE IN PRODUCTION
 *
 * Known Vulnerabilities:
 * - SWC-107: Reentrancy
 * - CWE-841: Improper Enforcement of Behavioral Workflow
 *
 * Expected Detections:
 * - Slither: reentrancy-eth, reentrancy-benign
 * - Mythril: SWC-107
 * - Manticore: Reentrancy path detection
 */
contract VulnerableBank {
    mapping(address => uint256) public balances;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    /**
     * @notice Deposit Ether into the bank
     */
    function deposit() external payable {
        require(msg.value > 0, "Must deposit positive amount");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /**
     * @notice Withdraw Ether from the bank
     * @dev VULNERABLE: State update happens AFTER external call
     * @param amount Amount to withdraw
     */
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // VULNERABILITY: External call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State update happens AFTER external call - REENTRANCY RISK
        balances[msg.sender] -= amount;
        emit Withdrawal(msg.sender, amount);
    }

    /**
     * @notice Get contract balance
     */
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    /**
     * @notice Get user balance
     */
    function getUserBalance(address user) external view returns (uint256) {
        return balances[user];
    }
}
