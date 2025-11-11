// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableBank - Deliberately Vulnerable Contract for MIESC Demo
 * @notice This contract contains multiple vulnerabilities for demonstration
 * @dev DO NOT USE IN PRODUCTION - Educational purposes only
 */
contract VulnerableBank {
    mapping(address => uint256) public balances;
    address public owner;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice Deposit ETH into the contract
     */
    function deposit() public payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /**
     * @notice Withdraw funds - VULNERABLE TO REENTRANCY!
     * @dev Classic reentrancy vulnerability - updates state after external call
     */
    function withdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "Insufficient balance");

        // VULNERABILITY: External call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State update happens AFTER external call - reentrancy risk!
        balances[msg.sender] = 0;

        emit Withdrawal(msg.sender, amount);
    }

    /**
     * @notice Emergency withdrawal by owner - MISSING ACCESS CONTROL!
     * @dev Anyone can call this function and drain the contract
     */
    function emergencyWithdraw() public {
        // VULNERABILITY: No access control check!
        // Should have: require(msg.sender == owner, "Only owner");

        payable(msg.sender).transfer(address(this).balance);
    }

    /**
     * @notice Get contract balance
     */
    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }

    /**
     * @notice Transfer ownership - DANGEROUS tx.origin usage
     * @dev Uses tx.origin instead of msg.sender - phishing vulnerability
     */
    function transferOwnership(address newOwner) public {
        // VULNERABILITY: Uses tx.origin instead of msg.sender
        require(tx.origin == owner, "Not owner");
        owner = newOwner;
    }
}
