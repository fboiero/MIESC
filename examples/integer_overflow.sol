// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

/**
 * @title Integer Overflow Example
 * @notice Classic integer overflow vulnerability
 * @dev Uses Solidity 0.7.0 (before automatic overflow checks)
 */
contract IntegerOverflow {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    constructor() {
        totalSupply = 1000000;
        balances[msg.sender] = totalSupply;
    }

    /**
     * @notice Transfer tokens
     * @dev VULNERABLE: No SafeMath, allows overflow
     */
    function transfer(address to, uint256 amount) public returns (bool) {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // VULNERABILITY: Overflow possible
        balances[msg.sender] -= amount;
        balances[to] += amount;  // Can overflow

        return true;
    }

    /**
     * @notice Batch transfer
     * @dev VULNERABLE: Can overflow total amount
     */
    function batchTransfer(address[] memory recipients, uint256 amount) public returns (bool) {
        uint256 totalAmount = recipients.length * amount;  // VULNERABILITY: Overflow

        require(balances[msg.sender] >= totalAmount, "Insufficient balance");

        for (uint256 i = 0; i < recipients.length; i++) {
            balances[recipients[i]] += amount;
        }

        balances[msg.sender] -= totalAmount;
        return true;
    }

    /**
     * @notice Add to balance
     * @dev VULNERABLE: Direct addition without overflow check
     */
    function addBalance(uint256 amount) public {
        // VULNERABILITY: Can overflow
        balances[msg.sender] += amount;
    }
}
