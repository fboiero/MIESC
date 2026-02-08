// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0; // Using 0.7.x to demonstrate overflow (0.8+ has built-in checks)

/**
 * @title IntegerOverflowVulnerable
 * @dev Test contract with SWC-101 integer overflow vulnerability
 * @notice DO NOT USE IN PRODUCTION - Educational purposes only
 */
contract IntegerOverflowVulnerable {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    event Transfer(address indexed from, address indexed to, uint256 amount);

    constructor() {
        totalSupply = 1000000;
        balances[msg.sender] = totalSupply;
    }

    /**
     * @dev VULNERABLE: Transfer without overflow check
     * @notice In Solidity <0.8.0, arithmetic operations can overflow silently
     */
    function transfer(address to, uint256 amount) external {
        // VULNERABILITY: No overflow check on subtraction
        // If amount > balance, this underflows to a huge number
        balances[msg.sender] -= amount;
        balances[to] += amount;
        emit Transfer(msg.sender, to, amount);
    }

    /**
     * @dev VULNERABLE: Batch transfer with overflow
     */
    function batchTransfer(address[] calldata recipients, uint256 amount) external {
        // VULNERABILITY: Multiplication can overflow
        uint256 totalAmount = recipients.length * amount;
        require(balances[msg.sender] >= totalAmount, "Insufficient balance");

        balances[msg.sender] -= totalAmount;
        for (uint256 i = 0; i < recipients.length; i++) {
            balances[recipients[i]] += amount;
        }
    }

    /**
     * @dev VULNERABLE: Lock time manipulation via overflow
     */
    mapping(address => uint256) public lockTime;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        lockTime[msg.sender] = block.timestamp + 1 weeks;
    }

    function increaseLockTime(uint256 _seconds) external {
        // VULNERABILITY: Can overflow to set lockTime to a past value
        lockTime[msg.sender] += _seconds;
    }

    function withdrawLocked() external {
        require(block.timestamp > lockTime[msg.sender], "Still locked");
        uint256 amount = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }
}
