// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

/**
 * @title IntegerOverflow
 * @notice Test contract with ARITHMETIC OVERFLOW/UNDERFLOW vulnerabilities
 * @dev For MIESC testing purposes - DO NOT USE IN PRODUCTION
 * @dev Uses Solidity 0.7.6 (before automatic overflow checks)
 *
 * Known Vulnerabilities:
 * - SWC-101: Integer Overflow and Underflow
 * - CWE-190: Integer Overflow
 * - CWE-191: Integer Underflow
 *
 * Expected Detections:
 * - Slither: incorrect-equality, divide-before-multiply
 * - Mythril: SWC-101
 * - Manticore: Overflow/underflow path detection
 */
contract IntegerOverflow {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    event Transfer(address indexed from, address indexed to, uint256 amount);

    /**
     * @notice Initialize user balance
     * @dev VULNERABLE: No overflow check
     */
    function mint(address user, uint256 amount) external {
        // VULNERABILITY: Can overflow
        balances[user] += amount;
        totalSupply += amount;
    }

    /**
     * @notice Transfer tokens
     * @dev VULNERABLE: No underflow check
     */
    function transfer(address to, uint256 amount) external {
        // VULNERABILITY: Can underflow
        balances[msg.sender] -= amount;
        balances[to] += amount;
        emit Transfer(msg.sender, to, amount);
    }

    /**
     * @notice Batch transfer with multiplication
     * @dev VULNERABLE: Multiplication overflow
     */
    function batchTransfer(address[] calldata recipients, uint256 amount) external {
        // VULNERABILITY: Multiplication can overflow
        uint256 totalAmount = recipients.length * amount;
        require(balances[msg.sender] >= totalAmount, "Insufficient balance");

        balances[msg.sender] -= totalAmount;
        for (uint256 i = 0; i < recipients.length; i++) {
            balances[recipients[i]] += amount;
            emit Transfer(msg.sender, recipients[i], amount);
        }
    }

    /**
     * @notice Calculate interest (unsafe division)
     * @dev VULNERABLE: Division before multiplication (precision loss)
     */
    function calculateInterest(uint256 principal, uint256 rate, uint256 time)
        external
        pure
        returns (uint256)
    {
        // VULNERABILITY: Division before multiplication
        return (principal / 100) * rate * time;
    }

    /**
     * @notice Unsafe subtraction
     * @dev VULNERABLE: Can underflow to max uint256
     */
    function unsafeSubtract(uint256 a, uint256 b) external pure returns (uint256) {
        // VULNERABILITY: No underflow check
        return a - b;
    }
}
