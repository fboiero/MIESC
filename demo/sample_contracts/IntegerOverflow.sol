// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;  // Using 0.7.0 - no automatic overflow checks

/**
 * @title TokenSale - Integer Overflow Vulnerability Demo
 * @notice This contract contains intentional integer overflow vulnerabilities for educational purposes
 * @dev DO NOT USE IN PRODUCTION - Demonstrates arithmetic overflow/underflow
 *
 * Vulnerability: CWE-190 (Integer Overflow), CWE-191 (Integer Underflow)
 * OWASP SC Top 10: SC03 - Arithmetic Issues
 * SWC-101: Integer Overflow and Underflow
 *
 * Note: Solidity 0.8+ has built-in overflow checks. This uses 0.7.0 to demonstrate the vulnerability.
 */
contract TokenSale {
    mapping(address => uint256) public balances;
    uint256 public tokenPrice = 1 ether;
    uint256 public totalSupply = 1000000;

    event Purchase(address indexed buyer, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    /**
     * @notice Buy tokens with ETH
     * @param amount Number of tokens to purchase
     * @dev VULNERABLE: No overflow check on multiplication
     *
     * Attack Vector:
     * 1. Attacker calls buyTokens(2^256 - 1)
     * 2. cost = (2^256 - 1) * 1 ether overflows to a small value
     * 3. Attacker pays tiny amount but gets massive tokens
     */
    function buyTokens(uint256 amount) public payable {
        // ❌ VULNERABILITY: Unchecked multiplication can overflow
        uint256 cost = amount * tokenPrice;

        require(msg.value >= cost, "Insufficient ETH sent");
        require(totalSupply >= amount, "Not enough tokens available");

        totalSupply -= amount;
        balances[msg.sender] += amount;

        emit Purchase(msg.sender, amount);
    }

    /**
     * @notice Withdraw tokens from balance
     * @param amount Number of tokens to withdraw
     * @dev VULNERABLE: No underflow check on subtraction
     *
     * Attack Vector:
     * 1. Attacker has 10 tokens
     * 2. Attacker calls withdraw(11)
     * 3. balances[attacker] = 10 - 11 underflows to 2^256 - 1
     * 4. Attacker now has virtually unlimited tokens
     */
    function withdraw(uint256 amount) public {
        // ❌ VULNERABILITY: Unchecked subtraction can underflow
        balances[msg.sender] -= amount;

        // Transfer tokens (simplified)
        emit Withdrawal(msg.sender, amount);
    }

    /**
     * @notice Batch purchase with discount
     * @param amounts Array of token amounts
     * @dev VULNERABLE: Multiple overflow points
     */
    function batchBuy(uint256[] memory amounts) public payable {
        uint256 total = 0;

        // ❌ VULNERABILITY: Loop accumulation can overflow
        for (uint256 i = 0; i < amounts.length; i++) {
            total += amounts[i];  // Can overflow
        }

        uint256 cost = total * tokenPrice;  // Can overflow again
        require(msg.value >= cost, "Insufficient ETH");

        balances[msg.sender] += total;
    }

    /**
     * @notice Get user's token balance
     */
    function getBalance(address user) public view returns (uint256) {
        return balances[user];
    }
}

/**
 * SECURE VERSION (Solidity 0.8+ with SafeMath or built-in checks):
 *
 * pragma solidity ^0.8.0;  // ✅ Built-in overflow checks
 *
 * // OR for 0.7.x, use SafeMath:
 * import "@openzeppelin/contracts/math/SafeMath.sol";
 *
 * contract SecureTokenSale {
 *     using SafeMath for uint256;
 *
 *     function buyTokens(uint256 amount) public payable {
 *         uint256 cost = amount.mul(tokenPrice);  // ✅ SafeMath prevents overflow
 *         require(msg.value >= cost, "Insufficient ETH sent");
 *         // ... rest of implementation
 *     }
 *
 *     function withdraw(uint256 amount) public {
 *         balances[msg.sender] = balances[msg.sender].sub(amount);  // ✅ SafeMath prevents underflow
 *         // ... rest of implementation
 *     }
 * }
 */

/**
 * EXPECTED MIESC DETECTION:
 *
 * Tool: Slither
 * Detector: integer-overflow
 * Severity: High
 * Confidence: Medium
 * Location: buyTokens() function, line 31
 * Description: "Integer overflow in amount * tokenPrice"
 *
 * Tool: Mythril
 * Detector: SWC-101
 * Severity: High
 * Description: "The arithmetic operation can result in integer overflow"
 *
 * Tool: Solhint
 * Rule: compiler-version
 * Severity: Warning
 * Description: "Use Solidity version ^0.8.0 for automatic overflow checks"
 *
 * AI Correlation Result:
 * - Vulnerability Type: Integer Overflow
 * - Confidence: 0.89
 * - Is False Positive: false
 * - Root Cause: "Unchecked arithmetic operations in Solidity 0.7.0"
 * - Remediation: "Upgrade to Solidity 0.8+ or use SafeMath library"
 * - Priority: 1 (Critical)
 * - Additional Info: "3 overflow points detected: multiplication, subtraction, loop accumulation"
 */
