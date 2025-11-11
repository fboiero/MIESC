// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableBank - Reentrancy Vulnerability Demo
 * @notice This contract contains an intentional reentrancy vulnerability for educational purposes
 * @dev DO NOT USE IN PRODUCTION - This is a demonstration of the classic reentrancy attack
 *
 * Vulnerability: CWE-841 (Improper Enforcement of Behavioral Workflow)
 * OWASP SC Top 10: SC01 - Reentrancy
 * SWC-107: Reentrancy
 */
contract VulnerableBank {
    mapping(address => uint256) public balances;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    /**
     * @notice Deposit ETH into the bank
     */
    function deposit() public payable {
        require(msg.value > 0, "Deposit amount must be greater than 0");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /**
     * @notice Withdraw ETH from the bank
     * @dev VULNERABLE: State is updated AFTER external call
     *
     * Attack Vector:
     * 1. Attacker deposits 1 ETH
     * 2. Attacker calls withdraw()
     * 3. Attacker's fallback function recursively calls withdraw()
     * 4. Balance is only updated after all recursive calls complete
     * 5. Attacker drains the contract
     */
    function withdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "Insufficient balance");

        // ❌ VULNERABILITY: External call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // ❌ State update happens AFTER external call
        balances[msg.sender] = 0;

        emit Withdrawal(msg.sender, amount);
    }

    /**
     * @notice Get the contract's total balance
     */
    function getContractBalance() public view returns (uint256) {
        return address(this).balance;
    }

    /**
     * @notice Get a user's balance
     */
    function getBalance(address user) public view returns (uint256) {
        return balances[user];
    }
}

/**
 * SECURE VERSION (Checks-Effects-Interactions Pattern):
 *
 * function withdraw() public {
 *     uint256 amount = balances[msg.sender];
 *     require(amount > 0, "Insufficient balance");
 *
 *     // ✅ Update state BEFORE external call
 *     balances[msg.sender] = 0;
 *
 *     // ✅ External call happens last
 *     (bool success, ) = msg.sender.call{value: amount}("");
 *     require(success, "Transfer failed");
 *
 *     emit Withdrawal(msg.sender, amount);
 * }
 *
 * OR use ReentrancyGuard from OpenZeppelin:
 * import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
 * contract SecureBank is ReentrancyGuard {
 *     function withdraw() public nonReentrant {
 *         // ... implementation
 *     }
 * }
 */

/**
 * EXPECTED MIESC DETECTION:
 *
 * Tool: Slither
 * Detector: reentrancy-eth
 * Severity: High
 * Confidence: High
 * Location: withdraw() function, line 35-47
 * Description: "Reentrancy in VulnerableBank.withdraw() - External call before state change"
 *
 * Tool: Mythril
 * Detector: SWC-107
 * Severity: High
 * Description: "The contract account state is changed after an external call"
 *
 * AI Correlation Result:
 * - Vulnerability Type: Reentrancy
 * - Confidence: 0.95
 * - Is False Positive: false
 * - Root Cause: "State modification after external call in withdraw function"
 * - Remediation: "Apply Checks-Effects-Interactions pattern or use ReentrancyGuard"
 * - Priority: 1 (Critical)
 */
