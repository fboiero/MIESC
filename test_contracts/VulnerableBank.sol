// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableBank
 * @dev Contract with intentional reentrancy vulnerability for testing MIESC
 */
contract VulnerableBank {
    mapping(address => uint256) public balances;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    /**
     * @dev Deposit ETH into the bank
     */
    function deposit() public payable {
        require(msg.value > 0, "Must deposit something");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /**
     * @dev VULNERABLE: Withdraw funds - has reentrancy vulnerability
     * The balance is updated AFTER the external call
     */
    function withdraw() public {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "Insufficient balance");

        // VULNERABILITY: External call before state update
        // An attacker can re-enter this function before balance is set to 0
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");

        // BUG: State change happens after external call
        balances[msg.sender] = 0;
        emit Withdrawal(msg.sender, balance);
    }

    /**
     * @dev Get contract balance
     */
    function getContractBalance() public view returns (uint256) {
        return address(this).balance;
    }
}

/**
 * @title SecureBank
 * @dev Correct implementation using checks-effects-interactions pattern
 */
contract SecureBank {
    mapping(address => uint256) public balances;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    function deposit() public payable {
        require(msg.value > 0, "Must deposit something");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /**
     * @dev SECURE: State is updated before external call
     */
    function withdraw() public {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "Insufficient balance");

        // CORRECT: State change before external call
        balances[msg.sender] = 0;
        emit Withdrawal(msg.sender, balance);

        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");
    }

    function getContractBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
