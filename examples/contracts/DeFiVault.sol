// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title DeFiVault - Multiple Vulnerability Example
 * @dev Contains multiple security issues for comprehensive testing
 */
contract DeFiVault {
    address public owner;
    uint256 public totalDeposits;
    mapping(address => uint256) public deposits;
    mapping(address => uint256) public lastWithdraw;

    uint256 public constant WITHDRAW_DELAY = 1 days;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    function deposit() public payable {
        require(msg.value > 0, "Zero deposit");
        deposits[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    // VULNERABILITY 1: Reentrancy
    // VULNERABILITY 2: No withdrawal delay enforcement
    function withdraw(uint256 amount) public {
        require(deposits[msg.sender] >= amount, "Insufficient balance");
        // Missing: require(block.timestamp >= lastWithdraw[msg.sender] + WITHDRAW_DELAY);

        // External call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        deposits[msg.sender] -= amount;
        totalDeposits -= amount;
        lastWithdraw[msg.sender] = block.timestamp;

        emit Withdrawal(msg.sender, amount);
    }

    // VULNERABILITY 3: Integer overflow potential in old Solidity
    // (Safe in 0.8+ but pattern shows bad practice)
    function addBonus(address user, uint256 bonus) public {
        require(msg.sender == owner, "Not owner");
        deposits[user] = deposits[user] + bonus;
    }

    // VULNERABILITY 4: Unchecked return value
    function emergencyWithdraw() public {
        require(msg.sender == owner, "Not owner");
        // Missing success check
        payable(owner).send(address(this).balance);
    }

    // VULNERABILITY 5: Block timestamp dependence
    function isWithdrawAllowed(address user) public view returns (bool) {
        return block.timestamp >= lastWithdraw[user] + WITHDRAW_DELAY;
    }

    function getContractBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
