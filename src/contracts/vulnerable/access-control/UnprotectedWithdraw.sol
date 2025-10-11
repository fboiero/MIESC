// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

/// @title UnprotectedWithdraw - Vulnerable to SWC-105
/// @notice Missing access control on critical function
/// @dev DO NOT USE IN PRODUCTION
contract UnprotectedWithdraw {
    address public owner;
    mapping(address => uint256) public balances;

    event Deposit(address indexed user, uint256 amount);
    event Withdraw(address indexed to, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /// @notice VULNERABLE: Missing onlyOwner modifier
    /// @dev Anyone can drain the contract
    function withdrawAll(address payable to) external {
        uint256 amount = address(this).balance;
        (bool success, ) = to.call{value: amount}("");
        require(success, "Transfer failed");
        emit Withdraw(to, amount);
    }

    /// @notice Properly protected function (for comparison)
    function emergencyWithdraw() external {
        require(msg.sender == owner, "Only owner");
        payable(owner).transfer(address(this).balance);
    }
}
