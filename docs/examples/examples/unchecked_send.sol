// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Unchecked Send Example
 * @notice Demonstrates unchecked external calls
 * @dev Multiple patterns of unchecked calls
 */
contract UncheckedSend {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    /**
     * @notice Withdraw with unchecked send
     * @dev VULNERABLE: send() return value not checked
     */
    function withdrawWithSend(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        balances[msg.sender] -= amount;

        // VULNERABILITY: Return value of send() not checked
        payable(msg.sender).send(amount);
    }

    /**
     * @notice Withdraw with unchecked call
     * @dev VULNERABLE: call() return value not checked
     */
    function withdrawWithCall(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        balances[msg.sender] -= amount;

        // VULNERABILITY: Return value of call() not checked
        payable(msg.sender).call{value: amount}("");
    }

    /**
     * @notice Batch payout
     * @dev VULNERABLE: Multiple unchecked sends in loop
     */
    function batchPayout(address payable[] memory recipients, uint256 amount) public {
        require(msg.sender == owner, "Only owner");

        for (uint256 i = 0; i < recipients.length; i++) {
            // VULNERABILITY: send() failures silently ignored
            recipients[i].send(amount);
        }
    }

    /**
     * @notice Emergency withdraw
     * @dev VULNERABLE: delegatecall return not checked
     */
    function emergencyWithdraw(address target, bytes memory data) public {
        require(msg.sender == owner, "Only owner");

        // VULNERABILITY: delegatecall return value not checked
        target.delegatecall(data);
    }

    receive() external payable {
        deposit();
    }
}
