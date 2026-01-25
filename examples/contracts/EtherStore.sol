// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title EtherStore - Classic Reentrancy Vulnerable Contract
 * @dev Based on real-world vulnerability patterns
 * Source: Adapted from common DeFi vulnerability examples
 */
contract EtherStore {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABLE: Classic reentrancy vulnerability
    function withdraw() public {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "Insufficient balance");

        // External call before state update - VULNERABLE
        (bool sent, ) = msg.sender.call{value: bal}("");
        require(sent, "Failed to send Ether");

        // State update after external call - TOO LATE
        balances[msg.sender] = 0;
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}

/**
 * @title EtherStoreSecure - Fixed version
 */
contract EtherStoreSecure {
    mapping(address => uint256) public balances;
    bool private locked;

    modifier noReentrant() {
        require(!locked, "Locked");
        locked = true;
        _;
        locked = false;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // SECURE: Uses checks-effects-interactions + reentrancy guard
    function withdraw() public noReentrant {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "Insufficient balance");

        // State update BEFORE external call
        balances[msg.sender] = 0;

        (bool sent, ) = msg.sender.call{value: bal}("");
        require(sent, "Failed to send Ether");
    }
}
