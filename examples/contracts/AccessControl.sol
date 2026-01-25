// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title AccessControl - Access Control Vulnerability Examples
 * @dev Demonstrates common access control issues
 */
contract AccessControlVulnerable {
    address public owner;
    mapping(address => uint256) public balances;

    // VULNERABLE: No access control on critical function
    function setOwner(address _newOwner) public {
        owner = _newOwner;
    }

    // VULNERABLE: Using tx.origin instead of msg.sender
    function withdrawAll() public {
        require(tx.origin == owner, "Not owner");
        payable(msg.sender).transfer(address(this).balance);
    }

    // VULNERABLE: Missing zero-address check
    function transferOwnership(address newOwner) public {
        require(msg.sender == owner, "Not owner");
        owner = newOwner; // No check for address(0)
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
}

/**
 * @title AccessControlSecure - Fixed version
 */
contract AccessControlSecure {
    address public owner;
    mapping(address => uint256) public balances;

    event OwnershipTransferred(address indexed previous, address indexed newOwner);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0), "Zero address");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    function withdrawAll() public onlyOwner {
        payable(owner).transfer(address(this).balance);
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
}
