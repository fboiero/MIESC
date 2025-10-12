// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Secure Bank Contract
 * @notice Example of properly secured contract following best practices
 * @dev Demonstrates fixes for common vulnerabilities
 *
 * Security Features:
 * 1. ✅ Reentrancy protection
 * 2. ✅ Access control with Ownable pattern
 * 3. ✅ Checks-Effects-Interactions pattern
 * 4. ✅ Safe external calls
 * 5. ✅ Input validation
 * 6. ✅ Event emission
 */
contract SecureBank {
    /// @notice User balances
    mapping(address => uint256) public balances;

    /// @notice Contract owner
    address public owner;

    /// @notice Reentrancy lock
    bool private locked;

    /// @notice Events for transparency
    event Deposit(address indexed user, uint256 amount, uint256 timestamp);
    event Withdrawal(address indexed user, uint256 amount, uint256 timestamp);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event EmergencyWithdrawal(address indexed recipient, uint256 amount);

    /// @notice Custom errors (gas efficient)
    error Unauthorized();
    error InsufficientBalance();
    error TransferFailed();
    error ReentrancyGuard();
    error ZeroAmount();
    error ZeroAddress();

    /**
     * @notice Initialize contract
     */
    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    /**
     * @notice Restrict function to owner
     */
    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    /**
     * @notice Reentrancy guard
     */
    modifier nonReentrant() {
        if (locked) revert ReentrancyGuard();
        locked = true;
        _;
        locked = false;
    }

    /**
     * @notice Deposit funds into the bank
     * @dev Validates input and emits event
     */
    function deposit() public payable {
        if (msg.value == 0) revert ZeroAmount();

        // Update state BEFORE any external interactions
        balances[msg.sender] += msg.value;

        emit Deposit(msg.sender, msg.value, block.timestamp);
    }

    /**
     * @notice Withdraw funds from the bank
     * @dev Protected against reentrancy, follows Checks-Effects-Interactions
     */
    function withdraw() public nonReentrant {
        uint256 balance = balances[msg.sender];

        // CHECKS
        if (balance == 0) revert InsufficientBalance();

        // EFFECTS (update state BEFORE external call)
        balances[msg.sender] = 0;

        // INTERACTIONS (external call comes last)
        (bool success, ) = msg.sender.call{value: balance}("");
        if (!success) revert TransferFailed();

        emit Withdrawal(msg.sender, balance, block.timestamp);
    }

    /**
     * @notice Withdraw specific amount
     * @param amount Amount to withdraw
     * @dev Allows partial withdrawals
     */
    function withdrawAmount(uint256 amount) public nonReentrant {
        if (amount == 0) revert ZeroAmount();

        uint256 balance = balances[msg.sender];
        if (balance < amount) revert InsufficientBalance();

        // CHECKS-EFFECTS-INTERACTIONS
        balances[msg.sender] -= amount;

        (bool success, ) = msg.sender.call{value: amount}("");
        if (!success) revert TransferFailed();

        emit Withdrawal(msg.sender, amount, block.timestamp);
    }

    /**
     * @notice Transfer ownership
     * @param newOwner Address of new owner
     * @dev Protected by onlyOwner modifier
     */
    function transferOwnership(address newOwner) public onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();

        address previousOwner = owner;
        owner = newOwner;

        emit OwnershipTransferred(previousOwner, newOwner);
    }

    /**
     * @notice Emergency withdrawal by owner
     * @param recipient Recipient address
     * @param amount Amount to withdraw
     * @dev Properly checks return value and uses reentrancy guard
     */
    function emergencyWithdraw(address payable recipient, uint256 amount)
        public
        onlyOwner
        nonReentrant
    {
        if (recipient == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();
        if (amount > address(this).balance) revert InsufficientBalance();

        // Safe external call with checked return value
        (bool success, ) = recipient.call{value: amount}("");
        if (!success) revert TransferFailed();

        emit EmergencyWithdrawal(recipient, amount);
    }

    /**
     * @notice Get balance of user
     * @param user Address to query
     * @return User balance
     */
    function getBalance(address user) public view returns (uint256) {
        return balances[user];
    }

    /**
     * @notice Get contract total balance
     * @return Total contract balance
     */
    function getTotalBalance() public view returns (uint256) {
        return address(this).balance;
    }

    /**
     * @notice Check if caller is owner
     * @return True if caller is owner
     */
    function isOwner() public view returns (bool) {
        return msg.sender == owner;
    }

    /**
     * @notice Receive function for direct ETH transfers
     */
    receive() external payable {
        deposit();
    }

    /**
     * @notice Fallback function
     */
    fallback() external payable {
        deposit();
    }
}
