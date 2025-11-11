// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title AccessControl
 * @notice Test contract with ACCESS CONTROL vulnerabilities
 * @dev For MIESC testing purposes - DO NOT USE IN PRODUCTION
 *
 * Known Vulnerabilities:
 * - SWC-105: Unprotected Ether Withdrawal
 * - SWC-106: Unprotected SELFDESTRUCT Instruction
 * - CWE-284: Improper Access Control
 * - CWE-862: Missing Authorization
 *
 * Expected Detections:
 * - Slither: suicidal, arbitrary-send-eth, missing-zero-check
 * - Mythril: SWC-105, SWC-106
 * - Aderyn: Missing access control modifiers
 */
contract AccessControl {
    address public owner;
    mapping(address => bool) public admins;
    mapping(address => uint256) public balances;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event AdminAdded(address indexed admin);
    event Withdrawal(address indexed user, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice Deposit Ether
     */
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /**
     * @notice Transfer ownership
     * @dev VULNERABLE: Missing zero address check
     */
    function transferOwnership(address newOwner) external {
        require(msg.sender == owner, "Not owner");
        // VULNERABILITY: No zero address check
        address previousOwner = owner;
        owner = newOwner;
        emit OwnershipTransferred(previousOwner, newOwner);
    }

    /**
     * @notice Add admin
     * @dev VULNERABLE: tx.origin authentication
     */
    function addAdmin(address admin) external {
        // VULNERABILITY: Uses tx.origin instead of msg.sender
        require(tx.origin == owner, "Not owner");
        admins[admin] = true;
        emit AdminAdded(admin);
    }

    /**
     * @notice Withdraw Ether
     * @dev VULNERABLE: No access control
     */
    function withdraw(uint256 amount) external {
        // VULNERABILITY: Missing access control - anyone can call
        require(address(this).balance >= amount, "Insufficient contract balance");
        payable(msg.sender).transfer(amount);
        emit Withdrawal(msg.sender, amount);
    }

    /**
     * @notice Emergency withdraw all funds
     * @dev VULNERABLE: Weak access control (only checks if admin exists)
     */
    function emergencyWithdraw() external {
        // VULNERABILITY: Checks if sender is in admins mapping, but doesn't check if true
        require(admins[msg.sender] == true || msg.sender == owner, "Not authorized");
        payable(msg.sender).transfer(address(this).balance);
    }

    /**
     * @notice Destroy contract
     * @dev VULNERABLE: Unprotected selfdestruct
     */
    function destroy() external {
        // VULNERABILITY: No access control on selfdestruct
        selfdestruct(payable(msg.sender));
    }

    /**
     * @notice Delegated call to arbitrary address
     * @dev VULNERABLE: Unchecked delegatecall
     */
    function delegateCall(address target, bytes calldata data) external returns (bool) {
        // VULNERABILITY: Arbitrary delegatecall without validation
        (bool success, ) = target.delegatecall(data);
        return success;
    }

    /**
     * @notice Get contract balance
     */
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
