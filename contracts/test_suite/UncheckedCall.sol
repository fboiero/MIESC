// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title UncheckedCall
 * @notice Test contract with UNCHECKED EXTERNAL CALL vulnerabilities
 * @dev For MIESC testing purposes - DO NOT USE IN PRODUCTION
 *
 * Known Vulnerabilities:
 * - SWC-104: Unchecked Call Return Value
 * - SWC-113: DoS with Failed Call
 * - CWE-252: Unchecked Return Value
 * - CWE-703: Improper Check of Exceptional Conditions
 *
 * Expected Detections:
 * - Slither: unchecked-send, unchecked-lowlevel, reentrancy-events
 * - Mythril: SWC-104, SWC-113
 * - Manticore: Failed call path detection
 */
contract UncheckedCall {
    mapping(address => uint256) public balances;
    address[] public recipients;

    event Payment(address indexed to, uint256 amount);
    event BatchPayment(uint256 totalRecipients, uint256 totalAmount);

    /**
     * @notice Deposit Ether
     */
    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    /**
     * @notice Send payment with unchecked send
     * @dev VULNERABLE: Unchecked send return value
     */
    function sendPayment(address payable recipient, uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // VULNERABILITY: send() return value not checked
        recipient.send(amount);

        balances[msg.sender] -= amount;
        emit Payment(recipient, amount);
    }

    /**
     * @notice Send payment with unchecked call
     * @dev VULNERABLE: Unchecked low-level call
     */
    function callPayment(address payable recipient, uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // VULNERABILITY: call() return value not checked
        recipient.call{value: amount}("");

        balances[msg.sender] -= amount;
        emit Payment(recipient, amount);
    }

    /**
     * @notice Batch payment to multiple recipients
     * @dev VULNERABLE: DoS with failed call
     */
    function batchPayment(address payable[] calldata _recipients, uint256 amount) external {
        uint256 totalAmount = _recipients.length * amount;
        require(balances[msg.sender] >= totalAmount, "Insufficient balance");

        // VULNERABILITY: One failed transfer can block all subsequent transfers
        for (uint256 i = 0; i < _recipients.length; i++) {
            // If one transfer fails, entire transaction reverts
            (bool success, ) = _recipients[i].call{value: amount}("");
            require(success, "Transfer failed"); // DoS vulnerability
        }

        balances[msg.sender] -= totalAmount;
        emit BatchPayment(_recipients.length, totalAmount);
    }

    /**
     * @notice Add recipient to list
     * @dev VULNERABLE: Unbounded array growth (DoS)
     */
    function addRecipient(address recipient) external {
        // VULNERABILITY: Unbounded array - can cause DoS
        recipients.push(recipient);
    }

    /**
     * @notice Pay all recipients
     * @dev VULNERABLE: DoS with unbounded loop
     */
    function payAllRecipients(uint256 amount) external {
        uint256 totalAmount = recipients.length * amount;
        require(balances[msg.sender] >= totalAmount, "Insufficient balance");

        // VULNERABILITY: Unbounded loop - gas DoS
        for (uint256 i = 0; i < recipients.length; i++) {
            payable(recipients[i]).transfer(amount);
        }

        balances[msg.sender] -= totalAmount;
    }

    /**
     * @notice External call without gas limit
     * @dev VULNERABLE: Uncontrolled external call
     */
    function externalCall(address target, bytes calldata data) external returns (bool) {
        // VULNERABILITY: No gas limit on external call
        (bool success, ) = target.call(data);
        // VULNERABILITY: Return value checked but no error handling
        return success;
    }

    /**
     * @notice Get number of recipients
     */
    function getRecipientCount() external view returns (uint256) {
        return recipients.length;
    }

    /**
     * @notice Get contract balance
     */
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
