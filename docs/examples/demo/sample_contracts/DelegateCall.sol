// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Proxy - Unsafe Delegatecall Vulnerability Demo
 * @notice This contract contains intentional delegatecall vulnerabilities for educational purposes
 * @dev DO NOT USE IN PRODUCTION - Demonstrates delegatecall storage collision and access control bypass
 *
 * Vulnerability: CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)
 * OWASP SC Top 10: SC02 - Access Control
 * SWC-112: Delegatecall to Untrusted Callee
 */

/**
 * @title Library contract (malicious example)
 */
contract Library {
    address public owner;  // Storage slot 0
    uint256 public value;  // Storage slot 1

    function setValue(uint256 _value) public {
        value = _value;
    }
}

/**
 * @title Proxy contract with delegatecall vulnerability
 */
contract Proxy {
    address public owner;        // Storage slot 0
    address public libraryAddress;  // Storage slot 1

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice Set the library address
     * @dev Only owner can change library
     */
    function setLibrary(address _library) public {
        require(msg.sender == owner, "Only owner");
        libraryAddress = _library;
    }

    /**
     * @notice Forward calls to library using delegatecall
     * @dev VULNERABLE: Allows arbitrary delegatecall without proper validation
     *
     * Attack Vector 1 (Storage Collision):
     * 1. Attacker deploys malicious Library contract
     * 2. Malicious Library.setValue() writes to storage slot 0 (owner variable)
     * 3. Attacker calls Proxy.forward() → delegatecall → overwrites owner
     * 4. Attacker gains ownership of Proxy contract
     *
     * Attack Vector 2 (Arbitrary Code Execution):
     * 1. Attacker can call any function in libraryAddress
     * 2. No validation of function signatures
     * 3. Can execute selfdestruct, transfer ownership, drain funds
     */
    function forward(bytes memory data) public returns (bytes memory) {
        // ❌ VULNERABILITY: Unsafe delegatecall to user-controlled address
        (bool success, bytes memory result) = libraryAddress.delegatecall(data);
        require(success, "Delegatecall failed");
        return result;
    }

    /**
     * @notice Alternative vulnerable pattern - direct delegatecall
     * @param target Target contract address
     * @param data Calldata to forward
     */
    function execute(address target, bytes memory data) public returns (bytes memory) {
        // ❌ VULNERABILITY: Allows delegatecall to arbitrary address
        require(msg.sender == owner, "Only owner");

        (bool success, bytes memory result) = target.delegatecall(data);
        require(success, "Execution failed");

        return result;
    }

    /**
     * @notice Receive ETH
     */
    receive() external payable {}

    /**
     * @notice Get contract balance
     */
    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}

/**
 * @title Malicious Library for attack demonstration
 */
contract MaliciousLibrary {
    address public owner;  // Storage slot 0 - same as Proxy.owner

    /**
     * @notice Malicious function that overwrites owner
     */
    function becomeOwner() public {
        // When called via delegatecall, this writes to Proxy's storage slot 0
        owner = msg.sender;  // ❌ Overwrites Proxy.owner
    }

    /**
     * @notice Drain the proxy contract
     */
    function drain() public {
        // When called via delegatecall, executes in Proxy's context
        selfdestruct(payable(msg.sender));  // ❌ Destroys Proxy and sends funds
    }
}

/**
 * SECURE VERSION:
 *
 * contract SecureProxy {
 *     address public owner;
 *     address public immutable libraryAddress;  // ✅ Immutable, set in constructor
 *
 *     // ✅ Whitelist of allowed function selectors
 *     mapping(bytes4 => bool) public allowedFunctions;
 *
 *     constructor(address _library, bytes4[] memory _allowedFunctions) {
 *         owner = msg.sender;
 *         libraryAddress = _library;  // ✅ Fixed at deployment
 *
 *         for (uint i = 0; i < _allowedFunctions.length; i++) {
 *             allowedFunctions[_allowedFunctions[i]] = true;
 *         }
 *     }
 *
 *     function forward(bytes memory data) public returns (bytes memory) {
 *         bytes4 selector = bytes4(data);
 *         require(allowedFunctions[selector], "Function not allowed");  // ✅ Validate function
 *
 *         (bool success, bytes memory result) = libraryAddress.delegatecall(data);
 *         require(success, "Delegatecall failed");
 *         return result;
 *     }
 *
 *     // ✅ Better: Use EIP-1967 transparent proxy pattern
 *     // ✅ Or: Use OpenZeppelin's proxy contracts
 * }
 */

/**
 * EXPECTED MIESC DETECTION:
 *
 * Tool: Slither
 * Detector: controlled-delegatecall
 * Severity: High
 * Confidence: High
 * Location: forward() function, line 64-68
 * Description: "Delegatecall to user-supplied address in Proxy.forward()"
 *
 * Tool: Mythril
 * Detector: SWC-112
 * Severity: High
 * Description: "The contract delegates execution to another contract with a user-supplied address"
 *
 * Tool: Slither
 * Detector: suicidal
 * Severity: High
 * Location: MaliciousLibrary.drain()
 * Description: "MaliciousLibrary.drain() allows anyone to destruct the contract"
 *
 * AI Correlation Result:
 * - Vulnerability Type: Unsafe Delegatecall
 * - Confidence: 0.92
 * - Is False Positive: false
 * - Root Cause: "Delegatecall to user-controlled address without proper validation"
 * - Remediation: "Use immutable library address, whitelist function selectors, or implement EIP-1967 proxy pattern"
 * - Priority: 1 (Critical)
 * - Related Vulnerabilities:
 *   - Storage collision (CWE-123)
 *   - Access control bypass (CWE-284)
 *   - Arbitrary code execution (CWE-94)
 */
