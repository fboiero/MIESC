// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title Delegatecall Injection
 * @notice Demonstrates delegatecall vulnerabilities
 * @dev Context preservation can be exploited
 */
contract DelegatecallVulnerable {
    address public owner;
    uint256 public value;
    address public library;

    constructor(address _library) {
        owner = msg.sender;
        library = _library;
    }

    /**
     * @notice Execute library function via delegatecall
     * @dev VULNERABLE: User-controlled delegatecall target
     */
    function execute(address target, bytes memory data) public {
        require(msg.sender == owner, "Not owner");

        // VULNERABILITY: Delegatecall to user-controlled address
        // Can overwrite storage slots
        (bool success, ) = target.delegatecall(data);
        require(success, "Delegatecall failed");
    }

    /**
     * @notice Update value via library
     * @dev VULNERABLE: Storage slot collision possible
     */
    function updateValue(uint256 newValue) public {
        // VULNERABILITY: If library has different storage layout,
        // this can overwrite critical variables
        (bool success, ) = library.delegatecall(
            abi.encodeWithSignature("setValue(uint256)", newValue)
        );
        require(success, "Update failed");
    }

    receive() external payable {}
}

/**
 * @title Legitimate Library
 */
contract Library {
    address public owner;  // Storage slot 0
    uint256 public value;  // Storage slot 1

    function setValue(uint256 newValue) public {
        value = newValue;
    }
}

/**
 * @title Malicious Library
 * @notice Exploits storage layout mismatch
 */
contract MaliciousLibrary {
    address public owner;  // Storage slot 0 - matches!

    /**
     * @notice Overwrites owner in delegatecall context
     */
    function setValue(uint256) public {
        // In delegatecall context, this overwrites
        // the CALLER's storage slot 0 (owner)
        owner = msg.sender;
    }

    /**
     * @notice Steals all funds
     */
    function exploit() public {
        // After becoming owner via setValue,
        // can drain funds
    }
}
