// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableProxy
 * @dev A deliberately vulnerable contract for testing the delegatecall detector.
 *      DO NOT use this contract in production!
 */
contract VulnerableProxy {
    address public implementation;
    address public owner;
    uint256 public value;

    constructor(address _implementation) {
        implementation = _implementation;
        owner = msg.sender;
    }

    // VULNERABILITY 1: Delegatecall to user-supplied address
    // Critical: Attacker can pass any address and execute arbitrary code
    function executeOnAddress(address target, bytes memory data) public returns (bytes memory) {
        (bool success, bytes memory result) = target.delegatecall(data);
        require(success, "Delegatecall failed");
        return result;
    }

    // VULNERABILITY 2: Unprotected delegatecall
    // Anyone can call this and potentially change storage
    function forward(bytes memory data) external returns (bytes memory) {
        (bool success, bytes memory result) = implementation.delegatecall(data);
        require(success, "Forward failed");
        return result;
    }

    // SAFE: Protected delegatecall with onlyOwner
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function safeForward(bytes memory data) external onlyOwner returns (bytes memory) {
        (bool success, bytes memory result) = implementation.delegatecall(data);
        require(success, "Forward failed");
        return result;
    }

    // VULNERABILITY 3: Delegatecall with encoded data
    function callWithSelector(bytes4 selector, address account) public {
        implementation.delegatecall(abi.encodeWithSelector(selector, account));
    }

    // Fallback that forwards calls (common proxy pattern)
    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}
