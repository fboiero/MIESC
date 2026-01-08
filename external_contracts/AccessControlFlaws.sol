// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title AccessControlFlaws - Multiple Access Control Vulnerabilities
 * @dev Common patterns from real exploits
 */
contract AccessControlFlaws {
    address public owner;
    address public pendingOwner;
    mapping(address => bool) public admins;
    mapping(address => uint256) public balances;

    bool private initialized;

    // VULNERABILITY 1: Unprotected initializer
    function initialize(address _owner) public {
        // BUG: Can be called multiple times!
        owner = _owner;
        admins[_owner] = true;
    }

    // VULNERABILITY 2: tx.origin authentication
    function withdrawTo(address _to, uint256 _amount) public {
        // BUG: tx.origin can be manipulated via phishing
        require(tx.origin == owner, "Not owner");
        payable(_to).transfer(_amount);
    }

    // VULNERABILITY 3: Missing zero address check
    function transferOwnership(address _newOwner) public {
        require(msg.sender == owner, "Not owner");
        // BUG: No check for address(0)
        owner = _newOwner;
    }

    // VULNERABILITY 4: Dangerous selfdestruct
    function emergencyDestroy() public {
        // BUG: Missing access control!
        selfdestruct(payable(msg.sender));
    }

    // VULNERABILITY 5: Front-running susceptible
    function claimReward(bytes32 _secret) public {
        // BUG: Secret visible in mempool
        require(keccak256(abi.encodePacked(_secret)) ==
                0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef);
        balances[msg.sender] += 100 ether;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
}

/**
 * @title ProxyVulnerable - Unsafe Proxy Pattern
 */
contract ProxyVulnerable {
    address public implementation;
    address public admin;

    // VULNERABILITY: Storage collision in proxy
    // First slot used by both proxy and implementation

    constructor(address _impl) {
        implementation = _impl;
        admin = msg.sender;
    }

    // VULNERABILITY: Unprotected upgrade
    function upgrade(address _newImpl) public {
        // BUG: Anyone can upgrade!
        implementation = _newImpl;
    }

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
}
