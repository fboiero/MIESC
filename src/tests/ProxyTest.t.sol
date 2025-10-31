// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../contracts/vulnerable/proxy/UninitializedProxy.sol";
import "../contracts/vulnerable/proxy/DelegateCallVuln.sol";

/// @title ProxyTest - Tests for proxy vulnerabilities
contract ProxyTest is Test {
    VaultImplementation public implementation;
    ProxyFactory public factory;
    ProxyAttacker public attacker;

    address user = address(0x1);
    address malicious = address(0x2);

    function setUp() public {
        implementation = new VaultImplementation();
        factory = new ProxyFactory();
        attacker = new ProxyAttacker();

        vm.deal(user, 100 ether);
        vm.deal(malicious, 10 ether);
    }

    /// @notice Test uninitialized proxy vulnerability
    function testUninitializedProxyExploit() public {
        // User creates proxy (without initializing)
        vm.prank(user);
        address proxy = factory.createProxy(address(implementation));

        // Verify proxy is uninitialized
        VaultImplementation vaultProxy = VaultImplementation(proxy);
        assertEq(vaultProxy.owner(), address(0));
        assertFalse(vaultProxy.initialized());

        // Attacker frontruns and initializes with their address
        vm.prank(malicious);
        attacker.exploit(proxy);

        // Attacker now owns the proxy!
        assertEq(vaultProxy.owner(), address(attacker));
        assertTrue(vaultProxy.initialized());

        // User deposits funds (thinking they own it)
        vm.prank(user);
        vaultProxy.deposit{value: 5 ether}();

        // Attacker can drain
        vm.prank(malicious);
        attacker.drain(proxy);

        assertEq(address(proxy).balance, 0);
        assertGt(address(attacker).balance, 5 ether);

        console.log("Attacker successfully took ownership and drained funds");
    }

    /// @notice Test proper initialization prevents exploit
    function testProperInitialization() public {
        vm.startPrank(user);
        address proxy = factory.createProxy(address(implementation));

        // Immediately initialize
        VaultImplementation(proxy).initialize(user);

        assertEq(VaultImplementation(proxy).owner(), user);
        vm.stopPrank();

        // Attacker cannot re-initialize
        vm.prank(malicious);
        vm.expectRevert("Already initialized");
        VaultImplementation(proxy).initialize(malicious);
    }
}

/// @title DelegateCallTest - Tests for delegatecall vulnerabilities
contract DelegateCallTest is Test {
    VulnerableProxy public proxy;
    MaliciousLibrary public malicious;
    ProxyExploiter public exploiter;

    address owner = address(0x1);

    function setUp() public {
        vm.prank(owner);
        proxy = new VulnerableProxy(address(0));

        malicious = new MaliciousLibrary();
        exploiter = new ProxyExploiter(address(proxy));

        vm.deal(address(proxy), 10 ether);
    }

    /// @notice Test delegatecall storage collision attack
    function testDelegateCallStorageCollision() public {
        address originalOwner = proxy.owner();
        assertEq(originalOwner, owner);

        // Execute exploit
        exploiter.exploit();

        // Ownership changed due to storage collision!
        address newOwner = proxy.owner();
        assertEq(newOwner, address(exploiter));
        assertNotEq(newOwner, originalOwner);

        // Funds drained
        assertEq(address(proxy).balance, 0);

        console.log("Original owner:", originalOwner);
        console.log("New owner (exploiter):", newOwner);
        console.log("Exploit successful via delegatecall storage collision");
    }

    /// @notice Fuzz test: Only owner should update implementation
    function testFuzz_OnlyOwnerCanUpdateImplementation(address caller, address newImpl) public {
        vm.assume(caller != owner);
        vm.assume(newImpl != address(0));

        vm.prank(caller);
        vm.expectRevert("Not owner");
        proxy.updateImplementation(newImpl);
    }
}
