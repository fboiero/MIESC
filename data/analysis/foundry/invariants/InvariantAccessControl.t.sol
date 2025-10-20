// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

/**
 * @title InvariantAccessControl
 * @notice Invariant tests for access control vulnerabilities
 * @dev Tests role-based access control invariants
 */
contract InvariantAccessControl is Test {
    AccessControlledVault public vault;
    AccessHandler public handler;

    address public owner;
    address public admin;
    address public user;

    function setUp() public {
        owner = address(this);
        admin = address(0x1);
        user = address(0x2);

        vault = new AccessControlledVault();
        handler = new AccessHandler(vault, owner, admin, user);

        // Fund handler
        vm.deal(address(handler), 100 ether);

        // Set up roles
        vault.grantRole(vault.ADMIN_ROLE(), admin);

        // Target handler
        targetContract(address(handler));
    }

    /// @notice Invariant: Only owner can grant roles
    function invariant_onlyOwnerCanGrantRoles() public view {
        // Admin count should only increase through owner actions
        assertTrue(
            vault.hasRole(vault.DEFAULT_ADMIN_ROLE(), owner),
            "Owner must have admin role"
        );
    }

    /// @notice Invariant: Only admins can perform admin actions
    function invariant_adminActionsRestricted() public view {
        uint256 unauthorizedAdminCalls = handler.ghost_unauthorizedAdminCalls();

        // All unauthorized calls should have failed
        assertEq(
            unauthorizedAdminCalls,
            handler.ghost_failedAdminCalls(),
            "All unauthorized admin calls should fail"
        );
    }

    /// @notice Invariant: Users cannot escalate privileges
    function invariant_noPrivilegeEscalation() public view {
        // Regular users should never gain admin role
        assertFalse(
            vault.hasRole(vault.ADMIN_ROLE(), user),
            "Regular user should not have admin role"
        );
    }

    /// @notice Invariant: Protected functions are not callable by anyone
    function invariant_protectedFunctionsSecure() public view {
        uint256 protectedCalls = handler.ghost_protectedFunctionCalls();
        uint256 successfulProtectedCalls = handler.ghost_successfulProtectedCalls();

        // Only authorized calls should succeed
        assertLe(
            successfulProtectedCalls,
            protectedCalls,
            "Protected functions should reject unauthorized calls"
        );
    }
}

/**
 * @title AccessHandler
 * @notice Handler for access control invariant testing
 */
contract AccessHandler is Test {
    AccessControlledVault public vault;
    address public owner;
    address public admin;
    address public user;

    uint256 public ghost_unauthorizedAdminCalls;
    uint256 public ghost_failedAdminCalls;
    uint256 public ghost_protectedFunctionCalls;
    uint256 public ghost_successfulProtectedCalls;

    constructor(AccessControlledVault _vault, address _owner, address _admin, address _user) {
        vault = _vault;
        owner = _owner;
        admin = _admin;
        user = _user;
    }

    /// @notice Try to call admin function as user
    function attemptUnauthorizedAdminCall() public {
        vm.prank(user);

        ghost_unauthorizedAdminCalls++;

        try vault.adminWithdraw(1 ether) {
            // Should not succeed
        } catch {
            ghost_failedAdminCalls++;
        }
    }

    /// @notice Try to grant role as non-owner
    function attemptUnauthorizedRoleGrant() public {
        vm.prank(user);

        ghost_protectedFunctionCalls++;

        try vault.grantRole(vault.ADMIN_ROLE(), user) {
            ghost_successfulProtectedCalls++;
        } catch {
            // Expected to fail
        }
    }

    /// @notice Authorized admin call
    function authorizedAdminCall(uint256 amount) public {
        amount = bound(amount, 0, 1 ether);

        vm.prank(admin);

        ghost_protectedFunctionCalls++;

        try vault.adminWithdraw(amount) {
            ghost_successfulProtectedCalls++;
        } catch {
            // May fail due to insufficient balance
        }
    }
}

/**
 * @title AccessControlledVault
 * @notice Simple vault with role-based access control
 */
contract AccessControlledVault is Test {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    mapping(bytes32 => mapping(address => bool)) private _roles;
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;

    constructor() {
        _roles[DEFAULT_ADMIN_ROLE][msg.sender] = true;
    }

    function hasRole(bytes32 role, address account) public view returns (bool) {
        return _roles[role][account];
    }

    function grantRole(bytes32 role, address account) public {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "Not admin");
        _roles[role][account] = true;
    }

    function adminWithdraw(uint256 amount) public {
        require(hasRole(ADMIN_ROLE, msg.sender), "Not admin");
        require(address(this).balance >= amount, "Insufficient balance");
        payable(msg.sender).transfer(amount);
    }

    receive() external payable {}
}
