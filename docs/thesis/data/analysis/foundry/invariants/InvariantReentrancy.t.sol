// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../../../src/contracts/vulnerable/reentrancy/BasicReentrancy.sol";

/**
 * @title InvariantReentrancy
 * @notice Invariant tests for reentrancy vulnerability detection
 * @dev Tests invariants that should hold but are violated by reentrancy
 */
contract InvariantReentrancy is Test {
    BasicReentrancy public vault;
    Handler public handler;

    function setUp() public {
        vault = new BasicReentrancy();
        handler = new Handler(vault);

        // Fund handler for testing
        vm.deal(address(handler), 100 ether);

        // Target handler for invariant testing
        targetContract(address(handler));

        // Exclude vault from msg.sender randomization
        excludeSender(address(vault));
    }

    /// @notice Invariant: Contract balance should equal sum of all user balances
    /// @dev This invariant is violated by reentrancy attacks
    function invariant_balanceConsistency() public view {
        uint256 totalBalances = handler.ghost_totalDeposited() - handler.ghost_totalWithdrawn();
        uint256 contractBalance = address(vault).balance;

        assertEq(
            contractBalance,
            totalBalances,
            "Contract balance should equal tracked balances"
        );
    }

    /// @notice Invariant: Individual balance should never exceed deposits
    /// @dev Reentrancy can violate this by withdrawing more than deposited
    function invariant_noOverWithdrawal() public view {
        address[] memory users = handler.getUsers();

        for (uint256 i = 0; i < users.length; i++) {
            address user = users[i];
            uint256 deposited = handler.getUserDeposited(user);
            uint256 withdrawn = handler.getUserWithdrawn(user);

            assertLe(
                withdrawn,
                deposited,
                "User should not withdraw more than deposited"
            );
        }
    }

    /// @notice Invariant: Balance should never go negative (underflow)
    /// @dev Checks for integer underflow vulnerabilities
    function invariant_noNegativeBalance() public view {
        address[] memory users = handler.getUsers();

        for (uint256 i = 0; i < users.length; i++) {
            address user = users[i];
            uint256 balance = vault.balances(user);

            // In Solidity 0.8+, underflow would revert, but we check consistency
            uint256 deposited = handler.getUserDeposited(user);
            uint256 withdrawn = handler.getUserWithdrawn(user);

            assertEq(
                balance,
                deposited - withdrawn,
                "Balance should equal deposits minus withdrawals"
            );
        }
    }

    /// @notice Invariant: Total withdrawn should never exceed total deposited
    /// @dev This is violated by reentrancy draining the contract
    function invariant_totalWithdrawalLimit() public view {
        uint256 totalDeposited = handler.ghost_totalDeposited();
        uint256 totalWithdrawn = handler.ghost_totalWithdrawn();

        assertLe(
            totalWithdrawn,
            totalDeposited,
            "Total withdrawn should not exceed total deposited"
        );
    }

    /// @notice Invariant: Contract should always be solvent
    /// @dev Contract balance + pending withdrawals >= user balances
    function invariant_solvency() public view {
        uint256 contractBalance = address(vault).balance;
        uint256 totalUserBalances = 0;

        address[] memory users = handler.getUsers();
        for (uint256 i = 0; i < users.length; i++) {
            totalUserBalances += vault.balances(users[i]);
        }

        assertGe(
            contractBalance,
            totalUserBalances,
            "Contract must have sufficient funds for all balances"
        );
    }
}

/**
 * @title Handler
 * @notice Handler contract for invariant testing
 * @dev Performs random actions and tracks state for invariant checks
 */
contract Handler is Test {
    BasicReentrancy public vault;

    // Ghost variables for tracking
    uint256 public ghost_totalDeposited;
    uint256 public ghost_totalWithdrawn;
    uint256 public ghost_depositCount;
    uint256 public ghost_withdrawCount;

    // Track users
    address[] public users;
    mapping(address => bool) public isUser;
    mapping(address => uint256) public userDeposited;
    mapping(address => uint256) public userWithdrawn;

    constructor(BasicReentrancy _vault) {
        vault = _vault;
    }

    /// @notice Random deposit action
    function deposit(uint256 amount) public {
        // Bound amount to reasonable values
        amount = bound(amount, 0.01 ether, 10 ether);

        // Ensure handler has funds
        vm.deal(address(this), amount);

        // Track user
        if (!isUser[address(this)]) {
            users.push(address(this));
            isUser[address(this)] = true;
        }

        // Perform deposit
        vault.deposit{value: amount}();

        // Update ghost variables
        ghost_totalDeposited += amount;
        ghost_depositCount++;
        userDeposited[address(this)] += amount;
    }

    /// @notice Random withdraw action
    function withdraw(uint256 amount) public {
        uint256 balance = vault.balances(address(this));

        // Only withdraw if we have balance
        if (balance == 0) return;

        // Bound amount to available balance
        amount = bound(amount, 0, balance);

        // Perform withdrawal
        try vault.withdraw(amount) {
            // Update ghost variables
            ghost_totalWithdrawn += amount;
            ghost_withdrawCount++;
            userWithdrawn[address(this)] += amount;
        } catch {
            // Withdrawal failed (expected in some cases)
        }
    }

    /// @notice Get list of users
    function getUsers() external view returns (address[] memory) {
        return users;
    }

    /// @notice Get user deposited amount
    function getUserDeposited(address user) external view returns (uint256) {
        return userDeposited[user];
    }

    /// @notice Get user withdrawn amount
    function getUserWithdrawn(address user) external view returns (uint256) {
        return userWithdrawn[user];
    }

    /// @notice Required to receive ETH from vault
    receive() external payable {}
}
