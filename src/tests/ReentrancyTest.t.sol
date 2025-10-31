// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../contracts/vulnerable/reentrancy/BasicReentrancy.sol";

/// @title ReentrancyTest - Foundry tests for reentrancy vulnerability
contract ReentrancyTest is Test {
    BasicReentrancy public victim;
    ReentrancyAttacker public attacker;

    address user1 = address(0x1);
    address user2 = address(0x2);

    function setUp() public {
        victim = new BasicReentrancy();
        attacker = new ReentrancyAttacker(address(victim));

        // Fund users
        vm.deal(user1, 100 ether);
        vm.deal(user2, 100 ether);
        vm.deal(address(attacker), 10 ether);
    }

    /// @notice Test normal deposit functionality
    function testDeposit() public {
        vm.prank(user1);
        victim.deposit{value: 1 ether}();

        assertEq(victim.balances(user1), 1 ether);
        assertEq(address(victim).balance, 1 ether);
    }

    /// @notice Test normal withdrawal
    function testWithdraw() public {
        vm.prank(user1);
        victim.deposit{value: 1 ether}();

        vm.prank(user1);
        victim.withdraw(0.5 ether);

        assertEq(victim.balances(user1), 0.5 ether);
    }

    /// @notice Test reentrancy attack
    function testReentrancyAttack() public {
        // Setup: users deposit funds
        vm.prank(user1);
        victim.deposit{value: 5 ether}();

        vm.prank(user2);
        victim.deposit{value: 5 ether}();

        uint256 victimBalanceBefore = address(victim).balance;
        uint256 attackerBalanceBefore = address(attacker).balance;

        // Execute attack
        vm.prank(address(attacker));
        attacker.attack{value: 1 ether}();

        uint256 victimBalanceAfter = address(victim).balance;
        uint256 attackerBalanceAfter = address(attacker).balance;

        // Attacker should have drained funds
        assertLt(victimBalanceAfter, victimBalanceBefore);
        assertGt(attackerBalanceAfter, attackerBalanceBefore);

        console.log("Victim balance before:", victimBalanceBefore);
        console.log("Victim balance after:", victimBalanceAfter);
        console.log("Attacker profit:", attackerBalanceAfter - attackerBalanceBefore);
    }

    /// @notice Fuzz test: withdraw should not exceed balance
    function testFuzz_WithdrawCannotExceedBalance(uint256 depositAmount, uint256 withdrawAmount) public {
        vm.assume(depositAmount > 0 && depositAmount <= 100 ether);
        vm.assume(withdrawAmount > depositAmount);

        vm.startPrank(user1);
        victim.deposit{value: depositAmount}();

        vm.expectRevert("Insufficient balance");
        victim.withdraw(withdrawAmount);
        vm.stopPrank();
    }

    /// @notice Invariant: Contract balance should equal sum of user balances
    /// @dev This will FAIL due to reentrancy allowing balance mismatch
    function invariant_BalanceIntegrity() public view {
        // This invariant should hold but will be violated by reentrancy
        // In a secure contract: sum(balances) == address(this).balance
    }
}
