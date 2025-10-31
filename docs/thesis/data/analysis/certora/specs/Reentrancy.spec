/*
 * Certora Formal Verification Spec for Reentrancy Vulnerability
 * Tests: BasicReentrancy.sol
 *
 * This spec defines rules that SHOULD hold in a secure contract
 * but WILL FAIL in the vulnerable contract, demonstrating the issue.
 */

methods {
    function deposit() external payable;
    function withdraw(uint256) external;
    function balances(address) external returns (uint256) envfree;
    function getBalance() external returns (uint256) envfree;
}

// Ghost variables to track state
ghost uint256 sumOfBalances {
    init_state axiom sumOfBalances == 0;
}

// Hook to update sumOfBalances on any balance change
hook Sload uint256 balance balances[KEY address user] STORAGE {
    havoc sumOfBalances assuming sumOfBalances@new == sumOfBalances@old + (balance - old(balance));
}

/**
 * Rule: Contract balance should equal sum of user balances
 * Status: FAILS in vulnerable contract due to reentrancy
 */
invariant balanceIntegrity()
    to_mathint(nativeBalances[currentContract]) == sumOfBalances
    {
        preserved deposit() with (env e) {
            require e.msg.value > 0;
        }
    }

/**
 * Rule: Withdraw should decrease user balance by exact amount
 * Status: Should PASS but actual balance might not update in reentrancy
 */
rule withdrawDecreasesBalance(address user, uint256 amount) {
    env e;
    require e.msg.sender == user;

    uint256 balanceBefore = balances(user);
    require balanceBefore >= amount;
    require amount > 0;

    withdraw(e, amount);

    uint256 balanceAfter = balances(user);

    assert balanceAfter == balanceBefore - amount,
        "Balance should decrease by withdrawn amount";
}

/**
 * Rule: Withdraw should not allow balance to go negative
 * Status: Should PASS (Solidity prevents underflow in 0.8+)
 */
rule noNegativeBalance(address user) {
    env e;
    require e.msg.sender == user;

    uint256 balanceBefore = balances(user);
    uint256 withdrawAmount;

    withdraw@withrevert(e, withdrawAmount);

    uint256 balanceAfter = balances(user);

    assert !lastReverted => balanceAfter >= 0,
        "Balance should never be negative";
}

/**
 * Rule: Multiple withdrawals should not exceed initial balance
 * Status: FAILS due to reentrancy allowing multiple withdrawals
 */
rule withdrawalLimit(address user) {
    env e1; env e2;
    require e1.msg.sender == user;
    require e2.msg.sender == user;

    uint256 initialBalance = balances(user);
    require initialBalance > 0;

    // First withdrawal
    uint256 amount1 = initialBalance / 2;
    withdraw(e1, amount1);

    // Second withdrawal (should fail or reduce remaining balance)
    uint256 amount2 = initialBalance / 2;
    withdraw@withrevert(e2, amount2);

    // Total withdrawn should not exceed initial balance
    assert lastReverted ||
           (balances(user) == initialBalance - amount1 - amount2),
        "Cannot withdraw more than balance";
}

/**
 * Rule: Reentrancy guard - function should not be callable during execution
 * Status: FAILS - contract allows reentrancy
 */
rule noReentrancy(address user, uint256 amount) {
    env e;
    require e.msg.sender == user;

    // If we're in the middle of a withdraw...
    storage initStorage = lastStorage;

    withdraw(e, amount);

    // ...we shouldn't be able to call withdraw again
    withdraw@withrevert(e, amount) at initStorage;

    assert lastReverted,
        "Should not allow reentrant calls";
}

/**
 * Rule: Contract solvency - contract should always have enough to pay
 * Status: FAILS due to reentrancy draining contract
 */
invariant contractSolvency()
    to_mathint(nativeBalances[currentContract]) >= sumOfBalances
    {
        preserved {
            requireInvariant balanceIntegrity();
        }
    }
