/*
 * Certora Verification Spec for VulnerableBank
 * This spec will FAIL for the vulnerable contract, proving the reentrancy bug
 */

methods {
    function balances(address) external returns (uint256) envfree;
    function totalDeposits() external returns (uint256) envfree;
    function getContractBalance() external returns (uint256) envfree;
    function deposit() external payable;
    function withdraw() external;
    function withdrawAmount(uint256) external;
}

// Ghost variable to track ETH balance
ghost mathint sumOfBalances {
    init_state axiom sumOfBalances == 0;
}

// Hook to update ghost on balance changes
hook Sstore balances[KEY address user] uint256 newValue (uint256 oldValue) {
    sumOfBalances = sumOfBalances + newValue - oldValue;
}

/*
 * INVARIANT: Sum of all user balances should equal totalDeposits
 * This SHOULD hold but reentrancy can break it
 */
invariant balanceIntegrity()
    sumOfBalances == to_mathint(totalDeposits())
    {
        preserved with (env e) {
            require e.msg.value <= 2^128;
        }
    }

/*
 * INVARIANT: Contract ETH balance >= totalDeposits
 * Reentrancy attack violates this
 */
invariant solvency()
    to_mathint(getContractBalance()) >= to_mathint(totalDeposits())

/*
 * RULE: Deposit increases balance correctly
 */
rule depositIncreasesBalance(env e) {
    uint256 balanceBefore = balances(e.msg.sender);
    uint256 totalBefore = totalDeposits();

    deposit(e);

    uint256 balanceAfter = balances(e.msg.sender);
    uint256 totalAfter = totalDeposits();

    assert balanceAfter == balanceBefore + e.msg.value,
        "Balance should increase by deposit amount";
    assert totalAfter == totalBefore + e.msg.value,
        "Total should increase by deposit amount";
}

/*
 * RULE: Withdraw decreases balance correctly
 * This rule will FAIL due to reentrancy - balance can be drained multiple times
 */
rule withdrawDecreasesBalanceCorrectly(env e) {
    uint256 balanceBefore = balances(e.msg.sender);
    require balanceBefore > 0;

    withdraw(e);

    uint256 balanceAfter = balances(e.msg.sender);

    assert balanceAfter == 0,
        "Balance should be zero after withdraw";
}

/*
 * RULE: No user can withdraw more than their balance
 * Reentrancy VIOLATES this rule
 */
rule noOverWithdraw(env e) {
    uint256 userBalance = balances(e.msg.sender);
    uint256 contractBalance = getContractBalance();

    withdraw(e);

    uint256 newContractBalance = getContractBalance();
    uint256 withdrawn = contractBalance - newContractBalance;

    assert withdrawn <= userBalance,
        "Should not withdraw more than balance";
}

/*
 * RULE: Withdrawing should not affect other users' balances
 */
rule withdrawDoesNotAffectOthers(env e, address other) {
    require other != e.msg.sender;

    uint256 otherBalanceBefore = balances(other);

    withdraw(e);

    uint256 otherBalanceAfter = balances(other);

    assert otherBalanceAfter == otherBalanceBefore,
        "Other users' balances should not change";
}

/*
 * RULE: State changes are atomic
 * External call before state update violates atomicity
 */
rule atomicStateChange(env e) {
    uint256 balanceBefore = balances(e.msg.sender);
    uint256 totalBefore = totalDeposits();
    uint256 contractBefore = getContractBalance();

    withdraw(e);

    uint256 balanceAfter = balances(e.msg.sender);
    uint256 totalAfter = totalDeposits();
    uint256 contractAfter = getContractBalance();

    // After withdraw, the following should all be true atomically
    assert (balanceAfter == 0) => (totalAfter == totalBefore - balanceBefore),
        "Total deposits should decrease by withdrawn amount";
    assert (balanceAfter == 0) => (contractAfter == contractBefore - balanceBefore),
        "Contract balance should decrease by withdrawn amount";
}
