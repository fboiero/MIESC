/*
 * Certora Formal Verification Spec for Access Control
 * Tests: UnprotectedWithdraw.sol
 *
 * Verifies that privileged functions are properly protected
 */

methods {
    function owner() external returns (address) envfree;
    function withdrawAll(address) external;
    function emergencyWithdraw() external;
    function deposit() external payable;
}

/**
 * Rule: Only owner should be able to withdrawAll
 * Status: FAILS in vulnerable contract
 */
rule onlyOwnerCanWithdrawAll(address caller, address to) {
    env e;
    require e.msg.sender == caller;
    require caller != owner();

    withdrawAll@withrevert(e, to);

    assert lastReverted,
        "Non-owner should not be able to withdrawAll";
}

/**
 * Rule: Owner should never change unexpectedly
 * Status: Should PASS
 */
rule ownerStability() {
    address ownerBefore = owner();

    env e;
    address to;
    deposit@withrevert(e);

    address ownerAfter = owner();

    assert ownerAfter == ownerBefore,
        "Owner should not change from deposit";
}

/**
 * Rule: Privileged functions should check caller
 * Status: FAILS if emergencyWithdraw missing check
 */
rule emergencyWithdrawOnlyOwner(address caller) {
    env e;
    require e.msg.sender == caller;
    require caller != owner();

    emergencyWithdraw@withrevert(e);

    assert lastReverted,
        "Only owner should call emergencyWithdraw";
}

/**
 * Rule: Contract balance should only decrease through owner
 * Status: FAILS if withdrawAll unprotected
 */
rule balanceProtection() {
    uint256 balanceBefore = nativeBalances[currentContract];

    env e;
    method f;
    calldataarg args;

    f(e, args);

    uint256 balanceAfter = nativeBalances[currentContract];

    assert balanceAfter < balanceBefore =>
           (e.msg.sender == owner() || f.selector == sig:deposit().selector),
        "Balance decrease should only be by owner or deposit";
}
