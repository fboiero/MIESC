// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// `selfdestruct` COMPILES under resolc (verified in F0, exit 0). It is flagged as a
// portability / semantic risk because its runtime behaviour on PolkaVM / pallet-revive
// may differ from the EVM (compile verified; runtime semantics not independently
// confirmed). NOT a compile error. Difference class (B).
contract SelfDestructUse {
    address payable private owner;

    constructor() {
        owner = payable(msg.sender);
    }

    function destroy() external {
        selfdestruct(owner);
    }
}
