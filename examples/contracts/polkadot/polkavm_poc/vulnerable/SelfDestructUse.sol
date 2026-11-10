// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// `selfdestruct` COMPILES under resolc (verified in F0, exit 0) but its semantics
// on PolkaVM / pallet-revive differ from the EVM. Flagged as a portability /
// semantic risk, NOT as a compile error. Difference class (B).
contract SelfDestructUse {
    address payable private owner;

    constructor() {
        owner = payable(msg.sender);
    }

    function destroy() external {
        selfdestruct(owner);
    }
}
