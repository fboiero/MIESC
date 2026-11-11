// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Base {
    uint256 public startId;

    constructor() {
        // Calls into a virtual overridden in the derived contract.
        startId = _firstId();
    }

    function _firstId() internal view virtual returns (uint256) {
        return 0;
    }
}

// resolc compiles via Yul/IR. With via-ir, base constructors run BEFORE the
// derived contract's state-variable initializers, so `offset` is still 0 when
// _firstId() runs during Base's constructor → startId == 0 on PolkaVM, whereas
// legacy EVM codegen yields 1 (revive compiler book example). Difference class (B).
contract Derived is Base {
    uint256 private offset = 1;

    function _firstId() internal view override returns (uint256) {
        return offset;
    }
}
