// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// PolkaVM memory is a FIXED 128kb buffer; accessing beyond it traps the contract
// at runtime (OutOfBound), unlike the EVM's gas-metered expanding memory. An
// unbounded, caller-controlled allocation can trap on PolkaVM. Difference class (B).
contract UnboundedMemory {
    function build(uint256 n) external pure returns (bytes memory out) {
        out = new bytes(n); // caller-controlled, unbounded size
        for (uint256 i = 0; i < n; i++) {
            out[i] = 0xff;
        }
    }
}
