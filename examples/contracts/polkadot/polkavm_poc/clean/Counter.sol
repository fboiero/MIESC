// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Clean contract: compiles with resolc and must NOT raise any High/Critical
// PolkaVM-difference finding (no 63/64 forwarding, no unbounded memory, no
// CREATE2 address assumption, no prevrandao entropy, no selfdestruct).
contract Counter {
    uint256 private count;

    function increment() external {
        count += 1;
    }

    function current() external view returns (uint256) {
        return count;
    }
}
