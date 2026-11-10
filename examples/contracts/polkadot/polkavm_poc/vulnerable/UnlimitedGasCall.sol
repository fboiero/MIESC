// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// PolkaVM / pallet-revive does NOT apply the EVM 63/64 gas rule when calling
// another contract (revive compiler book — "Differences to EVM"). Forwarding all
// remaining gas to an untrusted callee is therefore a DoS vector that an EVM-only
// analysis would not flag. Difference class (B): compiles fine, behaves worse.
contract UnlimitedGasCall {
    function forward(address target, bytes calldata data) external returns (bool ok) {
        // No gas cap on a call to an untrusted target.
        (ok, ) = target.call(data);
    }
}
