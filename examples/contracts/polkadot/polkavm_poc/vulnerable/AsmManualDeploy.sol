// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// On PolkaVM the deploy opcode consumes a code-HASH buffer plus a separate
// constructor-arguments buffer (revive compiler book), not the concatenated
// initcode buffer the EVM expects. A hand-rolled EIP-1167 clone or CREATE3-style
// deployment assembled in inline assembly therefore may break, and the
// deterministic address it precomputes on the EVM does not hold. Difference
// class (B): it compiles silently under resolc (verified) and diverges only at
// runtime. The Solidity-level new X{salt:} form is covered separately by
// polkavm-create2-address-assumption; this fixture exercises the assembly form.
contract CloneFactory {
    // EIP-1167 minimal-proxy clone via inline-assembly `create`.
    function clone(address impl) external returns (address inst) {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, 0x3d602d80600a3d3981f3363d3d373d3d3d363d73000000000000000000000000)
            mstore(add(ptr, 0x14), shl(0x60, impl))
            mstore(add(ptr, 0x28), 0x5af43d82803e903d91602b57fd5bf30000000000000000000000000000000000)
            inst := create(0, ptr, 0x37)
        }
    }

    // Deterministic clone via inline-assembly `create2`; the address precomputed
    // on the EVM does NOT hold on PolkaVM.
    function cloneDeterministic(address impl, bytes32 salt) external returns (address inst) {
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, 0x3d602d80600a3d3981f3363d3d373d3d3d363d73000000000000000000000000)
            mstore(add(ptr, 0x14), shl(0x60, impl))
            mstore(add(ptr, 0x28), 0x5af43d82803e903d91602b57fd5bf30000000000000000000000000000000000)
            inst := create2(0, ptr, 0x37, salt)
        }
    }
}
