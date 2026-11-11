// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Child {
    uint256 public x;
    constructor(uint256 _x) {
        x = _x;
    }
}

// On PolkaVM, contract addresses are derived from the code HASH (not the deploy
// code), and `type(T).creationCode` returns the keccak256 of the bytecode rather
// than the bytecode itself (revive compiler book). Any CREATE2 / cross-chain
// address precomputation that assumes EVM semantics is wrong. Difference class (B).
contract Create2Factory {
    function deploy(bytes32 salt, uint256 x) external returns (address a) {
        a = address(new Child{salt: salt}(x));
    }

    // EVM-style CREATE2 address precomputation — does NOT hold on PolkaVM.
    function predicted(bytes32 salt, uint256 x) external view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                bytes1(0xff),
                address(this),
                salt,
                keccak256(abi.encodePacked(type(Child).creationCode, abi.encode(x)))
            )
        );
    }
}
