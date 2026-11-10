// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// On PolkaVM, `block.prevrandao` (and DIFFICULTY) translate to a CONSTANT
// (2500000000000000) per the revive compiler book, so any randomness derived
// from it is fully predictable. Difference class (B): compiles, silently insecure.
contract PredictableRandomness {
    function roll() external view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.prevrandao, block.timestamp))) % 6;
    }
}
