// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.10;

import {INapierPool} from "../interfaces/INapierPool.sol";
import {Create2} from "@openzeppelin/contracts@4.9.3/utils/Create2.sol";

library PoolAddress {
    function computeAddress(address basePool, address underlying, bytes32 initHash, address factory)
        internal
        pure
        returns (INapierPool pool)
    {
        // Optimize salt computation
        // https://www.rareskills.io/post/gas-optimization#viewer-ed7oh
        // https://github.com/dragonfly-xyz/useful-solidity-patterns/tree/main/patterns/assembly-tricks-1#hash-two-words
        bytes32 salt;
        assembly {
            // Clean the upper 96 bits of `basePool` in case they are dirty.
            mstore(0x00, shr(96, shl(96, basePool)))
            mstore(0x20, shr(96, shl(96, underlying)))
            salt := keccak256(0x00, 0x40)
        }
        pool = INapierPool(Create2.computeAddress(salt, initHash, factory));
    }
}
