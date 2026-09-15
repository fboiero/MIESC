// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.17;

import {NapierPool} from "../NapierPool.sol";

/// @notice Library for deploying NapierPool contracts using CREATE2
/// @dev External library functions are used to downsize the factory contract
library Create2PoolLib {
    function deploy(address basePool, address underlying) external returns (NapierPool) {
        bytes32 salt;
        assembly {
            mstore(0x00, basePool) // note: ABI encoder v2 verifies the upper 96 bits are clean.
            mstore(0x20, underlying)
            salt := keccak256(0x00, 0x40)
        }
        return new NapierPool{salt: salt}();
    }
}
