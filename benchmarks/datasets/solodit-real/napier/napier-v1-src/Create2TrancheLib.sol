// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.19;

import {Tranche} from "./Tranche.sol";

/// @notice Library for deploying Tranche contracts using CREATE2
/// @dev External library functions are used to downsize the TrancheFactory contract
library Create2TrancheLib {
    function deploy(address adapter, uint256 maturity) external returns (Tranche) {
        bytes32 salt;
        assembly {
            mstore(0x00, adapter) // note: ABI encoder v2 verifies the upper 96 bits are clean.
            mstore(0x20, maturity)
            salt := keccak256(0x00, 0x40)
        }
        return new Tranche{salt: salt}();
    }
}
