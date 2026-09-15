// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.10;

import {IWETH9} from "src/interfaces/external/IWETH9.sol";

/// @title Periphery Immutable State
/// @notice Common immutable state used by periphery contracts
abstract contract PeripheryImmutableState {
    /// @notice Wrapped Ether
    IWETH9 public immutable WETH9;

    constructor(IWETH9 _WETH9) {
        WETH9 = _WETH9;
    }
}
