// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.10;

/////////////////////////////////////////////////////////////////
// NapierPool AMM configuration constants
/////////////////////////////////////////////////////////////////

// @notice Pool configuration Max logarithmic fee rate
// @dev ln(1.05) in 18 decimals
// @dev Computed by PrbMath library
uint80 constant MAX_LN_FEE_RATE_ROOT = 48790164169431991;

// @notice Max protocol fee percent. 100=100%
uint8 constant MAX_PROTOCOL_FEE_PERCENT = 100; // 100%

// @notice Min initial anchor
int256 constant MIN_INITIAL_ANCHOR = 1e18;
