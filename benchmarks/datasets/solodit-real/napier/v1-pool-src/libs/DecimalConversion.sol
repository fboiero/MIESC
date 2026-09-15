// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.0;

library DecimalConversion {
    /// @dev Turns a token into 18 point decimal
    /// @param amount The amount of the token in native decimal encoding
    /// @param decimals The token decimals (MUST be less than 18)
    /// @return The amount of token encoded into 18 point fixed point
    function to18Decimals(uint256 amount, uint8 decimals) internal pure returns (uint256) {
        // we shift left by the difference
        return amount * 10 ** (18 - decimals);
    }

    /// @dev Turns an 18 fixed point amount into a token amount
    /// @param amount The amount of the token in 18 decimal fixed point
    /// @param decimals The token decimals (MUST be less than 18)
    /// @return The amount of token encoded in native decimal point
    function from18Decimals(uint256 amount, uint8 decimals) internal pure returns (uint256) {
        // we shift right the amount by the number of decimals
        return amount / 10 ** (18 - decimals);
    }
}
