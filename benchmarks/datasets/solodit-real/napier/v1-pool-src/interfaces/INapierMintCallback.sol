// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.0;

interface INapierMintCallback {
    /**
     * @notice Callback function to handle the add liquidity.
     * @param underlyingDelta The change in underlying.
     * @param baseLptDelta The change in Base pool LP token.
     * @param data Additional data passed to the callback. Can be used to pass context-specific information.
     */
    function mintCallback(uint256 underlyingDelta, uint256 baseLptDelta, bytes calldata data) external;
}
