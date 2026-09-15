// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.0;

interface INapierSwapCallback {
    /**
     * @notice Callback function to handle the token swap.
     * @param underlyingDelta The change in underlying after the swap.
     * @param ptDelta The change in Principal token after the swap.
     * @param data Additional data passed to the callback. Can be used to pass context-specific information.
     */
    function swapCallback(int256 underlyingDelta, int256 ptDelta, bytes calldata data) external;
}
