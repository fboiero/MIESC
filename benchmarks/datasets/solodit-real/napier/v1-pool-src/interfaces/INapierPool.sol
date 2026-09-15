// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.0;

import {IERC20} from "@openzeppelin/contracts@4.9.3/token/ERC20/IERC20.sol";
import {CurveTricryptoOptimizedWETH} from "./external/CurveTricryptoOptimizedWETH.sol";

import {PoolState} from "../libs/PoolMath.sol";

interface INapierPool {
    event Mint(address indexed receiver, uint256 liquidity, uint256 underlyingUsed, uint256 baseLptUsed);

    event Burn(address indexed receiver, uint256 liquidity, uint256 underlyingOut, uint256 baseLptOut);

    event Swap(
        address indexed caller,
        address indexed receiver,
        int256 netUnderlying,
        uint256 index,
        int256 netPt,
        uint256 swapFee,
        uint256 protocolFee
    );

    event SwapBaseLpt(
        address indexed caller,
        address indexed receiver,
        int256 netUnderlying,
        int256 netBaseLpt,
        uint256 swapFee,
        uint256 protocolFee
    );

    event UpdateLnImpliedRate(uint256 lnImpliedRate);

    /**
     * @notice Add liquidity to the pool with Underlying and base lp token.
     * Caller have to transfer tokens to this contract before calling this function.
     * @param underlyingInDesired The desired amount of underlying asset to add.
     * @param baseLptInDesired The desired amount of base lp token to add.
     * @param recipient The recipient of the liquidity tokens.
     * @param data Additional data for callback.
     * @return The amount of liquidity tokens received.
     */
    function addLiquidity(uint256 underlyingInDesired, uint256 baseLptInDesired, address recipient, bytes memory data)
        external
        returns (uint256);

    /**
     * @notice Remove liquidity from the pool.
     * Caller have to transfer Lp token to this contract before calling this function.
     * @param recipient The recipient of the assets.
     * @return The amounts of base lp token and underlying asset received.
     */
    function removeLiquidity(address recipient) external returns (uint256, uint256);

    /**
     * @notice Swap exact amount of PT for Underlying asset.
     * It supports flash swap by specifying the callback data.
     * Flash swap enables user to receive Underlying asset before paying PT.
     * If the pool contract received enough PT after the callback, the swap is successful. Otherwise, the swap is reverted.
     * @param index The index of the PT.
     * @param ptIn The amount of PT to swap.
     * @param recipient The recipient of the swapped underlying asset.
     * @param data Additional data for the flash swap.
     * @return The amount of underlying asset received.
     */
    function swapPtForUnderlying(uint256 index, uint256 ptIn, address recipient, bytes calldata data)
        external
        returns (uint256);

    /**
     * @notice Swap Underlying asset for exact amount of PT.
     * It supports flash swap by specifying the callback data.
     * It enables user to receive PT before paying Underlying asset.
     * if the pool contract received enough Underlying asset after the callback, the swap is successful. Otherwise, the swap is reverted.
     * @param index The index of the PT.
     * @param ptOut The desired amount of PT to receive.
     * @param recipient The recipient of the PT.
     * @param data Additional data for the flash swap.
     * @return The amount of PT received.
     */
    function swapUnderlyingForPt(uint256 index, uint256 ptOut, address recipient, bytes calldata data)
        external
        returns (uint256);

    /**
     * @notice Swap Underlying asset for exact amount of Base LP token.
     * @param baseLpOut The desired amount of Base LP token to receive.
     * @param recipient The recipient of the Base LP token.
     */
    function swapUnderlyingForExactBaseLpToken(uint256 baseLpOut, address recipient) external returns (uint256);

    /**
     * @notice Swap exact amount of Base LP token for Underlying asset.
     * @param recipient The recipient of the Underlying asset.
     */
    function swapExactBaseLpTokenForUnderlying(uint256 baseLptIn, address recipient) external returns (uint256);

    /**
     * @notice Maturity of the pool, in unix timestamp.
     * @dev Maturity is same as the maturity of Principal Token in the pool.
     */
    function maturity() external view returns (uint256);

    function totalUnderlying() external view returns (uint128);

    function totalBaseLpt() external view returns (uint128);

    function getAssets() external view returns (address, address);

    /**
     * @notice State of the pool.
     * @dev This function is not expected to be called on-chain.
     */
    function readState() external view returns (PoolState memory);

    function tricrypto() external view returns (CurveTricryptoOptimizedWETH);

    function principalTokens() external view returns (IERC20[3] memory);

    function lastLnImpliedRate() external view returns (uint256);
}
