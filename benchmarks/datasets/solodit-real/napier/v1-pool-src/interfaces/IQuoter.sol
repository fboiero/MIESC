// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.0;

import {IPoolFactory} from "../interfaces/IPoolFactory.sol";
import {INapierPool} from "../interfaces/INapierPool.sol";

interface IQuoter {
    function getPoolAssets(INapierPool pool) external view returns (IPoolFactory.PoolAssets memory assets);

    /////////////////// Price ///////////////////

    function quoteBasePoolLpPrice(INapierPool pool) external view returns (uint256);

    function quotePtPrice(INapierPool pool, uint256 index) external view returns (uint256);

    /////////////////// Quote for swap ///////////////////

    function quotePtForUnderlying(INapierPool pool, uint256 index, uint256 ptIn)
        external
        returns (uint256 underlyingOut, uint256 gasEstimate);

    function quoteUnderlyingForPt(INapierPool pool, uint256 index, uint256 ptOutDesired)
        external
        returns (uint256 underlyingIn, uint256 gasEstimate);

    function quoteYtForUnderlying(INapierPool pool, uint256 index, uint256 ytIn)
        external
        returns (uint256 underlyingOut, uint256 gasEstimate);

    function quoteUnderlyingForYt(INapierPool pool, uint256 index, uint256 ytOut)
        external
        returns (uint256 underlyingIn, uint256 gasEstimate);

    /////////////////////////////////////////////////////////////////////////////////////
    // Quote for Liquidity provision / removal
    /////////////////////////////////////////////////////////////////////////////////////

    function quoteAddLiquidity(INapierPool pool, uint256[3] memory ptsIn, uint256 underlyingIn)
        external
        returns (uint256 liquidity, uint256 gasEstimate);

    function quoteAddLiquidityOneUnderlying(INapierPool pool, uint256 underlyingIn)
        external
        view
        returns (uint256 liquidity, uint256 baseLptSwap);

    function quoteAddLiquidityOnePt(INapierPool pool, uint256 index, uint256 ptIn)
        external
        view
        returns (uint256 liquidity, uint256 baseLptSwap);

    function quoteRemoveLiquidityBaseLpt(INapierPool pool, uint256 liquidity)
        external
        view
        returns (uint256, uint256);

    function quoteRemoveLiquidity(INapierPool pool, uint256 liquidity)
        external
        view
        returns (uint256, uint256[3] memory);

    function quoteRemoveLiquidityOnePt(INapierPool pool, uint256 index, uint256 liquidity)
        external
        view
        returns (uint256, uint256, uint256);

    function quoteRemoveLiquidityOneUnderlying(INapierPool pool, uint256 index, uint256 liquidity)
        external
        view
        returns (uint256 underlyingOut, uint256 gasEstimate);

    /////////////////// Approximation ///////////////////

    function approxPtForExactUnderlyingOut(INapierPool pool, uint256 index, uint256 underlyingDesired)
        external
        view
        returns (uint256);

    function approxPtForExactUnderlyingIn(INapierPool pool, uint256 index, uint256 underlyingDesired)
        external
        view
        returns (uint256);

    function approxYtForExactUnderlyingOut(INapierPool pool, uint256 index, uint256 underlyingDesired)
        external
        returns (uint256);

    function approxYtForExactUnderlyingIn(INapierPool pool, uint256 index, uint256 underlyingDesired)
        external
        returns (uint256);

    function approxBaseLptToAddLiquidityOneUnderlying(INapierPool pool, uint256 underlyingsToAdd)
        external
        view
        returns (uint256);

    function approxBaseLptToAddLiquidityOnePt(INapierPool pool, uint256 index, uint256 ptToAdd)
        external
        view
        returns (uint256);

    function approxBaseLptToRemoveLiquidityOnePt(INapierPool pool, uint256 liquidity) external view returns (uint256);
}
