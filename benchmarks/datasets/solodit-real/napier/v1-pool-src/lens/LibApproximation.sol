// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.10;

import {ApproxParams} from "./ApproxParams.sol";

import {PoolMath, PoolState, PoolPreCompute} from "../libs/PoolMath.sol";

import {Math} from "@openzeppelin/contracts@4.9.3/utils/math/Math.sol";
import {SafeCast} from "@openzeppelin/contracts@4.9.3/utils/math/SafeCast.sol";
import {SignedMath} from "../libs/SignedMath.sol";
import {sd, exp, ln, intoInt256} from "@prb/math/SD59x18.sol";

import {Errors} from "../libs/Errors.sol";

/// @dev These functions are not gas efficient and should _not_ be called on-chain.
library LibApproximation {
    using SignedMath for int256;
    using SafeCast for uint256;
    using SafeCast for int256;

    uint256 constant N_COINS = 3;

    /// @dev Bisection method to find an `x` such that minimizing the error function.
    /// @dev The function will revert if the error function does not converge within the tolerance `approx.eps` after `approx.maxIteration` iterations.
    /// @dev error_function SHOULD return `error = (v - v_approx) / v = 1 - v_approx / v` where `v` is the desired value and `v_approx` is the computed value.
    /// @param args The arguments for the error function
    /// @param error_function The function that calculates the relative error between the desired value and the current value.
    /// @param input The value we want to input to the error function
    /// @param approx The parameters for controlling the approximation process
    /// @return Returns `x` that minimizes the error function.
    function bisect(
        bytes memory args,
        function (uint256, bytes memory, uint256) view returns (int256) error_function,
        uint256 input,
        ApproxParams memory approx
    ) internal view returns (uint256) {
        uint256 a = approx.guessMin;
        uint256 b = approx.guessMax;
        uint256 midpoint;
        int256 error_mid;
        if (a >= b) revert Errors.ApproxBinarySearchInputInvalid();

        // Continue until the interval is sufficiently small or maxIteration is reached
        for (uint256 i = 0; i != approx.maxIteration; ++i) {
            midpoint = (a + b) / 2;
            error_mid = error_function(midpoint, args, input);
            // Check if the relative error is less than the tolerance
            if (abs(error_mid) < approx.eps) {
                return midpoint;
            }

            // Adjust the interval based on the sign of the error
            if (error_mid > 0) {
                a = midpoint;
            } else {
                b = midpoint;
            }
        }

        // If the function hasn't returned by now, it means it didn't converge within the tolerance range
        revert Errors.ApproxFail();
    }

    /// @notice Approximate an amount of baseLpt to swap for exact amount of underlying.
    /// @param state The pool state
    /// @param underlyingOut18Desired The desired amount of underlying to swap out (in 18 decimals)
    /// @param approx The parameters for controlling the approximation process
    /// @return The amount of baseLpt to swap in for exact amount of underlying
    function approxSwapBaseLptForExactUnderlying(
        PoolState memory state,
        uint256 underlyingOut18Desired,
        ApproxParams memory approx
    ) internal view returns (uint256) {
        PoolPreCompute memory comp = PoolMath.computeAmmParameters(state);
        uint256 max = calcMaxBaseLptIn(state, comp);
        if (max < approx.guessMax) {
            approx.guessMax = max;
        }
        bytes memory args = abi.encode(state, comp);
        return bisect(args, underlyingOutErrorFunc, underlyingOut18Desired, approx);
    }

    /// @notice Calculate swap exact underlying for baseLpt in and return relative error of desired and computed one.
    /// @param midpoint The amount of baseLpt to swap
    /// @param underlyingOut18Desired The desired amount of underlying to swap out (in 18 decimals)
    /// @return The relative error of computed underlying amount to the desired amount `underlyingOut18Desired`
    function underlyingOutErrorFunc(uint256 midpoint, bytes memory args, uint256 underlyingOut18Desired)
        internal
        pure
        returns (int256)
    {
        (PoolState memory state, PoolPreCompute memory comp) = abi.decode(args, (PoolState, PoolPreCompute));
        (int256 netUnderlying18,,) = PoolMath.calculateSwap(state, comp, -(midpoint * N_COINS).toInt256());
        // `netUnderlying18` is positive.
        // `abs(netUnderlying18)` should be smaller than desired underlying amount.
        if (netUnderlying18.toUint256() > underlyingOut18Desired) return -1e18; // indicate that the guess is too large
        // epsilon = (v - v_approx) / v = 1 - v_approx / v
        return (1e18 - netUnderlying18 * 1e18 / underlyingOut18Desired.toInt256());
    }

    /// @notice Approximate an amount of baseLpt to swap for exact amount of underlying.
    /// @param state The pool state
    /// @param underlyingIn18Desired The desired amount of underlying to swap in (in 18 decimals)
    /// @param approx The parameters for controlling the approximation process
    /// @return The amount of baseLpt to swap out for exact amount of underlying
    function approxSwapExactUnderlyingForBaseLpt(
        PoolState memory state,
        uint256 underlyingIn18Desired,
        ApproxParams memory approx
    ) internal view returns (uint256) {
        PoolPreCompute memory comp = PoolMath.computeAmmParameters(state);
        uint256 max = calcMaxBaseLptOut(comp, state.totalBaseLptTimesN, state.totalUnderlying18);
        if (max < approx.guessMax) {
            approx.guessMax = max;
        }
        bytes memory args = abi.encode(state, comp);
        return bisect(args, underlyingInErrorFunc, underlyingIn18Desired, approx);
    }

    /// @param midpoint The amount of baseLpt to swap
    /// @param underlyingIn18Desired The desired amount of underlying to swap for (in 18 decimals)
    /// @return The relative error of computed underlying amount to the desired amount `underlyingIn18Desired`
    function underlyingInErrorFunc(uint256 midpoint, bytes memory args, uint256 underlyingIn18Desired)
        internal
        pure
        returns (int256)
    {
        (PoolState memory state, PoolPreCompute memory comp) = abi.decode(args, (PoolState, PoolPreCompute));
        (int256 netUnderlying18,,) = PoolMath.calculateSwap(state, comp, (midpoint * N_COINS).toInt256());
        // `netUnderlying18` is negative.
        // `abs(netUnderlying18)` should be smaller than desired underlying amount.
        if (abs(netUnderlying18) > underlyingIn18Desired) return -1e18; // return a small negative value to indicate that the guess is too large
        // epsilon = (v - v_approx) / v = 1 - v_approx / v
        return (1e18 + netUnderlying18 * 1e18 / underlyingIn18Desired.toInt256());
    }

    /// @dev Approximate an amount of baseLpt to be swapped out to add liquidity from a given amount of baseLpt only.
    /// @param baseLptToAdd The amount of baseLpt to add liquidity (in 18 decimals)
    function approxBaseLptToAddLiquidityOnePt(PoolState memory state, uint256 baseLptToAdd, ApproxParams memory approx)
        internal
        view
        returns (uint256)
    {
        PoolPreCompute memory comp = PoolMath.computeAmmParameters(state);
        uint256 baseLptReserve = state.totalBaseLptTimesN / N_COINS;
        uint256 max = Math.min(calcMaxBaseLptIn(state, comp), baseLptReserve);
        approx.guessMax = Math.min(approx.guessMax, max); // upper bound should be the smaller one
        bytes memory args = abi.encode(state, comp);
        return bisect(args, computeRelErrorForPtDeposit, baseLptToAdd, approx);
    }

    function computeRelErrorForPtDeposit(uint256 midpoint, bytes memory args, uint256 baseLptToAdd)
        internal
        pure
        returns (int256)
    {
        (PoolState memory state, PoolPreCompute memory comp) = abi.decode(args, (PoolState, PoolPreCompute));
        // Calculate the net underlying amount to be swapped out.
        // `netUnderlying18` is positive.
        uint256 deltaB = midpoint * N_COINS;
        (int256 netUnderlying18,, int256 underlyingToProtocol18) =
            PoolMath.calculateSwap(state, comp, -deltaB.toInt256());
        // Formula:
        // `B`: Reserve of base pool LP token before a swap (in 18 decimals) times N_COINS
        // `U`: Reserve of underlying before a swap (in 18 decimals)
        // `b`: total base pool LP token to deposit (in 18 decimals) times N_COINS
        // `∆u`: underlying amount to be swapped out (in 18 decimals)
        // `∆b`: base pool LP token amount to be swapped in (in 18 decimals) times N_COINS
        // `fee`: swap fee charged by the pool (in 18 decimals)

        // To add liquidity proportional to pool reserve after swap should be:
        // ```
        // (U - ∆u - fee) / (B + ∆b) ~= ∆u / (b - ∆b)
        // ```
        // Find `b` such that minimize the epsilon:
        // ```
        // nemerator = (B + ∆b) * ∆u
        // denominator = (b - ∆b) * (U - ∆u - fee)
        // epsilon = (v - v_approx) / v = 1 - v_approx / v where v_approx = numerator / denominator and v = 1
        // ```
        uint256 deltaU = abs(netUnderlying18);
        if (baseLptToAdd * N_COINS <= deltaB) {
            return -1e18; // return a small negative value to indicate that the guess is too large
        }
        uint256 numeratorWad = (state.totalBaseLptTimesN + deltaB) * deltaU;
        uint256 denominator = (baseLptToAdd * N_COINS - deltaB)
            * (state.totalUnderlying18 - deltaU - underlyingToProtocol18.toUint256()) / 1e18;
        // epsilon = (v - v_approx) / v = 1 - v_approx / v
        return (1e18 - int256(numeratorWad / denominator));
    }

    /// @notice Approximate an amount of baseLpt to be swapped out to add liquidity from a given amount of underlying asset only.
    /// @dev See `NapierRouter.addLiquidityOneUnderlying` for more details.
    function approxBaseLptToAddLiquidityOneUnderlying(
        PoolState memory state,
        uint256 underlyingsToAdd18,
        ApproxParams memory approx
    ) internal view returns (uint256) {
        PoolPreCompute memory comp = PoolMath.computeAmmParameters(state);
        uint256 max = calcMaxBaseLptOut(comp, state.totalBaseLptTimesN, state.totalUnderlying18);
        if (max < approx.guessMax) {
            approx.guessMax = max;
        }
        bytes memory args = abi.encode(state, comp);
        return bisect(args, computeRelErrorForUnderlyingDeposit, underlyingsToAdd18, approx);
    }

    function computeRelErrorForUnderlyingDeposit(uint256 midpoint, bytes memory args, uint256 underlyingsToAdd18)
        internal
        pure
        returns (int256)
    {
        (PoolState memory state, PoolPreCompute memory comp) = abi.decode(args, (PoolState, PoolPreCompute));
        // Calculate the net underlying amount to be swapped in
        // `netUnderlying18` is negative.
        uint256 deltaB = midpoint * N_COINS;
        (int256 netUnderlying18,, int256 underlyingToProtocol18) =
            PoolMath.calculateSwap(state, comp, deltaB.toInt256());
        // Formula:
        // `B`: Reserve of base pool LP token before a swap (in 18 decimals) times N_COINS
        // `U`: Reserve of underlying before a swap (in 18 decimals)
        // `u`: total underlying amount to deposit (in 18 decimals)
        // `∆u`: underlying amount to be swapped in (in 18 decimals)
        // `∆b`: base pool LP token amount to be swapped out (in 18 decimals) times N_COINS
        // `fee`: swap fee charged by the pool (in 18 decimals)

        // To add liquidity proportional to pool reserve after swap should be:
        // ```
        // (U + ∆u - fee) / (B - ∆b) ~= (u - ∆u) / ∆b
        // ```
        // Find `∆b` such that minimize the epsilon:
        // ```
        // denominator = (B - ∆b) * (u - ∆u)
        // numerator = ∆b * (∆u + U - fee)
        // epsilon = (v - v_approx) / v = 1 - v_approx / v where v_approx = numerator / denominator and v = 1
        // ```
        uint256 deltaU = abs(netUnderlying18);
        if (underlyingsToAdd18 <= deltaU) {
            return -1e18; // return a small negative value to indicate that the guess is too large
        }
        uint256 denominator = (state.totalBaseLptTimesN - deltaB) * (underlyingsToAdd18 - deltaU) / 1e18;
        uint256 numeratorWad = deltaB * (deltaU + state.totalUnderlying18 - underlyingToProtocol18.toUint256());
        // epsilon = (v - v_approx) / v = 1 - v_approx / v
        return (1e18 - (numeratorWad / denominator).toInt256());
    }

    /// @notice Calculate the maximum amount of baseLpt that can be swapped for underlying.
    /// @dev See whitepaper for more details (ref: Pendle whitepaper)
    /// @dev Modified from Pendle finance implementation https://github.com/pendle-finance/pendle-core-v2-public/blob/618de8ac0e6acfc26c58bcc4ae58600a738f47c6/contracts/router/base/MarketApproxLib.sol#L290
    function calcMaxBaseLptOut(PoolPreCompute memory comp, uint256 totalBaseLptTimesN, uint256 totalUnderlying18)
        internal
        pure
        returns (uint256)
    {
        int256 logitP = exp(sd(comp.feeRate - comp.rateAnchor.mulWadDown(comp.rateScalar))).intoInt256();
        int256 proportion = logitP.divWadDown(logitP + SignedMath.WAD);
        uint256 numerator = proportion.mulWadDown((totalBaseLptTimesN + totalUnderlying18).toInt256()).toUint256();
        uint256 max = (totalBaseLptTimesN - numerator) / N_COINS;
        // only get 99.9% of the theoretical max to accommodate some precision issues
        return (max * 999) / 1000;
    }

    /// @dev Let f(x) be the function that calculates swap an amount of underlying for a given `x` amount of baseLp.
    /// f(x) has a local minimum at `x = maxBaseLptIn` in the x < 0 region (i.e. swap baseLpt for underlying).
    /// `x` such that `g(x) = 0` using bisection method.
    /// @dev Modified from Pendle finance implementation https://github.com/pendle-finance/pendle-core-v2-public/blob/618de8ac0e6acfc26c58bcc4ae58600a738f47c6/contracts/router/base/MarketApproxLib.sol#L290
    function calcMaxBaseLptIn(PoolState memory state, PoolPreCompute memory comp) internal pure returns (uint256) {
        uint256 low = 0;
        uint256 hi = state.totalUnderlying18 / N_COINS - 1;
        // This iterative process continues, continually narrowing the range until `low` and `hi` converge to the same value,
        // at which point the binary search has found the `x` for which the slope is non-negative.
        // forgefmt: disable-start
        while (low != hi) {
            uint256 mid = (low + hi + 1) / 2;
            if (calcSlope(comp, state.totalUnderlying18.toInt256(), state.totalBaseLptTimesN.toInt256(), (mid * N_COINS).toInt256()) < 0) {
                hi = mid - 1;
            } else low = mid;
        }
        // forgefmt: disable-end
        return low;
    }

    /// @notice Calculate the slope of the swap function `f(x)`. Let `g(x)` be the slope of `f(x)`.
    /// @dev See whitepaper for more details. (ref: Pendle whitepaper)
    function calcSlope(
        PoolPreCompute memory comp,
        int256 totalUnderlying18,
        int256 totalBaseLptTimesN,
        int256 baseLptToPoolTimesN
    ) internal pure returns (int256) {
        int256 diffAssetBaseLptToPool = totalUnderlying18 - baseLptToPoolTimesN;
        int256 sumLpt = baseLptToPoolTimesN + totalBaseLptTimesN;
        require(diffAssetBaseLptToPool > 0 && sumLpt > 0, "invalid baseLptToPoolTimesN");

        int256 part1 =
            (baseLptToPoolTimesN * (totalBaseLptTimesN + totalUnderlying18)).divWadDown(sumLpt * diffAssetBaseLptToPool);

        int256 part2 = ln(sd(sumLpt.divWadDown(diffAssetBaseLptToPool))).intoInt256();
        int256 part3 = SignedMath.WAD.divWadDown(comp.rateScalar);
        return comp.rateAnchor - (part1 - part2).mulWadDown(part3);
    }

    /// @dev Taken from OpenZeppelin's SignedMath library
    function abs(int256 n) internal pure returns (uint256) {
        unchecked {
            // must be unchecked in order to support `n = type(int256).min`
            return uint256(n >= 0 ? n : -n);
        }
    }
}
