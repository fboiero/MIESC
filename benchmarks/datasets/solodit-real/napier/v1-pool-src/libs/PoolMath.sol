// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.10;

/// @notice This library contains the math used in NapierPool.
/// @dev Taken and modified from Pendle V2: https://github.com/pendle-finance/pendle-core-v2-public/blob/163783b09014e515b645b83936fec32c5731d092/contracts/core/Market/MarketMathCore.sol
/// @dev Taken and modified from Notional : https://github.com/notional-finance/contracts-v2/blob/1845605ab0d9eec9b5dd374cf7c246957b534f85/contracts/internal/markets/Market.sol
/// @dev Naming convention:
/// - `pt` => baseLpt: BasePool LP token
/// - `asset` => `underlying`: underlying asset
/// - `totalPt` => `totalBaseLptTimesN`: total BasePool LP token reserve in the pool multiplied by the number of BasePool assets (N)
/// See NapierPool.sol for more details.
/// - `totalAsset` => `totalUnderlying`: total underlying asset reserve in the pool
/// - `executeTradeCore` function =>  `executeSwap` function
/// - `calculateTrade` function => `calculateSwap` function
/// - `getMarketPreCompute` function => `computeAmmParameters` function
/// - `setNewMarketStateTrade` function => `_setPostPoolState` function
/// @dev All functions in this library are view functions.
/// @dev Changes:
///  1) Math library dependency from LogExpMath to PRBMath etc.
///  2) Swap functions multiply the parameter `exactPtToAccount` by N(=3) to make it equivalent to the amount of PT being swapped.
///  3) Swap functions divide the computed underlying swap result by N.
///  3) Remove some redundant checks (e.g. check for maturity)
///  4) Remove some redundant variables (e.g. `totalAsset` in `MarketPreCompute`)
///  5) Remove some redundant functions (`addLiquidity` and `removeLiquidity`)

// libraries
import {Math} from "@openzeppelin/contracts@4.9.3/utils/math/Math.sol";
import {SafeCast} from "@openzeppelin/contracts@4.9.3/utils/math/SafeCast.sol";
import {FixedPointMathLib} from "./FixedPointMathLib.sol";
import {SignedMath} from "./SignedMath.sol";
import {sd, ln, intoInt256} from "@prb/math/SD59x18.sol"; // used for logarithm operation
import {ud, exp, intoUint256} from "@prb/math/UD60x18.sol"; // used for exp operation
import {Errors} from "./Errors.sol";

/// @param totalBaseLptTimesN - Reserve Curve v2 Tricrypto 3PrincipalToken Pool LP token x times N(=# of Curve v2 Pool assets) in 18 decimals
/// @param totalUnderlying18 - Reserve underlying asset in 18 decimals
/// @param scalarRoot - Scalar root for NapierPool (See whitepaper)
/// @param maturity - Expiry of NapierPool (Unix timestamp)
/// @param lnFeeRateRoot - Logarithmic fee rate root
/// @param protocolFeePercent - Protocol fee percent (base 100)
/// @param lastLnImpliedRate - Last ln implied rate
struct PoolState {
    uint256 totalBaseLptTimesN;
    uint256 totalUnderlying18;
    /// immutable variables ///
    uint256 scalarRoot;
    uint256 maturity;
    /// fee data ///
    uint256 lnFeeRateRoot;
    uint256 protocolFeePercent; // 100=100%
    /// last trade data ///
    uint256 lastLnImpliedRate;
}

/// @notice Variables that are used to compute the swap result
/// @dev params that are expensive to compute, therefore we pre-compute them
struct PoolPreCompute {
    int256 rateScalar;
    int256 rateAnchor;
    int256 feeRate;
}

/// @title PoolMath - library for calculating swaps
/// @notice Taken and modified from Pendle V2: https://github.com/pendle-finance/pendle-core-v2-public/blob/163783b09014e515b645b83936fec32c5731d092/contracts/core/Market/MarketMathCore.sol
/// @dev Swaps take place between the BasePool LP token and the underlying asset.
/// The BasePool LP token is basket of 3 principal tokens.
/// @dev The AMM formula is defined in terms of the amount of PT being swapped.
/// @dev The math assumes two tokens (pt and underlying) have same decimals. Need to convert if they have different decimals.
/// @dev All functions in this library are view functions.
library PoolMath {
    /// @notice Minimum liquidity in the pool
    uint256 internal constant MINIMUM_LIQUIDITY = 10 ** 3;
    /// @notice Percentage base (100=100%)
    int256 internal constant FULL_PERCENTAGE = 100;
    /// @notice Day in seconds in Unix timestamp
    uint256 internal constant DAY = 86400;
    /// @notice Year in seconds in Unix timestamp
    uint256 internal constant IMPLIED_RATE_TIME = 365 * DAY;

    /// @notice Max proportion of BasePool LP token / (BasePool LP token + underlying asset) in the pool
    uint256 internal constant MAX_POOL_PROPORTION = 0.96 * 1e18; // 96%

    int256 internal constant N_COINS = 3;

    using FixedPointMathLib for uint256;
    using SignedMath for int256;
    using SignedMath for uint256;
    using SafeCast for uint256;
    using SafeCast for int256;

    /// @param pool State - pool state of the pool
    /// @param exactBaseLptIn - exact amount of Base Pool LP tokens to be swapped in
    /// @return underlyingOut18 - underlying tokens to be swapped out (18 decimals)
    /// @return swapFee18 - swap fee in underlying (18 decimals)
    /// @return protocolFee18 - protocol fee in underlying (18 decimals)
    function swapExactBaseLpTokenForUnderlying(PoolState memory pool, uint256 exactBaseLptIn)
        internal
        view
        returns (uint256 underlyingOut18, uint256 swapFee18, uint256 protocolFee18)
    {
        (int256 _netUnderlyingToAccount18, int256 _netUnderlyingFee18, int256 _netUnderlyingToProtocol18) = executeSwap(
            pool,
            // Note: sign is defined from the perspective of the swapper.
            // negative because the swapper is selling pt
            // Note: Here we are multiplying by N_COINS because the swap formula is defined in terms of the amount of PT being swapped.
            // BaseLpt is equivalent to 3 times the amount of PT due to the initial deposit of 1:1:1:1=pt1:pt2:pt3:Lp share in Curve pool.
            exactBaseLptIn.neg() * N_COINS
        );

        underlyingOut18 = _netUnderlyingToAccount18.toUint256();
        swapFee18 = _netUnderlyingFee18.toUint256();
        protocolFee18 = _netUnderlyingToProtocol18.toUint256();
    }

    /// @param pool State - pool state of the pool
    /// @param exactBaseLptOut exact amount of Base Pool LP tokens to be swapped out
    /// @return underlyingIn18 - underlying tokens to be swapped in (18 decimals)
    /// @return swapFee18 - swap fee in underlying (18 decimals)
    /// @return protocolFee18 - protocol fee in underlying (18 decimals)
    function swapUnderlyingForExactBaseLpToken(PoolState memory pool, uint256 exactBaseLptOut)
        internal
        view
        returns (uint256 underlyingIn18, uint256 swapFee18, uint256 protocolFee18)
    {
        (int256 _netUnderlyingToAccount18, int256 _netUnderlyingFee18, int256 _netUnderlyingToProtocol18) = executeSwap(
            pool,
            // Note: sign is defined from the perspective of the swapper.
            // positive because the swapper is buying pt
            exactBaseLptOut.toInt256() * N_COINS
        );

        underlyingIn18 = _netUnderlyingToAccount18.neg().toUint256();
        swapFee18 = _netUnderlyingFee18.toUint256();
        protocolFee18 = _netUnderlyingToProtocol18.toUint256();
    }

    /// @notice Compute swap result given the amount of base pool LP tokens to be swapped in.
    /// @dev This function is used to compute the swap result before the swap is executed.
    /// @param pool State - pool state of the pool
    /// @param netBaseLptToAccount (int256) amount of base pool LP tokens to be swapped in (negative if selling pt) multiplied by the number of BasePool assets
    /// Note: sign is defined from the perspective of the swapper. positive if the swapper is buying pt.
    /// @return netUnderlyingToAccount18 (int256) amount of underlying tokens to be swapped out
    /// @return netUnderlyingFee18 (int256) total fee. including protocol fee.
    /// `netUnderlyingFee18 - netUnderlyingToProtocol` will be distributed to LP holders.
    /// @return netUnderlyingToProtocol18 (int256) Protocol fee
    function executeSwap(PoolState memory pool, int256 netBaseLptToAccount)
        internal
        view
        returns (int256 netUnderlyingToAccount18, int256 netUnderlyingFee18, int256 netUnderlyingToProtocol18)
    {
        if (pool.totalBaseLptTimesN.toInt256() <= netBaseLptToAccount) {
            revert Errors.PoolInsufficientBaseLptForTrade();
        }

        /// ------------------------------------------------------------
        /// MATH
        /// ------------------------------------------------------------
        PoolPreCompute memory comp = computeAmmParameters(pool);

        (netUnderlyingToAccount18, netUnderlyingFee18, netUnderlyingToProtocol18) =
            calculateSwap(pool, comp, netBaseLptToAccount);
        /// ------------------------------------------------------------
        /// WRITE
        /// ------------------------------------------------------------
        _setPostPoolState(pool, comp, netBaseLptToAccount, netUnderlyingToAccount18, netUnderlyingToProtocol18);
    }

    /// @notice Compute the pseudo invariant of the pool.
    /// @dev The pseudo invariant is computed every swap before the swap is executed.
    /// @param pool State - pool state of the pool
    function computeAmmParameters(PoolState memory pool) internal view returns (PoolPreCompute memory cache) {
        uint256 timeToExpiry = pool.maturity - block.timestamp;

        cache.rateScalar = _getRateScalar(pool, timeToExpiry);
        cache.rateAnchor = _getRateAnchor(
            pool.totalBaseLptTimesN, pool.lastLnImpliedRate, pool.totalUnderlying18, cache.rateScalar, timeToExpiry
        );
        cache.feeRate = _getExchangeRateFromImpliedRate(pool.lnFeeRateRoot, timeToExpiry);
    }

    /// @notice Calculate the new `RateAnchor(t)` based on the pre-trade implied rate, `lastImpliedRate`, before the swap.
    /// To ensure interest rate continuity, we adjust the `rateAnchor(t)` such that the pre-trade implied rate at t* remains the same as `lastImpliedRate`.
    ///
    /// Formulas for `rateAnchor(t)`:
    /// ----------------------------
    /// yearsToExpiry(t) = timeToExpiry / 365 days
    ///
    /// portion(t*) = totalBaseLptTimesN / (totalBaseLptTimesN + totalUnderlying18)
    ///
    /// extRate(t*) = lastImpliedRate^(yearsToExpiry(t))
    ///              = e^(ln(lastImpliedRate) * yearsToExpiry(t))
    ///
    /// rateAnchor(t) = extRate(t*) - ln(portion(t*)) / rateScalar(t)
    /// ----------------------------
    /// Where `portion(t*)` represents the portion of the pool that is BasePool LP token at t* and `extRate(t*)` is the exchange rate at t*.
    ///
    /// @param totalBaseLptTimesN total Base Lp token in the pool
    /// @param lastLnImpliedRate the implied rate for the last trade that occurred at t_last.
    /// @param totalUnderlying18 total underlying in the pool
    /// @param rateScalar a parameter of swap formula. Calculated as  `scalarRoot` divided by `yearsToExpiry`
    /// @param timeToExpiry time to maturity in seconds
    /// @return rateAnchor the new rate anchor
    function _getRateAnchor(
        uint256 totalBaseLptTimesN,
        uint256 lastLnImpliedRate,
        uint256 totalUnderlying18,
        int256 rateScalar,
        uint256 timeToExpiry
    ) internal pure returns (int256 rateAnchor) {
        // `extRate(t*) = e^(lastLnImpliedRate * yearsToExpiry(t))`
        // Get pre-trade exchange rate with zero-fee
        int256 preTradeExchangeRate = _getExchangeRateFromImpliedRate(lastLnImpliedRate, timeToExpiry);
        // exchangeRate should not be below 1.
        // But it is mathematically almost impossible to happen because `exp(x) < 1` is satisfied for all `x < 0`.
        // Here x = lastLnImpliedRate * yearsToExpiry(t), which is very unlikely to be negative.(or
        // more accurately the natural log rounds down to zero). `lastLnImpliedRate` is guaranteed to be positive when it is set
        // and `yearsToExpiry(t)` is guaranteed to be positive because swap can only happen before maturity.
        // We still check for this case to be safe.
        require(preTradeExchangeRate > SignedMath.WAD);
        uint256 proportion = totalBaseLptTimesN.divWadDown(totalBaseLptTimesN + totalUnderlying18);
        int256 lnProportion = _logProportion(proportion);

        // Compute `rateAnchor(t) = extRate(t*) - ln(portion(t*)) / rateScalar(t)`
        rateAnchor = preTradeExchangeRate - lnProportion.divWadDown(rateScalar);
    }

    /// @notice Converts an implied rate to an exchange rate given a time to maturity. The
    /// @dev Formula: `E = e^rt`
    /// @return exchangeRate the price of underlying token in Base LP token. Guaranteed to be positive or zero.
    function _getExchangeRateFromImpliedRate(uint256 lnImpliedRate, uint256 timeToExpiry)
        internal
        pure
        returns (int256 exchangeRate)
    {
        uint256 rt = (lnImpliedRate * timeToExpiry) / IMPLIED_RATE_TIME;
        exchangeRate = exp(ud(rt)).intoUint256().toInt256();
    }

    /// @notice Compute swap result given the delta of baseLpt an swapper wants to swap.
    /// @param pool State - pool state of the pool
    /// @param comp PreCompute - pre-computed values of the pool
    /// @param netBaseLptToAccount the delta of baseLpt the swapper wants to swap.
    /// @dev Note: Ensure that abs(`netBaseLptToAccount`) is not greater than `totalBaseLptTimesN`.
    /// @return netUnderlyingToAccount18 the amount of underlying the swapper will receive
    /// negative if the swapper is selling BaseLpt and positive if the swapper is buying BaseLpt.
    /// @return underlyingFee18 the amount of underlying charged as swap fee
    /// this includes `underlyingToProtocol18`
    /// @return underlyingToProtocol18 the amount of underlying the Pool fee recipient will receive as fee
    /// Protocol accrues fee in underlying.
    function calculateSwap(
        PoolState memory pool,
        PoolPreCompute memory comp,
        int256 netBaseLptToAccount // d_pt
    ) internal pure returns (int256, int256, int256) {
        // Calculates the exchange rate from underlying to baseLpt before any fees are applied
        // Note: The exchange rate is int type but it must be always strictly gt 1.
        // Note: `netBaseLptToAccount` should be checked prior to calling this function
        int256 preFeeExchangeRate = _getExchangeRate(
            pool.totalBaseLptTimesN, pool.totalUnderlying18, comp.rateScalar, comp.rateAnchor, netBaseLptToAccount
        ).toInt256();

        // Basically swap formula is:
        //                                 netBaseLptToAccount
        // netUnderlyingToAccount18 = -1 * ────────────────────────
        //                                       extRate
        // where `netBaseLptToAccount` is the delta of baseLpt (`d_pt`) and `netUnderlyingToAccount18` is the delta of underlying (`d_u`).
        // because if `d_pt > 0`, then `d_u < 0` and vice versa.
        // fees can be applied to the `extRate`.
        // `postFeeExchangeRate = preFeeExchangeRate / feeRate` if `netBaseLptToAccount > 0` else `postFeeExchangeRate = preFeeExchangeRate * feeRate`
        int256 netUnderlying18 = netBaseLptToAccount.divWadDown(preFeeExchangeRate).neg();

        // See whitepaper for the formula:
        // fee is calculated as the difference between the underlying amount before and after the fee is applied:
        // fee = underlyingNoFee - underlyingWithFee
        // where `underlyingNoFee = - (ptToAccount / preFeeExchangeRate)`
        // and `underlyingWithFee = - (ptToAccount / postFeeExchangeRate)`
        //
        // Therefore:
        // fee = - (ptToAccount / preFeeExchangeRate) + (ptToAccount / postFeeExchangeRate)
        int256 underlyingFee18;
        if (netBaseLptToAccount > 0) {
            // User swap underlying for baseLpt
            // Exchange rate after fee is applied is:
            //  `postFeeExchangeRate := preFeeExchangeRate / feeRate`
            //  `postFeeExchangeRate` must be strictly gt 1.
            // It's possible that the fee pushes the implied rate into negative territory. This is not allowed.
            int256 postFeeExchangeRate = preFeeExchangeRate.divWadDown(comp.feeRate);
            if (postFeeExchangeRate < SignedMath.WAD) revert Errors.PoolExchangeRateBelowOne(postFeeExchangeRate);

            // fee = - (ptToAccount / preFeeExchangeRate) + (ptToAccount / postFeeExchangeRate)
            //     = (ptToAccount / preFeeExchangeRate) * (feeRate - 1)
            //     = netUnderlying18 * (feeRate - 1)
            underlyingFee18 = netUnderlying18.mulWadDown(SignedMath.WAD - comp.feeRate);
        } else {
            // User swap baseLpt for underlying
            // Exchange rate after fee is applied is:
            //  `postFeeExchangeRate := preFeeExchangeRate * feeRate`
            // In this case, `postFeeExchangeRate` can't be below 1 unlike the case above.

            // fee = - (ptToAccount / preFeeExchangeRate) + (ptToAccount / postFeeExchangeRate)
            //     = - (ptToAccount / preFeeExchangeRate) + (ptToAccount / (preFeeExchangeRate * feeRate))
            //     = - (ptToAccount / preFeeExchangeRate) * (1 - 1 / feeRate)
            //     = - (ptToAccount / preFeeExchangeRate) * (feeRate - 1) / feeRate
            // Note: ptToAccount is negative in this branch so we negate it to ensure that fee is a positive number
            underlyingFee18 = ((netUnderlying18 * (SignedMath.WAD - comp.feeRate)) / comp.feeRate).neg();
        }

        // Subtract swap fee
        // underlyingWithFee = underlyingNoFee - fee
        int256 netUnderlyingToAccount18 = netUnderlying18 - underlyingFee18;
        // Charge protocol fee on swap fee
        // This underlying will be removed from the pool reserve
        int256 underlyingToProtocol18 = (underlyingFee18 * pool.protocolFeePercent.toInt256()) / FULL_PERCENTAGE;

        return (netUnderlyingToAccount18, underlyingFee18, underlyingToProtocol18);
    }

    /// @notice Update pool state cache after swap is executed
    /// @param pool pool state of the pool
    /// @param comp swap formula pre-computed values
    /// @param netBaseLptToAccount net Base Lpt to account. negative if the swapper is selling BaseLpt
    /// @param netUnderlyingToAccount18 net underlying to account. positive if the swapper is selling BaseLpt.
    /// @param netUnderlyingToProtocol18 should be removed from the pool reserve `totalUnderlying18`. must be positive
    function _setPostPoolState(
        PoolState memory pool,
        PoolPreCompute memory comp,
        int256 netBaseLptToAccount,
        int256 netUnderlyingToAccount18,
        int256 netUnderlyingToProtocol18
    ) internal view {
        // update pool state
        // Note safe because pre-trade check ensures totalBaseLptTimesN >= netBaseLptToAccount
        pool.totalBaseLptTimesN = (pool.totalBaseLptTimesN.toInt256() - netBaseLptToAccount).toUint256();
        pool.totalUnderlying18 = (pool.totalUnderlying18).toInt256().subNoNeg(
            netUnderlyingToAccount18 + netUnderlyingToProtocol18
        ).toUint256();
        // compute post-trade implied rate
        // this will be used to compute the new rateAnchor for the next trade
        uint256 timeToExpiry = pool.maturity - block.timestamp;
        pool.lastLnImpliedRate = _getLnImpliedRate(
            pool.totalBaseLptTimesN, pool.totalUnderlying18, comp.rateScalar, comp.rateAnchor, timeToExpiry
        );
        // It's technically unlikely that the implied rate is actually exactly zero but we will still fail
        // in this case.
        if (pool.lastLnImpliedRate == 0) revert Errors.PoolZeroLnImpliedRate();
    }

    /// @notice Get rate scalar given the pool state and time to maturity.
    /// @dev Formula: `scalarRoot * ONE_YEAR / yearsToExpiry`
    function _getRateScalar(PoolState memory pool, uint256 timeToExpiry) internal pure returns (int256) {
        uint256 rateScalar = (pool.scalarRoot * IMPLIED_RATE_TIME) / timeToExpiry;
        if (rateScalar == 0) revert Errors.PoolRateScalarZero();
        return rateScalar.toInt256();
    }

    /// @notice Calculates the current pool implied rate.
    /// ln(extRate) * ONE_YEAR / timeToExpiry
    /// @return lnImpliedRate the implied rate
    function _getLnImpliedRate(
        uint256 totalBaseLptTimesN,
        uint256 totalUnderlying18,
        int256 rateScalar,
        int256 rateAnchor,
        uint256 timeToExpiry
    ) internal pure returns (uint256 lnImpliedRate) {
        // This should ensure that exchange rate < FixedPointMathLib.WAD
        int256 exchangeRate =
            _getExchangeRate(totalBaseLptTimesN, totalUnderlying18, rateScalar, rateAnchor, 0).toInt256();

        // exchangeRate >= 1 so its ln(extRate) >= 0
        int256 lnRate = ln(sd(exchangeRate)).intoInt256();

        lnImpliedRate = (uint256(lnRate) * IMPLIED_RATE_TIME) / timeToExpiry;
    }

    /// @notice Calculates exchange rate given the total baseLpt and total underlying.
    ///     (1 / rateScalar) * ln(proportion / (1 - proportion)) + rateAnchor
    /// where:
    ///     proportion = totalPt / (totalPt + totalUnderlying)
    ///
    /// @dev Revert if the exchange rate is below 1. Prevent users from swapping when 1 baseLpt is worth more than 1 underlying.
    /// @dev Revert if the proportion of baseLpt to total is greater than MAX_POOL_PROPORTION.
    /// @param totalBaseLptTimesN the total baseLpt in the pool
    /// @param totalUnderlying18 the total underlying in the pool
    /// @param rateScalar the scalar used to compute the exchange rate
    /// @param rateAnchor the anchor used to compute the exchange rate
    /// @param netBaseLptToAccount the net baseLpt to the account (negative if account is swapping baseLpt for underlying)
    /// @return exchangeRate the price of underlying token in terms of Base LP token
    function _getExchangeRate(
        uint256 totalBaseLptTimesN,
        uint256 totalUnderlying18,
        int256 rateScalar,
        int256 rateAnchor,
        int256 netBaseLptToAccount
    ) internal pure returns (uint256) {
        // Revert if there is not enough baseLpt to support this swap.
        // Note: Ensure that abs(`netBaseLptToAccount`) is not greater than `totalBaseLptTimesN` before calling this function
        uint256 numerator = (totalBaseLptTimesN.toInt256() - netBaseLptToAccount).toUint256();
        uint256 proportion = numerator.divWadDown(totalBaseLptTimesN + totalUnderlying18);

        if (proportion > MAX_POOL_PROPORTION) {
            revert Errors.PoolProportionTooHigh();
        }

        int256 lnProportion = _logProportion(proportion);

        int256 exchangeRate = lnProportion.divWadDown(rateScalar) + rateAnchor;
        if (exchangeRate < int256(FixedPointMathLib.WAD)) revert Errors.PoolExchangeRateBelowOne(exchangeRate);
        return exchangeRate.toUint256();
    }

    /// @notice Compute Logit function (log(p/(1-p)) given a proportion `p`.
    /// @param proportion the proportion of baseLpt to (baseLpt + underlying) (0 <= proportion <= 1e18)
    function _logProportion(uint256 proportion) internal pure returns (int256 logitP) {
        if (proportion == FixedPointMathLib.WAD) revert Errors.PoolProportionMustNotEqualOne();

        // input = p/(1-p)
        int256 input = proportion.divWadDown(FixedPointMathLib.WAD - proportion).toInt256();
        // logit(p) = log(input) = ln(p/(1-p))
        logitP = ln(sd(input)).intoInt256();
    }

    /// @notice Compute the initial implied rate of the pool.
    /// @dev This function is expected to be called only once when initial liquidity is added.
    /// @param pool pool state of the pool
    /// @param initialAnchor initial anchor of the pool
    /// @return initialLnImpliedRate the initial implied rate
    function computeInitialLnImpliedRate(PoolState memory pool, int256 initialAnchor) internal view returns (uint256) {
        uint256 timeToExpiry = pool.maturity - block.timestamp;
        int256 rateScalar = _getRateScalar(pool, timeToExpiry);

        return
            _getLnImpliedRate(pool.totalBaseLptTimesN, pool.totalUnderlying18, rateScalar, initialAnchor, timeToExpiry);
    }
}
