// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.10;

// interfaces
import {IERC20Metadata} from "@openzeppelin/contracts@4.9.3/token/ERC20/extensions/IERC20Metadata.sol";
import {CurveTricryptoOptimizedWETH} from "../interfaces/external/CurveTricryptoOptimizedWETH.sol";
import {IBaseAdapter} from "@napier/napier-v1/src/interfaces/IBaseAdapter.sol";
import {ITranche} from "@napier/napier-v1/src/interfaces/ITranche.sol";
import {IPoolFactory} from "../interfaces/IPoolFactory.sol";
import {INapierPool} from "../interfaces/INapierPool.sol";

import {ApproxParams} from "./ApproxParams.sol";
import {IQuoter} from "../interfaces/IQuoter.sol";
import {INapierSwapCallback} from "../interfaces/INapierSwapCallback.sol";
import {INapierMintCallback} from "../interfaces/INapierMintCallback.sol";
// libraries
import {LibApproximation} from "./LibApproximation.sol";
import {PoolState, PoolPreCompute, PoolMath} from "../libs/PoolMath.sol";
import {CallbackType, CallbackDataTypes} from "../libs/CallbackDataTypes.sol";

import {SafeCast} from "@openzeppelin/contracts@4.9.3/utils/math/SafeCast.sol";
import {SignedMath} from "@openzeppelin/contracts@4.9.3/utils/math/SignedMath.sol";
import {DecimalConversion} from "../libs/DecimalConversion.sol";
import {MAX_BPS} from "@napier/napier-v1/src/Constants.sol";
import {Errors} from "../libs/Errors.sol";

/// @title Provides quotes for swaps and price of principal tokens
/// @notice Allows getting the expected amount out or amount in for a given swap without executing the swap
/// @dev These functions are not gas efficient and should _not_ be called on chain.
/// @dev Inspired by Uniswap V3 QuoterV2 https://github.com/Uniswap/v3-periphery/blob/main/contracts/lens/QuoterV2.sol
contract Quoter is IQuoter, INapierSwapCallback, INapierMintCallback {
    using DecimalConversion for uint256;
    using SafeCast for uint256;
    using SafeCast for int256;

    uint256 internal constant N_COINS = 3;
    uint256 internal constant WAD = 1e18;

    IPoolFactory public immutable factory;

    constructor(IPoolFactory _factory) {
        factory = _factory;
    }

    function getPoolAssets(INapierPool pool) public view returns (IPoolFactory.PoolAssets memory assets) {
        assets = factory.getPoolAssets(address(pool));
        if (assets.underlying == address(0)) revert Errors.RouterPoolNotFound();
    }

    function mintCallback(uint256, uint256, bytes calldata) external view override {
        // Assume this contract doesn't have the LP token before minting.
        // Revert containing the quote.
        uint256 liquidity = IERC20Metadata(msg.sender).balanceOf(address(this));
        _revertWithQuoteData(liquidity);
    }

    /// @dev Intentionally always reverts with data containing the quote
    function swapCallback(int256 underlyingDelta, int256 ptDelta, bytes calldata data) external view override {
        IPoolFactory.PoolAssets memory assets = getPoolAssets(INapierPool(msg.sender));
        CallbackType _type = CallbackDataTypes.getCallbackType(data);

        /// ----------------- PrincipalToken <> Underlying -----------------
        if (_type == CallbackType.SwapUnderlyingForPt || _type == CallbackType.SwapPtForUnderlying) {
            // Revert containing the quote and early return
            _revertWithQuoteData(SignedMath.abs(underlyingDelta));
        }

        /// ----------------- YieldToken <> Underlying -----------------
        // Decode callback data
        // Fetch series and maxscale data
        (uint256 ytDesired, uint256 index) = abi.decode(data[32:], (uint256, uint256));
        ITranche.Series memory series = ITranche(assets.principalTokens[index]).getSeries();
        uint256 cscale = IBaseAdapter(series.adapter).scale();
        if (cscale > series.maxscale) series.maxscale = cscale;

        uint256 netUnderlying; // quote data
        if (_type == CallbackType.SwapYtForUnderlying) {
            // Compute the amount of underlying we would get by redeeming the PT + YT.
            uint256 pyRedeem = ytDesired > ptDelta.toUint256() ? ptDelta.toUint256() : ytDesired; // unsafe cast is okay.
            // Note: We only take into account the underlying redeemed from the PT + YT burn here
            // because Router doesn't have YT balance and any accrued yield.
            // Formula:
            // `u` = An amount of underlying token to be redeemed from the PT + YT burn
            // `p` = An amount of PT and YT to redeem
            // `shares` = Shares to be redeemed from the PT and YT burn equivalent to `u` amount of underlying token
            // `maxscale` = The maximum scale of the series
            // `scale` = The scale of the series
            // ```
            // shares = p / maxscale
            // u = shares * scale
            // ```
            // Solving for `u`:
            // ```
            // u = p * scale / maxscale
            // ```
            uint256 underlyingRedeemed = pyRedeem * cscale / series.maxscale;

            if (underlyingRedeemed < (-underlyingDelta).toUint256()) revert Errors.RouterInsufficientUnderlyingRepay(); // unsafe cast is okay. `underlyingDelta` is negative in this branch
            netUnderlying = underlyingRedeemed - (-underlyingDelta).toUint256();
        } else if (_type == CallbackType.SwapUnderlyingForYt) {
            // Compute the amount of underlying to deposit to get the desired amount of YT
            // Formula: See `NapierRouter.swapUnderlyingForYt`.
            uint256 uDepositNoFee = ytDesired * cscale / series.maxscale;
            uint256 uDeposit = uDepositNoFee * MAX_BPS / (MAX_BPS - (series.issuanceFee + 1)); // 0.01 bps buffer
            // Subtract the amount of underlying we got from the swap
            if (uDeposit > underlyingDelta.toUint256()) {
                netUnderlying = uDeposit - underlyingDelta.toUint256();
            }
        }
        // Revert containing the quote
        _revertWithQuoteData(netUnderlying);
    }

    function _revertWithQuoteData(uint256 value) internal pure {
        assembly {
            let freeMemPtr := mload(0x40)
            mstore(freeMemPtr, value)
            revert(freeMemPtr, 0x20)
        }
    }

    /// @dev Handle a returndata that should contain the numeric quote
    /// @dev If the returndata is not the expected length, bubble up the revert reason.
    function _handleRevert(bytes memory returndata) internal pure returns (uint256) {
        // If length is 0x20, then assume it's a revert with quote data
        if (returndata.length != 0x20) {
            assembly {
                revert(
                    // Start of revert data bytes.
                    add(returndata, 0x20),
                    // Length of revert data.
                    mload(returndata)
                )
            }
        }
        return abi.decode(returndata, (uint256));
    }

    /////////////////////////////////////////////////////////////////////////////////////
    // Price
    /////////////////////////////////////////////////////////////////////////////////////

    /// @notice Returns price of Tricrypto LP token in terms of underlying token  (in 18 decimals)
    function quoteBasePoolLpPrice(INapierPool pool) public view returns (uint256) {
        // Load state
        getPoolAssets(pool); // Verify if pool exists

        // Get internal price of underlying token in terms of Base LP token from last implied rate and time to maturity.
        // Reminder: `lastLnImpliedRate` is the implied rate of the last swap.
        uint256 timeToMaturity = pool.maturity() - block.timestamp;
        uint256 lnImpliedRate = pool.lastLnImpliedRate();

        // `getExchangeRate()` returns the "scaled" (internally used) price of underlying token in Base LP token (in 18 decimals).
        // 1 underlying token worths `getExchangeRate()` divided by `N_COINS` Base LP token.
        return WAD * WAD * N_COINS / PoolMath._getExchangeRateFromImpliedRate(lnImpliedRate, timeToMaturity).toUint256();
    }

    /// @notice Returns price of principal token at index `index` in terms of underlying token  (in 18 decimals)
    function quotePtPrice(INapierPool pool, uint256 index) public view returns (uint256) {
        // Quote price of Base LP token in terms of underlying token
        uint256 underlyingPerLp = quoteBasePoolLpPrice(pool);
        CurveTricryptoOptimizedWETH tricrypto = CurveTricryptoOptimizedWETH(pool.tricrypto());

        // Quote price of principal token at index `i` in Base pool LP token
        // Note: `tricrypto.price_oracle(k)` actually returns the price of the coin at index `k + 1`, not at `k` in terms of coin at index 0, where k is 0 or 1 _not 2_.
        uint256 pt0PerPt = index == 0 ? WAD : tricrypto.price_oracle(index - 1);
        uint256 pt0PerLp = tricrypto.lp_price(); // The price of LP token in terms of the coin at index 0. (in WAD)
        uint256 ptPerLp = pt0PerLp * WAD / pt0PerPt;
        // Convert the price in Base LP token to the price in underlying token
        return underlyingPerLp * WAD / ptPerLp;
    }

    /////////////////////////////////////////////////////////////////////////////////////
    // Quote for Liquidity provision / removal
    /////////////////////////////////////////////////////////////////////////////////////

    /// @notice Returns a quote for adding liquidity to the pool with underlyings and PTs
    /// @return liquidity - Estimated amount of LP tokens received
    /// @return gasEstimate - Estimated gas cost of the transaction
    function quoteAddLiquidity(INapierPool pool, uint256[3] memory ptsIn, uint256 underlyingIn)
        public
        returns (uint256 liquidity, uint256 gasEstimate)
    {
        uint256 _before = gasleft();
        IPoolFactory.PoolAssets memory assets = getPoolAssets(pool);
        // pt amount -> baseLpt amount
        uint256 baseLptToAdd = CurveTricryptoOptimizedWETH(assets.basePool).calc_token_amount(ptsIn, true);
        try pool.addLiquidity(underlyingIn, baseLptToAdd, address(this), abi.encode(CallbackType.AddLiquidityPts)) {}
        catch (bytes memory ret) {
            liquidity = _handleRevert(ret);
            gasEstimate = _before - gasleft();
        }
    }

    /// @notice Returns a quote for adding liquidity to the pool with a single underlying token
    /// @return liquidity - Estimated amount of LP tokens received
    /// @return baseLptSwap - Estimated amount of base pool LP tokens. See `appoxBaseLptToAddLiquidityOneUnderlying` for details.
    function quoteAddLiquidityOneUnderlying(INapierPool pool, uint256 underlyingIn)
        public
        view
        returns (uint256 liquidity, uint256 baseLptSwap)
    {
        baseLptSwap = approxBaseLptToAddLiquidityOneUnderlying(pool, underlyingIn);
        // B: Reserve of base pool LP token before adding liquidity
        // ∆b: Base pool LP token amount to be swapped out
        // L: total Liquidity token amount before adding liquidity
        // s: shares of minted liquidity
        // s ~= L * ∆b / (B - ∆b)
        uint256 totalBaseLpt = pool.totalBaseLpt();
        uint256 totalLiquidity = IERC20Metadata(address(pool)).totalSupply();
        liquidity = totalLiquidity * baseLptSwap / (totalBaseLpt - baseLptSwap);
    }

    /// @notice Returns a quote for adding liquidity to the pool with a single principal token
    /// @return liquidity - Estimated amount of LP tokens received
    /// @return baseLptSwap - Estimated amount of base pool LP tokens. See `appoxBaseLptToAddLiquidityOnePt` for details.
    function quoteAddLiquidityOnePt(INapierPool pool, uint256 index, uint256 ptIn)
        public
        view
        returns (uint256 liquidity, uint256 baseLptSwap)
    {
        // Base pool LP token amount that would be swapped to underlying
        baseLptSwap = approxBaseLptToAddLiquidityOnePt(pool, index, ptIn);

        // Calculate underlying amount that gets from swapping with baseLpt
        PoolState memory state = pool.readState();
        (int256 underlyingAmount,,) =
            PoolMath.calculateSwap(state, PoolMath.computeAmmParameters(state), -(baseLptSwap * N_COINS).toInt256());
        uint256 underlyingIn = SignedMath.abs(underlyingAmount); // always positive

        IPoolFactory.PoolAssets memory assets = getPoolAssets(pool);
        uint8 uDecimals = IERC20Metadata(assets.underlying).decimals();

        // U: Reserve of underlying token amount before adding liquidity
        // ∆u: underlying token amount to be swapped out
        // L: total Liquidity token amount before adding liquidity
        // s: shares of minted liquidity
        // s ~= L * ∆u / (U - ∆u)
        uint256 totalUnderlying = uint256(pool.totalUnderlying()).to18Decimals(uDecimals);
        uint256 totalLiquidity = IERC20Metadata(address(pool)).totalSupply();
        liquidity = totalLiquidity * underlyingIn / (totalUnderlying - underlyingIn);
    }

    /// @notice Returns expected amount of underlying token and Base Pool LP token to be withdrawn for a given amount of liquidity
    /// @dev This is useful for estimating how much Base Pool LP token will be withdrawn.
    function quoteRemoveLiquidityBaseLpt(INapierPool pool, uint256 liquidity) public view returns (uint256, uint256) {
        IPoolFactory.PoolAssets memory assets = getPoolAssets(pool);
        uint8 uDecimals = IERC20Metadata(assets.underlying).decimals();

        // Withdraw underlying and baseLpt from the NapierPool pro rata to the liquidity amount
        (uint256 underlyingWithdrawn18, uint256 baseLptWithdrawn) =
            _getWithdrawalAmounts18(pool, pool.readState(), liquidity);
        return (underlyingWithdrawn18.from18Decimals(uDecimals), baseLptWithdrawn);
    }

    /// @notice Returns expected amount of underlying token and Principal tokens to be withdrawn for a given amount of liquidity
    /// @return The estimated amount of underlying token out
    /// @return The estimated amount of Principal token out for each index
    function quoteRemoveLiquidity(INapierPool pool, uint256 liquidity)
        public
        view
        returns (uint256, uint256[3] memory)
    {
        (uint256 underlyingOut, uint256 baseLptOut) = quoteRemoveLiquidityBaseLpt(pool, liquidity);
        CurveTricryptoOptimizedWETH tricrypto = pool.tricrypto();

        uint256 totSupply = tricrypto.totalSupply();
        uint256[3] memory ptsOut;
        for (uint256 i = 0; i < N_COINS; i++) {
            // Proportionally withdraw principal tokens in Tricrypto
            ptsOut[i] = tricrypto.balances(i) * baseLptOut / totSupply; // balance * share / Σ share_i
        }
        return (underlyingOut, ptsOut);
    }

    /// @notice Returns expected amount of Principal token to be withdrawn for a given amount of liquidity
    /// @return The estimated amount of Principal token out
    /// @return The estimated amount of Base pool LP token to be swapped out (Can be used as `baseLptSwap` in `removeLiquidityOnePt`)
    /// @return The estimated gas cost
    function quoteRemoveLiquidityOnePt(INapierPool pool, uint256 index, uint256 liquidity)
        public
        view
        returns (uint256, uint256, uint256)
    {
        // Approximate the amount of Base LP token to be swapped out to withdraw one principal token
        // Reminder: `removeLiquidityOnePt` withdraw underlying and Base pool LP token from Napier Pool,
        // and then swap the withdrawn underlyings for base pool LP token and withdraw one principal tokens from Tricrypto
        uint256 baseLptSwap = approxBaseLptToRemoveLiquidityOnePt(pool, liquidity); // excluded from gas estimate
        uint256 _before = gasleft();
        (, uint256 baseLptWithdrawn) = quoteRemoveLiquidityBaseLpt(pool, liquidity);
        uint256 ptWithdrawn = pool.tricrypto().calc_withdraw_one_coin(baseLptWithdrawn + baseLptSwap, index);
        uint256 gasEstimate = _before - gasleft();
        return (ptWithdrawn, baseLptSwap, gasEstimate);
    }

    /// @notice Returns expected amount of underlying token to be withdrawn for a given amount of liquidity
    /// @return underlyingOut The estimated amount of underlying token out
    /// @return gasEstimate The estimated gas cost
    function quoteRemoveLiquidityOneUnderlying(INapierPool pool, uint256 index, uint256 liquidity)
        public
        view
        returns (uint256 underlyingOut, uint256 gasEstimate)
    {
        uint256 _before = gasleft();
        IPoolFactory.PoolAssets memory assets = getPoolAssets(pool);
        PoolState memory state = pool.readState();
        uint8 uDecimals = IERC20Metadata(assets.underlying).decimals();

        // Step 1: Simulate withdrawing underlying and baseLPT from NapierPool
        (uint256 uWithdrawn18, uint256 baseLptWithdrawn) = _getWithdrawalAmounts18(pool, state, liquidity);

        // Step 2: Handle immature and mature pool cases
        if (block.timestamp < INapierPool(pool).maturity()) {
            // Update state to reflect the withdrawal amount
            state.totalUnderlying18 -= uWithdrawn18;
            state.totalBaseLptTimesN -= baseLptWithdrawn * N_COINS;
            // Simulate swap after the withdrawal
            (uint256 swappedUnderlying18,,) = PoolMath.swapExactBaseLpTokenForUnderlying(state, baseLptWithdrawn); // note: `state` is modified
            underlyingOut = (uWithdrawn18 + swappedUnderlying18).from18Decimals(uDecimals);
        } else {
            // If the pool is matured, simulate the redemption of the principal token.
            // Withdraw one principal token from the Tricrypto pool
            uint256 ptWithdrawn =
                CurveTricryptoOptimizedWETH(assets.basePool).calc_withdraw_one_coin(baseLptWithdrawn, index);
            uint256 withdrawn = ITranche(assets.principalTokens[index]).previewRedeem(ptWithdrawn);
            underlyingOut = uWithdrawn18.from18Decimals(uDecimals) + withdrawn;
        }

        gasEstimate = _before - gasleft();
    }

    /////////////////////////////////////////////////////////////////////////////////////
    // Swap
    /////////////////////////////////////////////////////////////////////////////////////

    /// @notice Returns expected amount of underlying token out for a given amount of principal token in
    function quotePtForUnderlying(INapierPool pool, uint256 index, uint256 ptIn)
        public
        returns (uint256 underlyingOut, uint256 gasEstimate)
    {
        uint256 _before = gasleft();
        try pool.swapPtForUnderlying(index, ptIn, address(this), abi.encode(CallbackType.SwapPtForUnderlying)) {}
        catch (bytes memory ret) {
            underlyingOut = _handleRevert(ret);
            gasEstimate = _before - gasleft();
        }
    }

    /// @notice Returns expected amount of underlying token in for a given amount of principal token out
    function quoteUnderlyingForPt(INapierPool pool, uint256 index, uint256 ptOutDesired)
        public
        returns (uint256 underlyingIn, uint256 gasEstimate)
    {
        uint256 _before = gasleft();

        try pool.swapUnderlyingForPt(index, ptOutDesired, address(this), abi.encode(CallbackType.SwapUnderlyingForPt)) {}
        catch (bytes memory ret) {
            underlyingIn = _handleRevert(ret);
            gasEstimate = _before - gasleft();
        }
    }

    /// @notice Returns expected amount of underlying token out for a given amount of yield token in
    function quoteYtForUnderlying(INapierPool pool, uint256 index, uint256 ytIn)
        public
        returns (uint256 underlyingOut, uint256 gasEstimate)
    {
        uint256 _before = gasleft();
        bytes memory data = abi.encode(CallbackType.SwapYtForUnderlying, ytIn, index);
        try INapierPool(pool).swapUnderlyingForPt(
            index,
            ytIn, // ptOutDesired
            address(this),
            data
        ) {} catch (bytes memory ret) {
            underlyingOut = _handleRevert(ret);
            gasEstimate = _before - gasleft();
        }
    }

    /// @notice Returns expected amount of underlying token out spent a given amount of yield token
    function quoteUnderlyingForYt(INapierPool pool, uint256 index, uint256 ytOut)
        public
        returns (uint256 underlyingIn, uint256 gasEstimate)
    {
        uint256 _before = gasleft();

        bytes memory data = abi.encode(CallbackType.SwapUnderlyingForYt, ytOut, index);
        try INapierPool(pool).swapPtForUnderlying(
            index,
            ytOut, // ptInDesired
            address(this),
            data
        ) {} catch (bytes memory ret) {
            underlyingIn = _handleRevert(ret);
            gasEstimate = _before - gasleft();
        }
    }

    /////////////////////////////////////////////////////////////////////////////////////
    // Approximation
    /////////////////////////////////////////////////////////////////////////////////////

    /// @notice Estimate pt in desired for exact underlying out (1%~ approximation error)
    /// @dev The returned value can be used as `ptInDesired` in `router.swapPtForUnderlying` to get `underlyingOut` exactly.
    /// @param pool The pool to swap on
    /// @param index The index of the principal token
    /// @param underlyingDesired The underlying amount out desired
    /// @return The estimated amount of principal token in
    function approxPtForExactUnderlyingOut(INapierPool pool, uint256 index, uint256 underlyingDesired)
        public
        view
        returns (uint256)
    {
        // Load state
        IPoolFactory.PoolAssets memory assets = getPoolAssets(pool);
        PoolState memory state = pool.readState();
        uint8 uDecimals = IERC20Metadata(assets.underlying).decimals();

        // underlyingDesired -> estimated baseLpt amount
        uint256 estimated = LibApproximation.approxSwapBaseLptForExactUnderlying(
            state,
            underlyingDesired.to18Decimals(uDecimals), // convert to 18 decimals
            defaultApprox()
        );
        // baseLpt amount -> estimated ith pt amount
        // Hack: Tricrypto doesn't provide a function to estimate the amount of principal token needed for a given liquidity amount.
        return CurveTricryptoOptimizedWETH(assets.basePool).calc_withdraw_one_coin(estimated, index);
    }

    /// @notice Estimate pt out desired for exact underlying in (1%~ approximation error)
    /// @dev The returned value can be used as `ptOutDesired` in `router.swapUnderlyingForPt` to get `underlyingIn` exactly.
    /// @param pool The pool to swap on
    /// @param index The index of the principal token
    /// @param underlyingDesired The underlying amount in desired
    /// @return The estimated amount of principal token out
    function approxPtForExactUnderlyingIn(INapierPool pool, uint256 index, uint256 underlyingDesired)
        public
        view
        returns (uint256)
    {
        // Load state
        IPoolFactory.PoolAssets memory assets = getPoolAssets(pool);
        PoolState memory state = pool.readState();
        uint8 uDecimals = IERC20Metadata(assets.underlying).decimals();

        // baseLpt amount -> pt amount
        uint256 estimated = LibApproximation.approxSwapExactUnderlyingForBaseLpt(
            state,
            underlyingDesired.to18Decimals(uDecimals), // convert to 18 decimals
            defaultApprox()
        );
        return CurveTricryptoOptimizedWETH(assets.basePool).calc_withdraw_one_coin(estimated, index);
    }

    /// @notice Estimate yt for exact underlying out (1%~ approximation error)
    /// @dev The returned value can be used as `ytInDesired` in `router.swapYtForUnderlying` to get `underlyingDesired` exactly.
    /// @dev Note: This method is mutative because it simulates the swap by calling mutative function though compiler warns it's not.
    /// @dev Revert conditions:
    /// - If the price of the principal token get close or higher than 1, revert with `RouterInsufficientUnderlyingRepay`.
    /// - If `underlyingDesired` is substantial enough to exceed the configured upper limit of the bisect method, revert with `ApproxFail`.
    /// @param pool The pool to swap on
    /// @param index The index of the principal token
    /// @param underlyingDesired The underlying amount out desired
    /// @return The estimated amount of yt in
    function approxYtForExactUnderlyingOut(INapierPool pool, uint256 index, uint256 underlyingDesired)
        public
        returns (uint256)
    {
        // Load state
        IPoolFactory.PoolAssets memory assets = getPoolAssets(pool);
        uint256 oneUnderlying = 10 ** IERC20Metadata(assets.underlying).decimals();

        ApproxParams memory approx = defaultApprox();
        approx.guessMax = _findMaxPtOut(pool, index, oneUnderlying / 100); // setting 1/100 of 1 underlying as an initial guess
        bytes memory args = abi.encode(pool, index);
        // Hack: Cast is needed because internal function to pass is mutative though `bisect` requires view function.
        return Casts.asMutativeFn(LibApproximation.bisect)(
            args, computeRelErrorYtForExactUnderlyingOut, underlyingDesired, approx
        );
    }

    function computeRelErrorYtForExactUnderlyingOut(uint256 midpoint, bytes memory args, uint256 underlyingDesired)
        private
        returns (int256)
    {
        (INapierPool pool, uint256 index) = abi.decode(args, (INapierPool, uint256));
        (uint256 underlyingOut,) = quoteYtForUnderlying(pool, index, midpoint);
        return 1e18 - (underlyingOut * 1e18 / underlyingDesired).toInt256();
    }

    /// @notice Estimate yt for exact underlying in.
    /// @dev The returned value can be used as `ytOutDesired` in `router.swapUnderlyingForYt` to spend `underlyingDesired` exactly.
    /// @dev Revert conditions:
    /// - If `underlyingDesired` is too large and impossible to find yt needed for the given `underlyingDesired`, revert with `ApproxFail`.
    /// - If we get more underlying than the amount we need to deposit to issue the YT, revert with `ApproxFailWithHint("No underlying deposit required")`.
    /// @param pool The pool to swap on
    /// @param index The index of the principal token
    /// @param underlyingDesired The desired amount of underlying token to spend
    /// @return The estimated amount of yt in
    function approxYtForExactUnderlyingIn(INapierPool pool, uint256 index, uint256 underlyingDesired)
        public
        returns (uint256)
    {
        ApproxParams memory approx = defaultApprox();
        approx.guessMin = 0; // price of principal token can be lower than 1 (in terms of underlying) if the pool is not balanced.
        approx.guessMax = _findMaxPtIn(pool, index, underlyingDesired); // find a reasonable upper limit.
        bytes memory args = abi.encode(pool, index);
        return Casts.asMutativeFn(LibApproximation.bisect)(
            args, computeRelErrorYtForExactUnderlyingIn, underlyingDesired, approx
        );
    }

    function computeRelErrorYtForExactUnderlyingIn(uint256 midpoint, bytes memory args, uint256 underlyingDesired)
        private
        returns (int256)
    {
        (INapierPool pool, uint256 index) = abi.decode(args, (INapierPool, uint256));
        (uint256 underlyingIn,) = quoteUnderlyingForYt(pool, index, midpoint);
        if (underlyingIn == 0) revert Errors.ApproxFailWithHint("No underlying deposit required");
        return 1e18 - (underlyingIn * 1e18 / underlyingDesired).toInt256();
    }

    /// @notice Estimate amount of Base LP token to be swapped out for `addLiquidityOneUnderlying` function.
    /// @dev The returned value can be used as `baseLptSwap` in `router.addLiquidityOneUnderlying`.
    /// @param pool The pool to add liquidity on
    /// @param underlyingsToAdd The underlying amount to add to the pool
    /// @return The estimated amount of Base LP token out
    function approxBaseLptToAddLiquidityOneUnderlying(INapierPool pool, uint256 underlyingsToAdd)
        public
        view
        returns (uint256)
    {
        IPoolFactory.PoolAssets memory assets = getPoolAssets(pool);
        PoolState memory state = pool.readState();
        uint8 uDecimals = IERC20Metadata(assets.underlying).decimals();

        ApproxParams memory approx = defaultApprox();
        approx.eps = 1e6; // Note: Higher precision is needed for this approximation
        // approximate baseLpt amount out
        return LibApproximation.approxBaseLptToAddLiquidityOneUnderlying(
            state,
            underlyingsToAdd.to18Decimals(uDecimals), // convert to 18 decimals
            approx
        );
    }

    /// @notice Estimate amount of Base LP token to be swapped in for `addLiquidityOnePt` function.
    /// @dev The returned value can be used as `baseLptSwap` in `router.addLiquidityOnePt`.
    /// @param pool The pool to add liquidity on
    /// @param index The index of the principal token
    /// @param ptToAdd The principal token amount to add to the pool
    /// @return The estimated amount of Base LP token in
    function approxBaseLptToAddLiquidityOnePt(INapierPool pool, uint256 index, uint256 ptToAdd)
        public
        view
        returns (uint256)
    {
        IPoolFactory.PoolAssets memory assets = getPoolAssets(pool);
        PoolState memory state = pool.readState();

        ApproxParams memory approx = defaultApprox();
        approx.eps = 1e6; // Note: Higher precision is needed for this approximation
        // pt amount -> baseLpt amount
        uint256[3] memory amounts;
        amounts[index] = ptToAdd;
        uint256 baseLptToAdd = CurveTricryptoOptimizedWETH(assets.basePool).calc_token_amount(amounts, true);
        // approximate baseLpt amount swap in
        return LibApproximation.approxBaseLptToAddLiquidityOnePt(state, baseLptToAdd, approx);
    }

    /// @notice Estimate amount of underlying token to be swapped in for `removeLiquidityOneUnderlying` function.
    /// @param pool The pool to remove liquidity on
    /// @param liquidity The liquidity amount to remove from the pool
    /// @return The estimated amount of Base LP token out
    function approxBaseLptToRemoveLiquidityOnePt(INapierPool pool, uint256 liquidity) public view returns (uint256) {
        getPoolAssets(pool); // Verify if pool exists
        PoolState memory state = pool.readState();

        (uint256 underlyingOut18, uint256 baseLptOut) = _getWithdrawalAmounts18(pool, state, liquidity);
        // Update state to reflect the withdrawal amount
        state.totalUnderlying18 -= underlyingOut18;
        state.totalBaseLptTimesN -= baseLptOut * N_COINS;

        ApproxParams memory approx = defaultApprox();
        approx.eps = 1e6; // Note: Higher precision is needed for this approximation
        return LibApproximation.approxSwapExactUnderlyingForBaseLpt(state, underlyingOut18, approx);
    }

    //////////////////////////////// Helper functions ////////////////////////////////

    function _getWithdrawalAmounts18(INapierPool pool, PoolState memory state, uint256 liquidity)
        internal
        view
        returns (uint256 underlyingOut18, uint256 baseLptOut)
    {
        if (liquidity == 0) revert Errors.PoolZeroAmountsInput();

        uint256 totalLp = IERC20Metadata(address(pool)).totalSupply();
        underlyingOut18 = (liquidity * state.totalUnderlying18) / totalLp;
        baseLptOut = (liquidity * state.totalBaseLptTimesN / N_COINS) / totalLp;
    }

    function _findMaxPtIn(INapierPool pool, uint256 index, uint256 guess) internal returns (uint256) {
        return _findMaxPt(pool, index, guess, true);
    }

    function _findMaxPtOut(INapierPool pool, uint256 index, uint256 guess) internal returns (uint256) {
        return _findMaxPt(pool, index, guess, false);
    }

    /// @notice Find the maximum amount of principal token that can be swapped in or out.
    /// @dev This function simulates swaps by calling the `quote*` function,
    /// which may revert if the swap is not possible. The state of the pool is not changed
    /// because `quote*` reverts before making any state changes.
    /// @dev Hack It's a workable solution, but it may not be the most elegant one.
    /// @param pool The pool to swap on.
    /// @param index The index of the principal token in the pool's list of principal tokens.
    /// @param guess An initial estimate of the maximum amount of principal token
    /// that can be swapped. The estimate must be smaller than the actual maximum.
    /// @return max The maximum amount of principal token that can be swapped in or out.
    function _findMaxPt(INapierPool pool, uint256 index, uint256 guess, bool ptForUnderlying)
        internal
        returns (uint256)
    {
        uint256 stepSize = pool.totalUnderlying() / 10; // 10% of total underlying
        bytes4 fn = ptForUnderlying ? this.quotePtForUnderlying.selector : this.quoteUnderlyingForPt.selector;

        uint256 a = guess; // lower bound
        uint256 b = guess; // upper bound
        // Find the upper bound such that the swap is NOT possible.
        while (true) {
            // Loop until the swap is not possible.
            (bool success,) = address(this).call(abi.encodeWithSelector(fn, pool, index, b));
            // If the swap is possible, increase the estimate.
            if (success) b += stepSize;
            else break;
        }
        // Try to find an amount of principal token such that the swap is barely possible.
        // Bisect the interval [a, b] and narrow down the interval that contains the maximum.
        uint256 midpoint;
        for (uint256 i = 0; i != 50; ++i) {
            midpoint = (a + b) / 2;
            // Check the swap is possible.
            (bool success,) = address(this).call(abi.encodeWithSelector(fn, pool, index, midpoint));
            if (success) {
                // If the swap is possible, max is in the interval [midpoint, b].
                a = midpoint;
            } else {
                // If the swap is not possible, max is in the interval [a, midpoint].
                b = midpoint;
            }
        }
        return midpoint;
    }

    function defaultApprox() internal pure returns (ApproxParams memory) {
        return ApproxParams({
            guessMin: 0, // initial a
            guessMax: type(uint128).max, // initial b
            maxIteration: 100,
            eps: 0.0001 * 1e18 // 0.01% relative error tolerance
        });
    }
}

library Casts {
    // forgefmt: disable-start
    function asMutativeFn(
        function(
            bytes memory,
            function (uint256, bytes memory, uint256) view returns (int256),
            uint256,
            ApproxParams memory
        ) internal view returns (uint256) fnIn
    )
        internal
        pure
        returns (
            function(
                bytes memory,
                function (uint256, bytes memory, uint256) returns (int256),
                uint256,
                ApproxParams memory
            ) internal returns (uint256) fnOut
        )
    {
        assembly {
            fnOut := fnIn
        }
    }
    // forgefmt: disable-end
}
