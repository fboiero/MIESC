// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.10;

// external interfaces
import {IERC20} from "@openzeppelin/contracts@4.9.3/token/ERC20/IERC20.sol";
import {IWETH9} from "./interfaces/external/IWETH9.sol";
import {CurveTricryptoOptimizedWETH} from "./interfaces/external/CurveTricryptoOptimizedWETH.sol";
import {ITranche} from "@napier/napier-v1/src/interfaces/ITranche.sol";
import {IBaseAdapter} from "@napier/napier-v1/src/interfaces/IBaseAdapter.sol";
import {INapierPool} from "./interfaces/INapierPool.sol";
import {IPoolFactory} from "./interfaces/IPoolFactory.sol";
// implements
import {INapierRouter} from "./interfaces/INapierRouter.sol";
import {INapierMintCallback} from "./interfaces/INapierMintCallback.sol";
import {INapierSwapCallback} from "./interfaces/INapierSwapCallback.sol";

// libraries
import {SafeERC20} from "@openzeppelin/contracts@4.9.3/token/ERC20/utils/SafeERC20.sol";
import {CallbackDataTypes, CallbackType} from "./libs/CallbackDataTypes.sol";
import {PoolAddress} from "./libs/PoolAddress.sol";
import {MAX_BPS} from "@napier/napier-v1/src/Constants.sol";
import {Errors} from "./libs/Errors.sol";

// inherits
import {PeripheryImmutableState} from "./base/PeripheryImmutableState.sol";
import {PeripheryPayments} from "./base/PeripheryPayments.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts@4.9.3/security/ReentrancyGuard.sol";
import {Multicallable} from "./base/Multicallable.sol";

/// @notice Router for Napier pools
/// @dev This contract provides a single entry point for Napier pools. Accepts native ETH.
/// @dev Multicallable is used to batch multiple operations. E.g. Swap Principal Tokens for WETH and unwrap WETH to ETH with a single transaction.
/// See each function for more details.
contract NapierRouter is
    INapierRouter,
    INapierSwapCallback,
    INapierMintCallback,
    PeripheryPayments,
    ReentrancyGuard,
    Multicallable
{
    using SafeERC20 for IERC20;
    using SafeERC20 for ITranche;

    /// @notice Napier Pool Factory
    /// @dev pool passed as functions parameter must be deployed by this factory
    IPoolFactory public immutable factory;

    bytes32 internal immutable POOL_CREATION_HASH;

    /// @notice If the transaction is too old, revert.
    /// @param deadline Transaction deadline in unix timestamp
    modifier checkDeadline(uint256 deadline) {
        if (block.timestamp > deadline) revert Errors.RouterTransactionTooOld();
        _;
    }

    constructor(IPoolFactory _factory, IWETH9 _WETH9) PeripheryImmutableState(_WETH9) {
        factory = _factory;
        POOL_CREATION_HASH = _factory.POOL_CREATION_HASH();
    }

    /// @dev Revert if `msg.sender` is not a Napier pool.
    function _verifyCallback(address basePool, address underlying) internal view {
        if (
            PoolAddress.computeAddress(basePool, underlying, POOL_CREATION_HASH, address(factory))
                != INapierPool(msg.sender)
        ) revert Errors.RouterCallbackNotNapierPool();
    }

    function mintCallback(uint256 underlyingDelta, uint256 baseLptDelta, bytes calldata data) external override {
        // `data` is encoded as follows:
        // [0x00: 0x20] CallbackType (uint8)
        // [0x20:  ~  ] Custom data (based on CallbackType)
        CallbackDataTypes.AddLiquidityData memory params = abi.decode(data[0x20:], (CallbackDataTypes.AddLiquidityData));
        _verifyCallback(params.basePool, params.underlying);

        // In all addLiquidity functions of router, underlying tokens are saved in payer and baseLpTokens are saved in router.
        // So in this callback function, we don't need to get CallbackTypes.
        // If this contract holds enough ETH, wrap it. Otherwise, transfer from the caller.
        _pay(params.underlying, params.payer, msg.sender, underlyingDelta);
        IERC20(params.basePool).safeTransfer(msg.sender, baseLptDelta);
    }

    function swapCallback(int256 underlyingDelta, int256 ptDelta, bytes calldata data) external override {
        // `data` is encoded as follows:
        // [0x00: 0x20] CallbackType (uint8)
        // [0x20: 0x40] Underlying (address)
        // [0x40: 0x60] BasePool (address)
        // [0x60:  ~  ] Custom data (based on CallbackType)
        (address underlying, address basePool) = abi.decode(data[0x20:0x60], (address, address));
        _verifyCallback(basePool, underlying);

        CallbackType _type = CallbackDataTypes.getCallbackType(data);

        if (_type == CallbackType.SwapPtForUnderlying) {
            CallbackDataTypes.SwapPtForUnderlyingData memory params =
                abi.decode(data[0x60:], (CallbackDataTypes.SwapPtForUnderlyingData));
            params.pt.safeTransferFrom(params.payer, msg.sender, uint256(-ptDelta));
        } else if (_type == CallbackType.SwapUnderlyingForPt) {
            // Decode callback data
            CallbackDataTypes.SwapUnderlyingForPtData memory params =
                abi.decode(data[0x60:], (CallbackDataTypes.SwapUnderlyingForPtData));

            // Check slippage. Revert if exceeded max underlying in
            if (uint256(-underlyingDelta) > params.underlyingInMax) revert Errors.RouterExceededLimitUnderlyingIn();
            _pay(underlying, params.payer, msg.sender, uint256(-underlyingDelta));
        } else if (_type == CallbackType.SwapYtForUnderlying) {
            // Decode callback data
            CallbackDataTypes.SwapYtForUnderlyingData memory params =
                abi.decode(data[0x60:], (CallbackDataTypes.SwapYtForUnderlyingData));

            uint256 uRepay = uint256(-underlyingDelta); // unsafe cast is okay because always negative in this branch
            uint256 pyRedeem; // amount of PT (YT) to be redeemed
            // Assign the minimum amount of (ytIn, ptDelta) to `pyRedeem`
            if (params.ytIn >= uint256(ptDelta)) {
                // If the actual amount of PT received is less than the requested amount, use the actual amount
                pyRedeem = uint256(ptDelta);
            } else {
                pyRedeem = params.ytIn;
                // Surplus of `ptDelta` - `params.ytIn` should be refunded to the payer
                // no underflow because of the if statement above
                IERC20(params.pt).safeTransfer(params.payer, uint256(ptDelta) - params.ytIn); // non-zero
            }

            // Transfer YT from caller to this contract
            IERC20(params.pt.yieldToken()).safeTransferFrom(params.payer, address(this), pyRedeem);

            // Optimistically redeem any amount of PT and YT for underlying
            // Later, we will check if the amount of underlying redeemed is enough to cover the underlying to be repaid
            uint256 uRedeemed = params.pt.redeemWithYT({
                pyAmount: pyRedeem,
                to: address(this),
                from: address(this) // At this point, the YT is already in this contract
            });
            if (uRedeemed < uRepay) revert Errors.RouterInsufficientUnderlyingRepay();
            // Check slippage
            uint256 underlyingToRecipient = uRedeemed - uRepay; // no underflow because of the if statement above
            if (underlyingToRecipient < params.underlyingOutMin) revert Errors.RouterInsufficientUnderlyingOut();

            // Repay underlying to Napier pool and transfer the rest to recipient
            IERC20(underlying).safeTransfer(msg.sender, uRepay);
            IERC20(underlying).safeTransfer(params.recipient, underlyingToRecipient);
        } else if (_type == CallbackType.SwapUnderlyingForYt) {
            // Decode callback data
            CallbackDataTypes.SwapUnderlyingForYtData memory params =
                abi.decode(data[0x60:], (CallbackDataTypes.SwapUnderlyingForYtData));

            uint256 uReceived = uint256(underlyingDelta); // unsafe cast is okay because always positive in this branch.
            uint256 pyDesired = uint256(-ptDelta); // principal token to be repaid and yield token to be issued

            // Pull underlying from payer.
            // Economically, it's almost unlikely that the payer doesn't need to pay underlying asset.
            // But if the above case happens, it would be reverted.
            if (params.underlyingDeposit <= uReceived) revert Errors.RouterNonSituationSwapUnderlyingForYt();
            uint256 uPull = params.underlyingDeposit - uReceived;
            if (uPull > params.maxUnderlyingPull) revert Errors.RouterExceededLimitUnderlyingIn();
            _pay(underlying, params.payer, address(this), uPull);

            IERC20(underlying).forceApprove(address(params.pt), params.underlyingDeposit);
            uint256 pyIssued = params.pt.issue({to: address(this), underlyingAmount: params.underlyingDeposit});

            // Repay the PT to Napier pool
            if (pyIssued < pyDesired) revert Errors.RouterInsufficientPtRepay();
            params.pt.safeTransfer(msg.sender, pyDesired);
            // Transfer the remaining PT to payer
            params.pt.safeTransfer(params.payer, pyIssued - pyDesired);
            // Transfer the YT to recipient
            params.yt.safeTransfer(params.recipient, pyIssued);
        }
    }

    /// @inheritdoc INapierRouter
    /// @notice Swap exact amount of Principal Token (PT) for Underlying.
    /// @notice Caller must approve the router to spend PTs prior to calling this method.
    /// @notice Revert if the pool is not deployed by the factory set in the constructor.
    /// @notice Revert if maturity has passed for the pool.
    /// @notice Revert if deadline has passed.
    /// @notice Revert if the amount of underlying asset received is less than the minimum amount specified.
    /// @param pool The address of the pool.
    /// @param index The index of the PT. (0, 1, 2)
    /// @param ptInDesired The amount of PT to swap.
    /// @param underlyingOutMin The minimum amount of underlying asset to receive.
    /// @param recipient The recipient of the swapped underlying asset.
    /// @param deadline The deadline for the swap.
    /// @return The amount of underlying asset received.
    function swapPtForUnderlying(
        address pool,
        uint256 index,
        uint256 ptInDesired,
        uint256 underlyingOutMin,
        address recipient,
        uint256 deadline
    ) external override nonReentrant checkDeadline(deadline) returns (uint256) {
        // dev: Optimistically call to the `pool` provided by the untrusted caller.
        // And then verify the pool using CREATE2.
        (address underlying, address basePool) = INapierPool(pool).getAssets();

        // if `pool` doesn't matched, it would be reverted.
        if (INapierPool(pool) != PoolAddress.computeAddress(basePool, underlying, POOL_CREATION_HASH, address(factory)))
        {
            revert Errors.RouterPoolNotFound();
        }

        address pt = address(INapierPool(pool).principalTokens()[index]);

        // Abi encode callback data to be used in swapCallback
        bytes memory data = new bytes(0xa0);

        uint256 callbackType = uint256(CallbackType.SwapPtForUnderlying);
        assembly {
            // Equivanlent to:
            // data = abi.encode(CallbackType.SwapUnderlyingForPt, underlying, basePool, CallbackDataTypes.SwapUnderlyingForPtData({payer: msg.sender, underlyingInMax: underlyingInMax}))
            mstore(add(data, 0x20), callbackType)
            mstore(add(data, 0x40), underlying)
            mstore(add(data, 0x60), basePool)
            mstore(add(data, 0x80), caller()) // dev: Ensure 'payer' is always 'msg.sender' to prevent allowance theft on callback.
            mstore(add(data, 0xa0), pt)
        }
        uint256 underlyingOut = INapierPool(pool).swapPtForUnderlying(index, ptInDesired, recipient, data);
        if (underlyingOut < underlyingOutMin) revert Errors.RouterInsufficientUnderlyingOut();

        return underlyingOut;
    }

    /// @inheritdoc INapierRouter
    /// @notice Swap underlying for PT.
    /// @notice Caller must approve the router to spend underlying asset prior to calling this method.
    /// @dev If caller calls with ether, the ether will be wrapped to WETH9.
    /// Note: the remaining ether is NOT returned automatically. Caller must call refundETH to get the remaining ether back.
    /// @dev Revert conditions are the same as swapPtForUnderlying.
    /// @param pool The address of the pool.
    /// @param index The index of the PT.
    /// @param ptOutDesired The amount of PT to receive.
    /// @param underlyingInMax The maximum amount of underlying asset to spend.
    /// @param recipient The recipient of the PT.
    /// @param deadline The deadline for the swap.
    /// @return The amount of underlying asset spent.
    function swapUnderlyingForPt(
        address pool,
        uint256 index,
        uint256 ptOutDesired,
        uint256 underlyingInMax,
        address recipient,
        uint256 deadline
    ) external payable override nonReentrant checkDeadline(deadline) returns (uint256) {
        // dev: Optimistically call to the `pool` provided by the untrusted caller.
        // And then verify the pool using CREATE2.
        (address underlying, address basePool) = INapierPool(pool).getAssets();

        // if `pool` doesn't matched, it would be reverted.
        if (INapierPool(pool) != PoolAddress.computeAddress(basePool, underlying, POOL_CREATION_HASH, address(factory)))
        {
            revert Errors.RouterPoolNotFound();
        }

        IERC20 pt = INapierPool(pool).principalTokens()[index];

        // Abi encode callback data to be used in swapCallback
        bytes memory data = new bytes(0xa0);
        {
            uint256 callbackType = uint256(CallbackType.SwapUnderlyingForPt);
            assembly {
                // Equivanlent to:
                // data = abi.encode(CallbackType.SwapUnderlyingForPt, underlying, basePool, CallbackDataTypes.SwapUnderlyingForPtData({payer: msg.sender, underlyingInMax: underlyingInMax}))
                mstore(add(data, 0x20), callbackType)
                mstore(add(data, 0x40), underlying)
                mstore(add(data, 0x60), basePool)
                mstore(add(data, 0x80), caller()) // dev: Ensure 'payer' is always 'msg.sender' to prevent allowance theft on callback.
                mstore(add(data, 0xa0), underlyingInMax)
            }
        }

        uint256 prevBalance = pt.balanceOf(address(this));
        uint256 underlyingUsed = INapierPool(pool).swapUnderlyingForPt(
            index,
            ptOutDesired,
            address(this), // this contract will receive principal token from pool
            data
        );

        pt.safeTransfer(recipient, pt.balanceOf(address(this)) - prevBalance);
        return underlyingUsed;
    }

    /// @inheritdoc INapierRouter
    /// @notice Swap underlying asset for YT.
    /// @dev Under the hood, Router receives underlying asset from `pool` with flash swap and issues PT and YT.
    /// After that, pay back the PT to `pool` and transfer the issued YT to `recipient`.
    /// @param pool The address of the pool.
    /// @param index The index of principal token / yield token.
    /// @param ytOutDesired The amount of YT to receive. (at least `ytOutDesired` amount of PT and YT should be issued)
    /// @param underlyingInMax The maximum amount of underlying asset to spend.
    /// @param recipient The recipient of the YT.
    /// @param deadline The deadline for the swap.
    /// @return The amount of underlying asset recipient spent.
    function swapUnderlyingForYt(
        address pool,
        uint256 index,
        uint256 ytOutDesired,
        uint256 underlyingInMax,
        address recipient,
        uint256 deadline
    ) external payable override nonReentrant checkDeadline(deadline) returns (uint256) {
        // dev: Optimistically call to the `pool` provided by the untrusted caller.
        // And then verify the pool using CREATE2.
        (address underlying, address basePool) = INapierPool(pool).getAssets();

        // if `pool` doesn't matched, it would be reverted.
        if (INapierPool(pool) != PoolAddress.computeAddress(basePool, underlying, POOL_CREATION_HASH, address(factory)))
        {
            revert Errors.RouterPoolNotFound();
        }

        ITranche pt = ITranche(address(INapierPool(pool).principalTokens()[index]));

        uint256 uDeposit; // underlying asset to be deposited to Tranche
        {
            // This section of code aims to calculate the amount of underlying asset (`uDeposit`) required to issue a specific amount of PT and YT (`ytOutDesired`).
            // The calculations are based on the formula used in the `Tranche.issue` function.

            ITranche.Series memory series = pt.getSeries();

            // Update maxscale if current scale is greater than maxscale
            uint256 maxscale = series.maxscale;
            uint256 cscale = IBaseAdapter(series.adapter).scale();
            if (cscale > maxscale) {
                maxscale = cscale;
            }
            // Variable Definitions:
            // - `uDeposit`: The amount of underlying asset that needs to be deposited to issue PT and YT.
            // - `ytOutDesired`: The desired amount of PT and YT to be issued.
            // - `cscale`: Current scale of the Tranche.
            // - `maxscale`: Maximum scale of the Tranche (denoted as 'S' in the formula).
            // - `issuanceFee`: Issuance fee in basis points. (10000 =100%).

            // Formula for `Tranche.issue`:
            // ```
            // shares = uDeposit / s
            // fee = shares * issuanceFeeBps / 10000
            // pyIssue = (shares - fee) * S
            // ```

            // Solving for `uDeposit`:
            // ```
            // uDeposit = (pyIssue * s / S) / (1 - issuanceFeeBps / 10000)
            // ```
            // Hack:
            // Buffer is added to the denominator.
            // This ensures that at least `ytOutDesired` amount of PT and YT are issued.
            // If maximum scale and current scale are significantly different or `ytOutDesired` is small, the function might fail.
            // Without this buffer, any rounding errors that reduce the issued PT and YT could lead to an insufficient amount of PT to be repaid to the pool.
            uint256 uDepositNoFee = cscale * ytOutDesired / maxscale;
            uDeposit = uDepositNoFee * MAX_BPS / (MAX_BPS - (series.issuanceFee + 1)); // 0.01 bps buffer
        }

        // Abi encode callback data to be used in swapCallback
        bytes memory data = new bytes(0x120);
        {
            uint256 callbackType = uint256(CallbackType.SwapUnderlyingForYt);
            address yt = pt.yieldToken();
            assembly {
                // Equivanlent to:
                // abi.encode(CallbackType.SwapUnderlyingForYt, underlying, basePool, CallbackDataTypes.SwapUnderlyingForYtData({pt: pt, yt: yt, payer: msg.sender, recipient: recipient, underlyingDeposit: uDeposit, maxUnderlyingPull: underlyingInMax}))
                mstore(add(data, 0x20), callbackType)
                mstore(add(data, 0x40), underlying)
                mstore(add(data, 0x60), basePool)
                mstore(add(data, 0x80), caller()) // dev: Ensure 'payer' is always 'msg.sender' to prevent allowance theft on callback.
                mstore(add(data, 0xa0), pt)
                mstore(add(data, 0xc0), yt)
                mstore(add(data, 0xe0), recipient)
                mstore(add(data, 0x100), uDeposit)
                mstore(add(data, 0x120), underlyingInMax)
            }
        }
        uint256 received = INapierPool(pool).swapPtForUnderlying(
            index,
            ytOutDesired, // ptInDesired
            address(this), // this contract will receive underlying token from pool
            data
        );

        // Underlying pulled = underlying deposited - underlying received from swap
        return uDeposit - received;
    }

    /// @inheritdoc INapierRouter
    /// @notice Swap YT for underlying asset.
    /// @dev Under the hood, Router receives principal token from `pool` with flash swap and redeem it with YT for underlying asset.
    /// After that, pay back the underlying asset to `pool` and transfer the remaining underlying asset to `recipient`.
    /// @param pool The address of the pool.
    /// @param index The index of the YT.
    /// @param ytIn The amount of YT to swap.
    /// @param underlyingOutMin The minimum amount of underlying asset to receive.
    /// @param recipient The recipient of the underlying asset.
    /// @param deadline The deadline for the swap.
    /// @return The amount of underlying asset recipient received.
    function swapYtForUnderlying(
        address pool,
        uint256 index,
        uint256 ytIn,
        uint256 underlyingOutMin,
        address recipient,
        uint256 deadline
    ) external override nonReentrant checkDeadline(deadline) returns (uint256) {
        // dev: Optimistically call to the `pool` provided by the untrusted caller.
        // And then verify the pool using CREATE2.
        (address underlying, address basePool) = INapierPool(pool).getAssets();

        // if `pool` doesn't matched, it would be reverted.
        if (INapierPool(pool) != PoolAddress.computeAddress(basePool, underlying, POOL_CREATION_HASH, address(factory)))
        {
            revert Errors.RouterPoolNotFound();
        }

        ITranche pt = ITranche(address(INapierPool(pool).principalTokens()[index]));

        uint256 prevBalance = IERC20(underlying).balanceOf(recipient);

        // Abi encode callback data to be used in swapCallback
        bytes memory data = new bytes(0x100);
        uint256 callbackType = uint256(CallbackType.SwapYtForUnderlying);
        assembly {
            // Equivanlent to:
            // data = abi.encode(CallbackType.SwapYtForUnderlying, underlying, basePool, CallbackDataTypes.SwapYtForUnderlyingData({pt: pt, payer: msg.sender, ytIn: ytIn, recipient: recipient, underlyingOutMin: underlyingOutMin}))
            mstore(add(data, 0x20), callbackType)
            mstore(add(data, 0x40), underlying)
            mstore(add(data, 0x60), basePool)
            mstore(add(data, 0x80), caller()) // dev: Ensure 'payer' is always 'msg.sender' to prevent allowance theft on callback.
            mstore(add(data, 0xa0), pt)
            mstore(add(data, 0xc0), ytIn)
            mstore(add(data, 0xe0), recipient)
            mstore(add(data, 0x100), underlyingOutMin)
        }
        // Note: swap for PT approximate equal to `ytIn`
        INapierPool(pool).swapUnderlyingForPt(
            index,
            ytIn, // ptOutDesired
            address(this), // this contract will receive principal token from pool
            data
        );

        // Underlying received = balance after swap - balance before swap
        return IERC20(underlying).balanceOf(recipient) - prevBalance;
    }

    /// @inheritdoc INapierRouter
    /// @notice Caller must approve the router to spend underlying asset and PTs prior to calling this method.
    /// @notice Revert if the pool is not deployed by the factory set in the constructor
    /// @notice Revert if maturity has passed for the pool
    /// @notice Revert if deadline has passed
    /// @notice Revert if the amount of liquidity tokens received is less than the minimum amount specified
    /// @notice It will refund the remaining tokens (Native ETH or Base LP token) to the caller if any.
    /// @param pool The address of the pool.
    /// @param underlyingIn The amount of underlying asset to deposit.
    /// @param ptsIn The amounts of PTs to deposit. Can be zero but at least one must be non-zero. Otherwise, revert in the Curve pool.
    /// @param liquidityMin The minimum amount of liquidity tokens to receive.
    /// @param recipient The recipient of the liquidity tokens.
    /// @param deadline The deadline for adding liquidity.
    /// @return The amount of liquidity tokens received.
    function addLiquidity(
        address pool,
        uint256 underlyingIn,
        uint256[3] calldata ptsIn,
        uint256 liquidityMin,
        address recipient,
        uint256 deadline
    ) external payable override nonReentrant checkDeadline(deadline) returns (uint256) {
        // dev: Optimistically call to the `pool` provided by the untrusted caller.
        // And then verify the pool using CREATE2.
        (address underlying, address basePool) = INapierPool(pool).getAssets();

        // if `pool` doesn't matched, it would be reverted.
        if (INapierPool(pool) != PoolAddress.computeAddress(basePool, underlying, POOL_CREATION_HASH, address(factory)))
        {
            revert Errors.RouterPoolNotFound();
        }

        IERC20[3] memory pts = INapierPool(pool).principalTokens();

        // Loop unrolling for gas optimization
        pts[0].safeTransferFrom(msg.sender, address(this), ptsIn[0]);
        pts[1].safeTransferFrom(msg.sender, address(this), ptsIn[1]);
        pts[2].safeTransferFrom(msg.sender, address(this), ptsIn[2]);
        // approve max to Tricrypto pool
        if (pts[0].allowance(address(this), basePool) < ptsIn[0]) pts[0].approve(basePool, type(uint256).max); // dev: Principal token will revert if failed to approve
        if (pts[1].allowance(address(this), basePool) < ptsIn[1]) pts[1].approve(basePool, type(uint256).max);
        if (pts[2].allowance(address(this), basePool) < ptsIn[2]) pts[2].approve(basePool, type(uint256).max);

        uint256 baseLptIn = CurveTricryptoOptimizedWETH(basePool).add_liquidity(ptsIn, 0);
        // Add liquidity to Napier pool
        uint256 liquidity = INapierPool(pool).addLiquidity(
            underlyingIn,
            baseLptIn,
            recipient,
            abi.encode(
                CallbackType.AddLiquidityPts,
                CallbackDataTypes.AddLiquidityData({payer: msg.sender, underlying: underlying, basePool: basePool})
            )
        );
        if (liquidity < liquidityMin) revert Errors.RouterInsufficientLpOut();

        // Sweep remaining tokens if any.
        uint256 bBalance = IERC20(basePool).balanceOf(address(this));
        if (bBalance > 0) IERC20(basePool).safeTransfer(msg.sender, bBalance);
        // If WETH or ERC20 tokens are used, the exact amount is pulled from the caller. So, no need to sweep.
        // If caller sent native ETH, make sure to send remaining ETH back to caller.
        if (address(this).balance > 0) _safeTransferETH(msg.sender, address(this).balance);

        return liquidity;
    }

    /// @inheritdoc INapierRouter
    /// @notice Add liquidity to Napier pool from one principal token proportionally as possible as it can.
    /// @notice Deadline should be tightly set.
    /// @notice Caller must approve the router to spend PT prior to calling this method.
    /// @dev Caller must specify the amount of base LP token to be swapped for underlying asset using off-chain calculation.
    /// @dev Remaining base LP token and underlying asset are swept to the caller if any.
    /// @param pool The address of the pool.
    /// @param index The index of the PT.
    /// @param amountIn The amount of PT to deposit.
    /// @param liquidityMin The minimum amount of liquidity tokens to receive.
    /// @param recipient The recipient of the liquidity tokens.
    /// @param deadline The deadline for adding liquidity.
    /// @param baseLpTokenSwap The estimated baseLpt amount to swap with underlying tokens.
    /// @return The amount of liquidity tokens received.
    function addLiquidityOnePt(
        address pool,
        uint256 index,
        uint256 amountIn,
        uint256 liquidityMin,
        address recipient,
        uint256 deadline,
        uint256 baseLpTokenSwap
    ) external override nonReentrant checkDeadline(deadline) returns (uint256) {
        // dev: Optimistically call to the `pool` provided by the untrusted caller.
        // And then verify the pool using CREATE2.
        (address underlying, address basePool) = INapierPool(pool).getAssets();

        // if `pool` doesn't matched, it would be reverted.
        if (INapierPool(pool) != PoolAddress.computeAddress(basePool, underlying, POOL_CREATION_HASH, address(factory)))
        {
            revert Errors.RouterPoolNotFound();
        }

        IERC20[3] memory pts = INapierPool(pool).principalTokens();
        pts[index].safeTransferFrom(msg.sender, address(this), amountIn);
        if (pts[index].allowance(address(this), basePool) < amountIn) pts[index].approve(basePool, type(uint256).max);

        uint256[3] memory ptsIn;
        ptsIn[index] = amountIn;
        uint256 baseLptIn = CurveTricryptoOptimizedWETH(basePool).add_liquidity(ptsIn, 0);
        IERC20(basePool).forceApprove(address(pool), baseLptIn);

        // Swap some base LP token for underlying
        uint256 underlyingIn = INapierPool(pool).swapExactBaseLpTokenForUnderlying(baseLpTokenSwap, address(this));

        // Add liquidity to Napier pool
        uint256 liquidity = INapierPool(pool).addLiquidity(
            underlyingIn,
            baseLptIn - baseLpTokenSwap,
            recipient,
            abi.encode(
                CallbackType.AddLiquidityOnePt,
                CallbackDataTypes.AddLiquidityData({
                    payer: address(this), // Router has already had both tokens at this point
                    underlying: underlying,
                    basePool: basePool
                })
            )
        );
        if (liquidity < liquidityMin) revert Errors.RouterInsufficientLpOut();

        // Sweep remaining tokens if any.
        uint256 bBalance = IERC20(basePool).balanceOf(address(this));
        if (bBalance > 0) IERC20(basePool).safeTransfer(msg.sender, bBalance);
        uint256 uBalance = IERC20(underlying).balanceOf(address(this));
        if (uBalance > 0) IERC20(underlying).safeTransfer(msg.sender, uBalance);

        return liquidity;
    }

    /// @inheritdoc INapierRouter
    /// @notice Add liquidity to NapierPool with one underlying asset.
    /// @notice Deadline should be tightly set.
    /// @notice Caller must approve the router to spend underlying asset prior to calling this method.
    /// @dev Under the hood, router swap some underlying asset for Base pool LP token.
    /// @dev Caller must specify the amount of base LP token to be swapped for underlying asset using off-chain calculation.
    /// @dev Remaining base LP token and underlying asset are swept to the caller if any.
    /// @param pool The address of the pool.
    /// @param underlyingIn The amount of underlying asset to deposit.
    /// @param liquidityMin The minimum amount of liquidity tokens to receive.
    /// @param recipient The recipient of the liquidity tokens.
    /// @param deadline The deadline for adding liquidity.
    /// @param baseLpTokenSwap The estimated baseLpTokenSwap amount to swap with underlying tokens.
    /// @return The amount of liquidity tokens received.
    function addLiquidityOneUnderlying(
        address pool,
        uint256 underlyingIn,
        uint256 liquidityMin,
        address recipient,
        uint256 deadline,
        uint256 baseLpTokenSwap
    ) external override nonReentrant checkDeadline(deadline) returns (uint256) {
        // dev: Optimistically call to the `pool` provided by the untrusted caller.
        // And then verify the pool using CREATE2.
        (address underlying, address basePool) = INapierPool(pool).getAssets();

        // if `pool` doesn't matched, it would be reverted.
        if (INapierPool(pool) != PoolAddress.computeAddress(basePool, underlying, POOL_CREATION_HASH, address(factory)))
        {
            revert Errors.RouterPoolNotFound();
        }

        IERC20(underlying).safeTransferFrom(msg.sender, address(this), underlyingIn);

        // Swap some underlying for baseLpt
        // At this point, Router doesn't know how much underlying is needed to get `baseLpTokenSwap` amount of base LP token.
        // So, Router just approve pool to spend all underlying asset and let pool to spend as much as it needs.
        // approve max
        if (IERC20(underlying).allowance(address(this), pool) < underlyingIn) {
            IERC20(underlying).forceApprove(pool, type(uint256).max);
        }
        uint256 uSpent = INapierPool(pool).swapUnderlyingForExactBaseLpToken(baseLpTokenSwap, address(this));

        // Add liquidity to Napier pool
        uint256 liquidity = INapierPool(pool).addLiquidity(
            underlyingIn - uSpent, // remaining underlying asset
            baseLpTokenSwap, // base LP token from swap
            recipient,
            abi.encode(
                CallbackType.AddLiquidityOneUnderlying,
                CallbackDataTypes.AddLiquidityData({
                    payer: address(this), // Router has already had both tokens at this point
                    underlying: underlying,
                    basePool: basePool
                })
            )
        );
        if (liquidity < liquidityMin) revert Errors.RouterInsufficientLpOut();

        // Sweep remaining tokens if any. WETH is not unwrapped.
        uint256 bBalance = IERC20(basePool).balanceOf(address(this));
        if (bBalance > 0) IERC20(basePool).safeTransfer(msg.sender, bBalance);
        uint256 uBalance = IERC20(underlying).balanceOf(address(this));
        if (uBalance > 0) IERC20(underlying).safeTransfer(msg.sender, uBalance);

        return liquidity;
    }

    /// @inheritdoc INapierRouter
    /// @notice Remove liquidity from NapierPool and Curve pool.
    /// @notice Caller must approve the router to spend liquidity tokens prior to calling this method.
    /// @dev Can withdraw liquidity even if maturity has passed.
    /// @dev Revert if the pool is not deployed by the factory set in the constructor.
    /// @dev Revert if deadline has passed.
    /// @dev Revert if the amount of underlying asset received is less than the minimum amount specified.
    /// @dev Revert if the amount of PTs received is less than the minimum amount specified.
    /// @param pool The address of the pool.
    /// @param liquidity The amount of liquidity tokens to burn.
    /// @param underlyingOutMin The minimum amount of underlying asset to receive.
    /// @param ptsOutMin The minimum amounts of PTs to receive.
    /// @param recipient The recipient of the PTs and underlying asset.
    /// @param deadline The deadline for removing liquidity.
    /// @return The amounts of PTs and underlying asset received.
    function removeLiquidity(
        address pool,
        uint256 liquidity,
        uint256 underlyingOutMin,
        uint256[3] calldata ptsOutMin,
        address recipient,
        uint256 deadline
    ) external override nonReentrant checkDeadline(deadline) returns (uint256, uint256[3] memory) {
        // dev: Optimistically call to the `pool` provided by the untrusted caller.
        // And then verify the pool using CREATE2.
        (address underlying, address basePool) = INapierPool(pool).getAssets();

        // if `pool` doesn't matched, it would be reverted.
        if (INapierPool(pool) != PoolAddress.computeAddress(basePool, underlying, POOL_CREATION_HASH, address(factory)))
        {
            revert Errors.RouterPoolNotFound();
        }

        IERC20(pool).safeTransferFrom(msg.sender, pool, liquidity);
        (uint256 underlyingOut, uint256 baseLptOut) = INapierPool(pool).removeLiquidity(address(this));

        // Check slippage for underlying
        if (underlyingOut < underlyingOutMin) revert Errors.RouterInsufficientUnderlyingOut();

        // Note: Curve Tricrypto Optimized WETH pool doesn't cause clear error messages
        // Curve pool would check slippage for principal tokens
        uint256[3] memory ptsOut = CurveTricryptoOptimizedWETH(basePool).remove_liquidity(
            baseLptOut,
            ptsOutMin, // min_amounts
            false,
            recipient,
            false
        );

        // Transfer underlying to recipient
        IERC20(underlying).safeTransfer(recipient, underlyingOut);

        return (underlyingOut, ptsOut);
    }

    /// @inheritdoc INapierRouter
    /// @notice Remove liquidity from NapierPool and Curve pool with one underlying asset.
    /// @notice Caller must approve the router to spend liquidity tokens prior to calling this method.
    /// @dev Can withdraw liquidity even if maturity has passed.
    /// @dev Revert conditions are the same as removeLiquidity.
    /// @param pool Address of the pool to remove liquidity from.
    /// @param index The index of PT to be withdrawn when removing liquidity from Base pool. Ignored if maturity has not passed.
    /// @param liquidity Liquidity to be removed from Napier pool.
    /// @param underlyingOutMin Minimum amount of underlying asset to receive.
    /// @param recipient Recipient of the underlying asset.
    /// @param deadline Deadline for removing liquidity. Revert if deadline has passed when the transaction is executed.
    function removeLiquidityOneUnderlying(
        address pool,
        uint256 index,
        uint256 liquidity,
        uint256 underlyingOutMin,
        address recipient,
        uint256 deadline
    ) external override nonReentrant checkDeadline(deadline) returns (uint256) {
        // dev: Optimistically call to the `pool` provided by the untrusted caller.
        // And then verify the pool using CREATE2.
        (address underlying, address basePool) = INapierPool(pool).getAssets();

        // if `pool` doesn't matched, it would be reverted.
        if (INapierPool(pool) != PoolAddress.computeAddress(basePool, underlying, POOL_CREATION_HASH, address(factory)))
        {
            revert Errors.RouterPoolNotFound();
        }

        IERC20[3] memory pts = INapierPool(pool).principalTokens();
        // Remove liquidity from Napier pool and get base LP token and underlying back
        IERC20(pool).safeTransferFrom(msg.sender, pool, liquidity);
        (uint256 underlyingOut, uint256 baseLptOut) = INapierPool(pool).removeLiquidity(address(this));

        // The withdrawn base LP token is exchanged for underlying in two different ways depending on the maturity.
        // If maturity has passed, redeem else swap for underlying.
        // 1. Swapping is used when maturity hasn't passed because redeeming is disabled before maturity.
        // 2. Redeeming is preferred because it doesn't cause slippage.
        if (block.timestamp < INapierPool(pool).maturity()) {
            // Swap base LP token for underlying
            // approve max
            if (IERC20(basePool).allowance(address(this), basePool) < baseLptOut) {
                IERC20(basePool).forceApprove(pool, type(uint256).max);
            }
            uint256 removed = INapierPool(pool).swapExactBaseLpTokenForUnderlying(baseLptOut, address(this));
            underlyingOut += removed;
        } else {
            // Withdraw the pt from base pool in return for base LP token
            // Allow unlimited slippage. Check slippage later
            uint256 ptWithdrawn = CurveTricryptoOptimizedWETH(basePool).remove_liquidity_one_coin(
                baseLptOut, index, 0, false, address(this)
            );
            // Redeem the pt for underlying
            uint256 redeemed = ITranche(address(pts[index])).redeem(ptWithdrawn, address(this), address(this));
            underlyingOut += redeemed;
        }

        // Check slippage
        if (underlyingOut < underlyingOutMin) revert Errors.RouterInsufficientUnderlyingOut();
        IERC20(underlying).safeTransfer(recipient, underlyingOut);

        return underlyingOut;
    }

    /// @notice Remove liquidity from the pool and receive a single PT.
    /// @notice Caller must approve the router to spend liquidity tokens prior to calling this method.
    /// @dev Revert conditions are the same as removeLiquidity.
    /// @dev Caller must specify the amount of base LP token to be swapped with underlying asset using off-chain calculation.
    /// @dev Remaining base LP token and underlying asset are swept to the caller if any.
    /// @param pool Address of the pool to remove liquidity from.
    /// @param index The index of PT.
    /// @param liquidity The amount of liquidity tokens to remove.
    /// @param ptOutMin The minimum amount of PT to receive.
    /// @param recipient The recipient of the PT.
    /// @param deadline Deadline for removing liquidity. Revert if deadline has passed when the transaction is executed.
    /// @param baseLpTokenSwap The estimated baseLpt amount to swap with underlying tokens.
    /// @return The amount of PT received.
    function removeLiquidityOnePt(
        address pool,
        uint256 index,
        uint256 liquidity,
        uint256 ptOutMin,
        address recipient,
        uint256 deadline,
        uint256 baseLpTokenSwap
    ) external override nonReentrant checkDeadline(deadline) returns (uint256) {
        // dev: Optimistically call to the `pool` provided by the untrusted caller.
        // And then verify the pool using CREATE2.
        (address underlying, address basePool) = INapierPool(pool).getAssets();

        // if `pool` doesn't matched, it would be reverted.
        if (INapierPool(pool) != PoolAddress.computeAddress(basePool, underlying, POOL_CREATION_HASH, address(factory)))
        {
            revert Errors.RouterPoolNotFound();
        }

        // Remove liquidity from Napier pool and get base LP token and underlying back
        IERC20(pool).safeTransferFrom(msg.sender, pool, liquidity);
        (uint256 underlyingIn, uint256 baseLptOut) = INapierPool(pool).removeLiquidity(address(this));

        // Swap underlying for baseLpt
        // At this point, we don't know how much actual underlying amount will be needed to swap.
        // `baseLpTokenSwap` should be set so that the actual underlying amount would be less than `underlyingIn` otherwise revert in the pool.
        IERC20(underlying).forceApprove(pool, underlyingIn);
        INapierPool(pool).swapUnderlyingForExactBaseLpToken(baseLpTokenSwap, address(this));

        // Withdraw liquidity in a one principal token
        uint256 ptWithdrawn = CurveTricryptoOptimizedWETH(basePool).remove_liquidity_one_coin(
            baseLptOut + baseLpTokenSwap, index, ptOutMin, false, recipient
        );

        // Sweep remaining tokens if any.
        uint256 bBalance = IERC20(basePool).balanceOf(address(this));
        if (bBalance > 0) IERC20(basePool).safeTransfer(msg.sender, bBalance);
        uint256 uBalance = IERC20(underlying).balanceOf(address(this));
        if (uBalance > 0) IERC20(underlying).safeTransfer(msg.sender, uBalance);

        return ptWithdrawn;
    }
}
