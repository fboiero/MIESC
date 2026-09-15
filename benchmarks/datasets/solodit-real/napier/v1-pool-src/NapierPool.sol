// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.10;

// interfaces
import {IERC20} from "@openzeppelin/contracts@4.9.3/token/ERC20/IERC20.sol";
import {CurveTricryptoOptimizedWETH} from "./interfaces/external/CurveTricryptoOptimizedWETH.sol";
import {ITranche} from "@napier/napier-v1/src/interfaces/ITranche.sol";

import {INapierPool} from "./interfaces/INapierPool.sol";
import {INapierSwapCallback} from "./interfaces/INapierSwapCallback.sol";
import {INapierMintCallback} from "./interfaces/INapierMintCallback.sol";
import {IPoolFactory} from "./interfaces/IPoolFactory.sol";
// libs
import {PoolMath, PoolState} from "./libs/PoolMath.sol";
import {Math} from "@openzeppelin/contracts@4.9.3/utils/math/Math.sol";
import {SignedMath} from "./libs/SignedMath.sol";
import {SafeCast} from "@openzeppelin/contracts@4.9.3/utils/math/SafeCast.sol";
import {SafeERC20} from "@openzeppelin/contracts@4.9.3/token/ERC20/utils/SafeERC20.sol";
import {DecimalConversion} from "./libs/DecimalConversion.sol";
import {MAX_LN_FEE_RATE_ROOT, MAX_PROTOCOL_FEE_PERCENT} from "./libs/Constants.sol";
import {Errors} from "./libs/Errors.sol";
// inherits
import {ERC20} from "@openzeppelin/contracts@4.9.3/token/ERC20/ERC20.sol";
import {ERC20Permit} from "@openzeppelin/contracts@4.9.3/token/ERC20/extensions/ERC20Permit.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts@4.9.3/security/ReentrancyGuard.sol";

/// @dev NapierPool is a pool that allows users to trade between a BasePool LP token and an underlying asset.
/// BasePool LP token is a token that represents a share of basket of 3 Principal Tokens Curve V2 pool.
///
/// Note: This pool and its math assumes the following regarding BasePool:
/// 1. The BasePool assets are 3 Napier Principal Tokens (PT) of the same maturity and same underlying asset.
///    We can consider BasePool LP token as something like ETF of 3 PTs.
/// 2. BasePool LP token is approximately three times more valuable than 1 PT because the initial deposit on Curve pool issues 1:1:1:1=pt1:pt2:pt3:share.
/// e.g. When the initial price of PT1, PT2 and PT3 is 1,`1` BasePool LP token is convertible to `1` PT1 + `1` PT2 + `1` PT3 instead of `1/3` for each PT.
/// We need to adjust the balance of BasePool LP token by multiplying 3 to make it comparable to underlying asset.
/// Economically at maturity 1/3 BaseLP token is expected to be convertible to approximately 1 underlying asset.
/// 3. BasePool LP token has 18 decimals.
/// 4. PTs have the same decimals as underlying asset.
contract NapierPool is INapierPool, ReentrancyGuard, ERC20Permit {
    using PoolMath for PoolState;
    using SafeERC20 for IERC20;
    using SafeERC20 for CurveTricryptoOptimizedWETH;
    using SignedMath for uint256;
    using SafeCast for uint256;
    using DecimalConversion for uint256;

    /// @dev Number of coins in the BasePool
    uint256 internal constant N_COINS = 3;

    /// @notice The factory that deployed this pool.
    IPoolFactory public immutable factory;

    /// @notice BasePool LP token i.e. Curve v2 3assets pool
    CurveTricryptoOptimizedWETH public immutable tricrypto;

    /// @notice Underlying asset (e.g. DAI, WETH)
    IERC20 public immutable underlying;
    uint8 internal immutable uDecimals;

    /// @notice Napier Principal Tokens
    /// @dev We don't use static size array here because Solidity doesn't support immutable static size array.
    /// @dev This would significantly reduce gas cost by avoiding SLOAD. About 2000 gas per reading principal token. (cold)
    /// @dev pt_i is the i-th asset of the BasePool coins. i.e pt[i] = CurveV2Pool.coins(i)
    IERC20 internal immutable pt1;
    IERC20 internal immutable pt2;
    IERC20 internal immutable pt3;

    /// @notice Maturity of the pool in unix timestamp
    /// @notice At or after maturity, the pool will no longer accept any liquidity provision or swap. Removing liquidity is still allowed.
    /// @dev Users can still swap, add or remove liquidity even after maturity on Curve pool.
    /// @dev expiry of the pool. This is the maturity of all principal tokens in the pool.
    uint256 public immutable maturity;

    /// @notice AMM parameter: Scalar root of the pool
    /// @dev adjust the capital efficiency of the market.
    uint256 public immutable scalarRoot;

    /// @notice AMM parameter: Initial anchor of the pool
    /// @dev initial rate anchor to anchor the market’s formula to be more capital efficient around a certain interest rate.
    int256 public immutable initialAnchor;

    /// @notice Recipient of the protocol fee
    address public immutable feeRecipient;

    /// @notice AMM parameter: Logarithmic fee rate root of the pool
    /// @dev Fees rate in terms of interest rate
    uint80 internal lnFeeRateRoot;

    /// @notice AMM parameter: Fee Napier charges for swaps in percentage (100=100%)
    uint8 internal protocolFeePercent;

    /// @notice AMM parameter: Last logarithmic implied rate of the pool
    uint256 public lastLnImpliedRate;

    /// @notice Total amount of BaseLpt in the pool (Reserve)
    uint128 public totalBaseLpt;

    /// @notice Total amount of underlying in the pool (Reserve)
    uint128 public totalUnderlying;

    /// @dev Revert if maturity is reached
    modifier notExpired() {
        if (maturity <= block.timestamp) revert Errors.PoolExpired();
        _;
    }

    constructor() payable ERC20("Napier Pool LP Token", "NapierPool LPT") ERC20Permit("Napier Pool LP Token") {
        factory = IPoolFactory(msg.sender);
        IPoolFactory.InitArgs memory args = factory.args();
        // Set mutable variables
        protocolFeePercent = args.configs.protocolFeePercent;
        // Set immutable variables
        scalarRoot = args.configs.scalarRoot;
        initialAnchor = args.configs.initialAnchor;
        lnFeeRateRoot = args.configs.lnFeeRateRoot;
        feeRecipient = args.configs.feeRecipient;

        address basePool = args.assets.basePool;
        tricrypto = CurveTricryptoOptimizedWETH(basePool);

        ERC20 _underlying = ERC20(args.assets.underlying);
        underlying = _underlying;
        uDecimals = _underlying.decimals();

        // hack: we don't use static size array here to save gas cost
        ITranche _pt1 = ITranche(args.assets.principalTokens[0]);
        ITranche _pt2 = ITranche(args.assets.principalTokens[1]);
        ITranche _pt3 = ITranche(args.assets.principalTokens[2]);

        pt1 = _pt1;
        pt2 = _pt2;
        pt3 = _pt3;
        // Assume that the maturity of all principal tokens are the same
        maturity = _pt1.maturity();

        // Approve Curve pool to transfer PTs
        _pt1.approve(basePool, type(uint256).max); // dev: Principal token will revert if failed to approve
        _pt2.approve(basePool, type(uint256).max);
        _pt3.approve(basePool, type(uint256).max);
    }

    ////////////////////////////////////////////////////////////////////////////////
    // Mutative functions
    ////////////////////////////////////////////////////////////////////////////////

    /// @inheritdoc INapierPool
    /// @notice Provide BasePoolLpToken (BaseLpt) and underlying in exchange for Lp token, which will grant LP holders more exchange fee over time
    /// @dev Mint as much LP token as possible.
    /// @dev BaseLpt and Underlying should be transferred to this contract prior to calling
    /// @dev Revert if maturity is reached
    /// @dev Revert if deposited assets are too small to mint more than minimum liquidity
    /// @dev Revert if deposited assets are too small to compute ln implied rate
    /// @dev Revert if computed initial exchange rate in base LP token is below one. (deposited base LP token is much less than deposited underlying)
    /// @dev Revert if proportion of deposited base LP token is higher than the maximum proportion. (deposited base LP token is too large compared to deposited underlying)
    /// @dev Revert if minted LP token is zero
    /// @param recipient recipient of the minted LP token
    /// @return liquidity amount of LP token minted
    function addLiquidity(uint256 underlyingInDesired, uint256 baseLptInDesired, address recipient, bytes memory data)
        external
        override
        nonReentrant
        notExpired
        returns (uint256)
    {
        // Cache state variables
        (uint256 _totalUnderlying, uint256 _totalBaseLpt) = (totalUnderlying, totalBaseLpt);

        uint256 bBalance = _balance(tricrypto); // Base Pool LP token reserve
        uint256 uBalance = _balance(underlying); // NOTE: Sum of underlying asset reserve and stuck protocol fees.

        (uint256 liquidity, uint256 underlyingUsed, uint256 baseLptUsed) =
            _mintLiquidity(_totalUnderlying, _totalBaseLpt, recipient, underlyingInDesired, baseLptInDesired);

        /// WRITE ///
        // Last ln implied rate doesn't change because liquidity is added proportionally
        totalUnderlying = (_totalUnderlying + underlyingUsed).toUint128();
        totalBaseLpt = (_totalBaseLpt + baseLptUsed).toUint128();

        /// INTERACTION ///
        if (!factory.isCallbackReceiverAuthorized(msg.sender)) revert Errors.PoolUnauthorizedCallback();
        INapierMintCallback(msg.sender).mintCallback(underlyingUsed, baseLptUsed, data);

        /// CHECK ///
        if (_balance(tricrypto) < bBalance + baseLptUsed) revert Errors.PoolInsufficientBaseLptReceived();
        if (_balance(underlying) < uBalance + underlyingUsed) {
            revert Errors.PoolInsufficientUnderlyingReceived();
        }

        return liquidity;
    }

    /// @notice Mint LP token for the given amount of underlying and base LP token
    /// @dev This function doesn't update state variables except Lp token and last implied rate.
    /// @dev *variableName*18 represents the value *in 18 decimals*.
    /// @dev Mint as much LP token as possible.
    /// @dev If the pool is not initialized, a portion of issued LP token will be permanently locked.
    /// @dev Revert if minted LP token is zero
    /// @param totalUnderlyingCache total underlying balance of the pool in underlying unit.
    /// @param totalBaseLptCache total base LP token balance of the pool **(All BaseLpt has 18 decimals)**
    /// @param recipient recipient of the minted LP token
    /// @param underlyingIn deposited underlying **in underlying unit**
    /// @param baseLptIn deposited base LP token **(All BaseLpt has 18 decimals)**
    /// @return liquidity - amount of LP token minted
    /// @return underlyingUsed - amount of underlying used
    /// @return baseLptUsed - amount of base LP token used
    function _mintLiquidity(
        uint256 totalUnderlyingCache,
        uint256 totalBaseLptCache,
        address recipient,
        uint256 underlyingIn,
        uint256 baseLptIn
    ) internal returns (uint256 liquidity, uint256 underlyingUsed, uint256 baseLptUsed) {
        uint256 totalLp = totalSupply();

        if (totalLp == 0) {
            // Note: This path is executed only once.
            // Amounts of underlying is converted to 18 decimals to normalize how much LP token is issued.
            liquidity = Math.sqrt(underlyingIn.to18Decimals(uDecimals) * baseLptIn) - PoolMath.MINIMUM_LIQUIDITY;
            underlyingUsed = underlyingIn;
            baseLptUsed = baseLptIn;
            /// WRITE
            // Note: Only at initial issuance, a portion of the issued LP tokens will be permanently locked.
            _mint(address(1), PoolMath.MINIMUM_LIQUIDITY);
            lastLnImpliedRate = PoolMath.computeInitialLnImpliedRate(
                PoolState({
                    totalBaseLptTimesN: baseLptUsed * N_COINS,
                    totalUnderlying18: underlyingUsed.to18Decimals(uDecimals),
                    scalarRoot: scalarRoot,
                    maturity: maturity,
                    lnFeeRateRoot: lnFeeRateRoot,
                    protocolFeePercent: protocolFeePercent,
                    lastLnImpliedRate: 0
                }),
                initialAnchor
            );
            emit UpdateLnImpliedRate(lastLnImpliedRate);
        } else {
            // Note: Multiplying N_COINS is not needed because it is canceled out thanks to ratio calculation.
            uint256 netLpByBaseLpt = (baseLptIn * totalLp) / totalBaseLptCache;
            uint256 netLpByUnderlying = (underlyingIn * totalLp) / totalUnderlyingCache;
            if (netLpByBaseLpt < netLpByUnderlying) {
                liquidity = netLpByBaseLpt;
                baseLptUsed = baseLptIn;
                underlyingUsed = (totalUnderlyingCache * liquidity) / totalLp;
            } else {
                liquidity = netLpByUnderlying;
                underlyingUsed = underlyingIn;
                baseLptUsed = (totalBaseLptCache * liquidity) / totalLp;
            }
        }
        /// WRITE
        // Mint LP token to recipient
        if (liquidity == 0) revert Errors.PoolZeroAmountsOutput();
        _mint(recipient, liquidity);

        emit Mint(recipient, liquidity, underlyingUsed, baseLptUsed);
    }

    /// @inheritdoc INapierPool
    /// @notice Burn Lp token in exchange for underlying and base LP token.
    /// @dev liquidity token (Lp token) should be transferred to this contract prior to calling this function
    /// @dev Revert if underlying and base LP token are zero
    /// @dev Revert if liquidity to burn is zero
    /// @param recipient recipient of the withdrawn underlying and base LP token
    /// @return underlyingOut amount of underlying withdrawn
    /// @return baseLptOut amount of base LP token withdrawn
    function removeLiquidity(address recipient)
        external
        override
        nonReentrant
        returns (uint256 underlyingOut, uint256 baseLptOut)
    {
        uint256 liquidity = balanceOf(address(this));
        (uint256 _totalUnderlying, uint256 _totalBaseLpt) = (totalUnderlying, totalBaseLpt);

        (underlyingOut, baseLptOut) = _burnLiquidity(totalUnderlying, totalBaseLpt, liquidity);
        if (underlyingOut == 0 && baseLptOut == 0) revert Errors.PoolZeroAmountsOutput();

        /// WRITE ///
        totalUnderlying = (_totalUnderlying - underlyingOut).toUint128();
        totalBaseLpt = (_totalBaseLpt - baseLptOut).toUint128();

        /// INTERACTION ///
        underlying.safeTransfer(recipient, underlyingOut);
        tricrypto.safeTransfer(recipient, baseLptOut);

        emit Burn(recipient, liquidity, underlyingOut, baseLptOut);
    }

    /// @notice Burn Lp token in exchange for underlying and Base LP token.
    /// @dev This function doesn't update state variables except Lp token.
    /// @dev *variableName*18 represents the value *in 18 decimals*.
    /// @dev Not revert even if `underlyingOut18` and `baseLptOut` are zero
    /// @param totalUnderlyingCache total underlying balance of the pool **in 18 decimals**.
    /// @param totalBaseLptCache total Base LP token balance of the pool **(All BaseLpt has 18 decimals)**
    /// @param liquidity amount of LP token to burn
    /// @return underlyingOut - amount of underlying withdrawn **in 18 decimals**
    /// @return baseLptOut - amount of Base LP token withdrawn
    function _burnLiquidity(uint256 totalUnderlyingCache, uint256 totalBaseLptCache, uint256 liquidity)
        internal
        returns (uint256 underlyingOut, uint256 baseLptOut)
    {
        if (liquidity == 0) revert Errors.PoolZeroAmountsInput();

        uint256 totalLp = totalSupply();
        underlyingOut = (liquidity * totalUnderlyingCache) / totalLp;
        baseLptOut = (liquidity * totalBaseLptCache) / totalLp;

        _burn(address(this), liquidity);
    }

    /// @inheritdoc INapierPool
    /// @notice Swap exact amount of PT for underlying token
    /// @dev Revert if maturity is reached
    /// @dev Revert if index is invalid
    /// @dev Revert if callback recipient is not authorized
    /// @dev Revert if ptIn is too large and runs out of underlying reserve
    /// @dev Revert if minted base Lp token is less than expected. (pt is not enough to mint expected base Lp token amount)
    /// @param index index of the PT token
    /// @param ptIn amount of PT token to swap
    /// @param recipient recipient of the underlying token and receiver of callback function
    /// @param data data to pass to the recipient on callback. If empty, no callback.
    /// @return underlyingOut amount of underlying token out
    function swapPtForUnderlying(uint256 index, uint256 ptIn, address recipient, bytes calldata data)
        external
        override
        nonReentrant
        notExpired
        returns (uint256 underlyingOut)
    {
        uint256[3] memory amountsIn;
        uint256 exactBaseLptIn;
        uint256 swapFee;
        uint256 protocolFee;
        // stack too deep
        {
            PoolState memory state = _loadState();

            // Pre-compute the swap result given principal token
            amountsIn[index] = ptIn;
            exactBaseLptIn = tricrypto.calc_token_amount(amountsIn, true);
            // Pre-compute the swap result given BaseLpt and underlying
            (uint256 underlyingOut18, uint256 swapFee18, uint256 protocolFee18) =
                state.swapExactBaseLpTokenForUnderlying(exactBaseLptIn);
            underlyingOut = underlyingOut18.from18Decimals(uDecimals);
            swapFee = swapFee18.from18Decimals(uDecimals);
            protocolFee = protocolFee18.from18Decimals(uDecimals);

            // dev: If `underlyingOut18` is less than 10**(18 - underlyingDecimals), `underlyingOut` will be zero.
            // Revert to prevent users from swapping non-zero amount of BaseLpt for 0 underlying.
            if (underlyingOut == 0) revert Errors.PoolZeroAmountsOutput();

            /// WRITE ///
            _writeState(state);
        }
        {
            uint256 bBalance = _balance(tricrypto); // Base Pool LP token reserve
            uint256 uBalance = _balance(underlying); // NOTE: Sum of underlying asset reserve and stuck protocol fees.

            /// INTERACTION ///
            // dev: Optimistically transfer underlying to recipient
            underlying.safeTransfer(recipient, underlyingOut);

            // incoming to user => positive, outgoing from user => negative
            if (!factory.isCallbackReceiverAuthorized(msg.sender)) revert Errors.PoolUnauthorizedCallback();
            INapierSwapCallback(msg.sender).swapCallback(underlyingOut.toInt256(), ptIn.neg(), data);

            // Curve pool will revert if we don't receive enough principal token at this point
            // Deposit the principal token which `msg.sender` should send in the callback to BasePool
            tricrypto.add_liquidity(amountsIn, 0); // unlimited slippage

            /// CHECK ///
            // Revert if we don't receive enough baseLpt
            if (_balance(tricrypto) < bBalance + exactBaseLptIn) revert Errors.PoolInsufficientBaseLptReceived();
            if (_balance(underlying) < uBalance - underlyingOut) {
                revert Errors.PoolInvariantViolated();
            }
        }
        emit Swap(msg.sender, recipient, underlyingOut.toInt256(), index, ptIn.neg(), swapFee, protocolFee);
    }

    /// @inheritdoc INapierPool
    /// @notice Swap underlying token for approximately exact amount of PT
    /// @notice This function can NOT swap underlying for *exact* amount of PT due to approximation error on Curve pool.
    /// Revert if maturity is reached
    /// Revert if index is invalid
    /// Revert if callback recipient is not authorized
    /// Revert if ptOutDesired is too large and runs out of pt reserve in Base pool
    /// Revert if underlying received is less than expected.
    /// @param index index of the PT
    /// @param ptOutDesired amount of PT to be swapped out
    /// @param recipient recipient of the PT and receiver of callback function
    /// @param data data to pass to the recipient on callback
    /// callback can be invoked by only authorized contract
    function swapUnderlyingForPt(uint256 index, uint256 ptOutDesired, address recipient, bytes calldata data)
        external
        override
        nonReentrant
        notExpired
        returns (uint256 underlyingIn)
    {
        uint256 exactBaseLptOut;
        uint256 swapFee;
        uint256 protocolFee;
        // Pre-compute the swap result
        // stack too deep
        {
            PoolState memory state = _loadState();

            uint256[3] memory ptsOut;
            ptsOut[index] = ptOutDesired;
            exactBaseLptOut = tricrypto.calc_token_amount(ptsOut, false);
            // Pre-compute the swap result given BaseLpt
            (uint256 underlyingIn18, uint256 swapFee18, uint256 protocolFee18) =
                state.swapUnderlyingForExactBaseLpToken(exactBaseLptOut);
            underlyingIn = underlyingIn18.from18Decimals(uDecimals);
            swapFee = swapFee18.from18Decimals(uDecimals);
            protocolFee = protocolFee18.from18Decimals(uDecimals);

            // dev: If `underlyingIn18` is less than 10**(18 - underlyingDecimals), `underlyingIn` will be zero.
            // Revert to prevent users from swapping for free.
            if (underlyingIn == 0) revert Errors.PoolZeroAmountsInput();

            /// WRITE ///
            _writeState(state);
        }

        uint256 bBalance = _balance(tricrypto); // Base Pool LP token reserve
        uint256 uBalance = _balance(underlying); // NOTE: Sum of underlying asset reserve and stuck protocol fees.

        /// INTERACTION ///
        // Remove the principal token from BasePool with minimum = 0
        uint256 ptOutActual = tricrypto.remove_liquidity_one_coin(exactBaseLptOut, index, 0, false, recipient);

        // incoming to user => positive, outgoing from user => negative
        if (!factory.isCallbackReceiverAuthorized(msg.sender)) revert Errors.PoolUnauthorizedCallback();
        INapierSwapCallback(msg.sender).swapCallback(underlyingIn.neg(), ptOutActual.toInt256(), data);

        /// CHECK ///
        // Revert if we don't receive enough underlying
        if (_balance(underlying) < uBalance + underlyingIn) {
            revert Errors.PoolInsufficientUnderlyingReceived();
        }
        if (_balance(tricrypto) < bBalance - exactBaseLptOut) {
            revert Errors.PoolInvariantViolated();
        }

        emit Swap(msg.sender, recipient, underlyingIn.neg(), index, ptOutActual.toInt256(), swapFee, protocolFee);
    }

    /// @inheritdoc INapierPool
    /// @notice Swap underlying token for exact amount of Base Lp token
    /// @notice Approve this contract to use underlying prior to calling this function.
    /// @dev Revert if maturity is reached
    function swapUnderlyingForExactBaseLpToken(uint256 baseLptOut, address recipient)
        external
        override
        nonReentrant
        notExpired
        returns (uint256)
    {
        PoolState memory state = _loadState();

        (uint256 underlyingIn18, uint256 swapFee18, uint256 protocolFee18) =
            state.swapUnderlyingForExactBaseLpToken(baseLptOut);
        uint256 underlyingIn = underlyingIn18.from18Decimals(uDecimals);
        uint256 swapFee = swapFee18.from18Decimals(uDecimals);
        uint256 protocolFee = protocolFee18.from18Decimals(uDecimals);

        // dev: If `underlyingIn18` is less than 10**(18 - underlyingDecimals), `underlyingIn` will be zero.
        // Revert to prevent users from swapping for free.
        if (underlyingIn == 0) revert Errors.PoolZeroAmountsInput();

        /// WRITE ///
        _writeState(state);

        /// INTERACTION ///
        underlying.safeTransferFrom(msg.sender, address(this), underlyingIn);
        tricrypto.safeTransfer(recipient, baseLptOut);

        emit SwapBaseLpt(msg.sender, recipient, -(underlyingIn.toInt256()), baseLptOut.toInt256(), swapFee, protocolFee);
        return underlyingIn;
    }

    /// @inheritdoc INapierPool
    /// @notice Swap exact amount of Base Lp token for underlying token
    /// @notice Approve this contract to use BaseLP token prior to calling this function.
    /// @dev Revert if maturity is reached
    function swapExactBaseLpTokenForUnderlying(uint256 baseLptIn, address recipient)
        external
        override
        nonReentrant
        notExpired
        returns (uint256)
    {
        PoolState memory state = _loadState();

        (uint256 underlyingOut18, uint256 swapFee18, uint256 protocolFee18) =
            state.swapExactBaseLpTokenForUnderlying(baseLptIn);
        uint256 underlyingOut = underlyingOut18.from18Decimals(uDecimals);
        uint256 swapFee = swapFee18.from18Decimals(uDecimals);
        uint256 protocolFee = protocolFee18.from18Decimals(uDecimals);

        // dev: If `underlyingOut18` is less than 10**(18 - underlyingDecimals), `underlyingOut` will be zero.
        // Revert to prevent users from swapping non-zero amount of BaseLpt for 0 underlying.
        if (underlyingOut == 0) revert Errors.PoolZeroAmountsOutput();

        /// WRITE ///
        _writeState(state);

        /// INTERACTION ///
        tricrypto.safeTransferFrom(msg.sender, address(this), baseLptIn);
        underlying.safeTransfer(recipient, underlyingOut);

        emit SwapBaseLpt(msg.sender, recipient, underlyingOut.toInt256(), baseLptIn.neg(), swapFee, protocolFee);
        return underlyingOut;
    }

    /// @notice Forcibly sweep excess tokens to the fee recipient
    /// @notice This function can be called by anyone
    /// @notice Protocol fee is sent to the fee recipient
    /// @dev Excess tokens (excluding fees) can be swept by anyone, using `addLiquidity` etc.
    /// @dev Can be used when the pool is in an inconsistent state:
    /// A large amount of base LP token or underlying is donated to the pool, which makes the pool revert when swapping base LP token for underlying
    /// because the pool doesn't have enough underlying to swap.
    function skim() external nonReentrant {
        (uint256 _totalUnderlying, uint256 _totalBaseLpt) = (totalUnderlying, totalBaseLpt);

        uint256 baseLptExcess = _balance(tricrypto) - _totalBaseLpt;
        uint256 feesAndExcess = _balance(underlying) - _totalUnderlying;

        if (baseLptExcess != 0) tricrypto.safeTransfer(feeRecipient, baseLptExcess);
        if (feesAndExcess != 0) underlying.safeTransfer(feeRecipient, feesAndExcess);
    }

    ////////////////////////////////////////////////////////////////////////////////
    // Protected functions
    ////////////////////////////////////////////////////////////////////////////////

    /// @notice Set fee parameters
    /// @notice Only the factory owner can call this function.
    /// @param paramName name of the parameter to set (lnFeeRateRoot, protocolFeePercent)
    /// @param value value of the parameter
    function setFeeParameter(bytes32 paramName, uint256 value) external {
        if (factory.owner() != msg.sender) revert Errors.PoolOnlyOwner();

        if (paramName == "lnFeeRateRoot") {
            if (value > MAX_LN_FEE_RATE_ROOT) revert Errors.LnFeeRateRootTooHigh();
            lnFeeRateRoot = uint80(value); // unsafe cast here is Okay because we checked the value is less than MAX_LN_FEE_RATE_ROOT
        } else if (paramName == "protocolFeePercent") {
            if (value > MAX_PROTOCOL_FEE_PERCENT) revert Errors.ProtocolFeePercentTooHigh();
            protocolFeePercent = uint8(value); // unsafe cast here is Okay
        } else {
            revert Errors.PoolInvalidParamName();
        }
    }

    ////////////////////////////////////////////////////////////////////////////////
    // View functions
    ////////////////////////////////////////////////////////////////////////////////

    /// @notice get Principal Tokens within the pool
    function principalTokens() public view returns (IERC20[3] memory) {
        return [pt1, pt2, pt3];
    }

    /// @notice read the state of the pool
    function readState() external view returns (PoolState memory) {
        return _loadState();
    }
    /// @notice get underlying and tricrypto addresses of the pool

    function getAssets() public view returns (address, address) {
        return (address(underlying), address(tricrypto));
    }

    ////////////////////////////////////////////////////////////////////////////////
    // Util
    ////////////////////////////////////////////////////////////////////////////////

    /// @notice read the state of the pool from storage into memory
    function _loadState() internal view returns (PoolState memory state) {
        state = PoolState({
            totalBaseLptTimesN: totalBaseLpt * N_COINS,
            totalUnderlying18: uint256(totalUnderlying).to18Decimals(uDecimals),
            lnFeeRateRoot: lnFeeRateRoot,
            protocolFeePercent: protocolFeePercent,
            scalarRoot: scalarRoot,
            maturity: maturity,
            lastLnImpliedRate: lastLnImpliedRate
        });
    }

    /// @notice write back the state of the pool from memory to storage
    function _writeState(PoolState memory state) internal {
        lastLnImpliedRate = state.lastLnImpliedRate;
        totalBaseLpt = (state.totalBaseLptTimesN / N_COINS).toUint128();
        totalUnderlying = state.totalUnderlying18.from18Decimals(uDecimals).toUint128();

        emit UpdateLnImpliedRate(state.lastLnImpliedRate);
    }

    /// @notice credit: UniswapV3Pool
    /// @dev This function is gas optimized to avoid a redundant extcodesize check in addition to the returndatasize
    /// check
    function _balance(IERC20 token) internal view returns (uint256) {
        (bool success, bytes memory data) =
            address(token).staticcall(abi.encodeWithSelector(IERC20.balanceOf.selector, address(this)));
        require(success && data.length >= 32);
        return abi.decode(data, (uint256));
    }
}
