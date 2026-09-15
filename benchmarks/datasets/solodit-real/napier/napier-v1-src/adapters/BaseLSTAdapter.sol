// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.10;

import {IWETH9} from "../interfaces/IWETH9.sol";
import {IERC20} from "@openzeppelin/contracts@4.9.3/token/ERC20/IERC20.sol";

import {BaseAdapter} from "../BaseAdapter.sol";
import {ERC4626} from "@openzeppelin/contracts@4.9.3/token/ERC20/extensions/ERC4626.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts@4.9.3/security/ReentrancyGuard.sol";

import {SafeCast} from "@openzeppelin/contracts@4.9.3/utils/math/SafeCast.sol";
import {WETH} from "../Constants.sol";

/// @notice Adapter for Liquid Staking Token (LST)
/// @dev This adapter facilitates immediate ETH withdrawals without a waiting period.
/// It maintains an ETH buffer to enable these withdrawals. The size of this buffer is determined
/// by a specified desired buffer percentage. The maintenance of the buffer
/// are handled by a designated account.
/// @dev LST Adapter is NOT compatible with EIP4626 standard. We don't expect it to be used by other contracts other than Tranche.
abstract contract BaseLSTAdapter is BaseAdapter, ERC4626, ReentrancyGuard {
    using SafeCast for uint256;

    uint256 constant BUFFER_PERCENTAGE_PRECISION = 1e18; // 1e18 = 100%
    uint256 constant MIN_BUFFER_PERCENTAGE = 0.01 * 1e18; // 1%

    /// @notice Rebalancer of the ETH buffer, can be set by the owner
    /// @notice The account can request a withdrawal
    address public rebalancer;

    /// @notice Desired buffer percentage in WAD
    uint256 public targetBufferPercentage = 0.1 * 1e18; // 10% desired buffer percentage

    /// @notice Amount of ETH pending withdrawal
    uint128 public withdrawalQueueEth;

    /// @notice Amount of ETH available (Buffer), does not include pending withdrawal. Internal accounting of ETH
    uint128 public bufferEth;

    /// @notice Request ID of the withdrawal request
    /// @dev 0 if there is no pending withdrawal request
    uint256 public requestId;

    error ZeroAssets();
    error ZeroShares();
    error InsufficientBuffer();
    error BufferTooLarge();
    error InvalidBufferPercentage();
    error WithdrawalPending();
    error NoPendingWithdrawal();
    error NotRebalancer();
    error NotImplemented();

    /// @notice Reverts if the caller is not the rebalancer
    modifier onlyRebalancer() {
        if (rebalancer != msg.sender) revert NotRebalancer();
        _;
    }

    /// @dev Adapter itself is the target token
    constructor(address _rebalancer) BaseAdapter(WETH, address(this)) ERC4626((IWETH9(WETH))) {
        rebalancer = _rebalancer;
    }

    ////////////////////////////////////////////////////////
    /// ADAPTER METHOD
    ////////////////////////////////////////////////////////

    /// @notice Handles prefunded deposits
    /// @return The amount of staked ETH
    /// @return The amount of shares minted
    function prefundedDeposit() external nonReentrant returns (uint256, uint256) {
        uint256 bufferEthCache = bufferEth; // cache storage reads
        uint256 queueEthCache = withdrawalQueueEth; // cache storage reads
        uint256 assets = IWETH9(WETH).balanceOf(address(this)) - bufferEthCache; // amount of WETH deposited at this time
        uint256 shares = previewDeposit(assets);

        if (assets == 0) return (0, 0);
        if (shares == 0) revert ZeroShares();

        // Calculate the target buffer amount considering the user's deposit.
        // bufferRatio is defined as the ratio of ETH balance to the total assets in the adapter in ETH.
        // Formula:
        // desiredBufferRatio = (withdrawalQueueEth + bufferEth + assets - s) / (withdrawalQueueEth + bufferEth + stakedEth + assets)
        // Where:
        // assets := Amount of ETH the user is depositing
        // s := Amount of ETH to stake at this time, s <= bufferEth + assets.
        //
        // Thus, the formula can be simplified to:
        // s = (withdrawalQueueEth + bufferEth + assets) - (withdrawalQueueEth + bufferEth + stakedEth + assets) * desiredBufferRatio
        //   = (withdrawalQueueEth + bufferEth + assets) - targetBufferEth
        //
        // Flow:
        // If `s` <= 0, don't stake any ETH.
        // If `s` < bufferEth + assets, stake `s` amount of ETH.
        // If `s` >= bufferEth + assets, all available ETH can be staked in theory.
        // However, we cap the stake amount. This is to prevent the buffer from being completely drained.
        //
        // Let `a` be the available amount of ETH in the buffer after the deposit. `a` is calculated as:
        // a = (bufferEth + assets) - s
        uint256 targetBufferEth = ((totalAssets() + assets) * targetBufferPercentage) / BUFFER_PERCENTAGE_PRECISION;

        /// WRITE ///
        _mint(msg.sender, shares);

        uint256 availableEth = bufferEthCache + assets; // non-zero

        // If the buffer is insufficient: Doesn't stake any of the deposit
        if (targetBufferEth >= availableEth + queueEthCache) {
            bufferEth = availableEth.toUint128();
            return (assets, shares);
        }

        uint256 stakeAmount;
        unchecked {
            stakeAmount = availableEth + queueEthCache - targetBufferEth; // non-zero, no underflow
        }
        // If the stake amount exceeds 95% of the available ETH, cap the stake amount.
        // This is to prevent the buffer from being completely drained. This is not a complete solution.
        //
        // The condition: stakeAmount > availableEth, is equivalent to: queueEthCache > targetBufferEth
        // Possible scenarios:
        // - Target buffer percentage was changed to a lower value and there is a large withdrawal request pending.
        // - There is a pending withdrawal request and the available ETH are not left in the buffer.
        // - There is no pending withdrawal request and the available ETH are not left in the buffer.
        uint256 maxStakeAmount = (availableEth * 95) / 100;
        if (stakeAmount > maxStakeAmount) {
            stakeAmount = maxStakeAmount; // max 95% of the available ETH
        }

        /// INTERACT ///
        // Deposit into the yield source
        // Actual amount of ETH spent may be less than the requested amount.
        stakeAmount = _stake(stakeAmount); // stake amount can be 0

        /// WRITE ///
        bufferEth = (availableEth - stakeAmount).toUint128(); // no underflow theoretically

        return (assets, shares);
    }

    /// @notice Handles prefunded redemptions
    /// @dev Withdraw from the buffer. If the buffer is insufficient, revert with an error
    /// @param recipient The address to receive the redeemed WETH
    /// @return The amount of redeemed WETH
    /// @return The amount of shares burned
    function prefundedRedeem(address recipient) external virtual returns (uint256, uint256) {
        uint256 shares = balanceOf(address(this));
        uint256 assets = previewRedeem(shares);

        if (shares == 0) return (0, 0);
        if (assets == 0) revert ZeroAssets();

        uint256 bufferEthCache = bufferEth;
        // If the buffer is insufficient, shares cannot be redeemed immediately
        // Need to wait for the withdrawal to be completed and the buffer to be refilled.
        if (assets > bufferEthCache) revert InsufficientBuffer();

        unchecked {
            /// WRITE ///
            // Reduce the buffer and burn the shares
            bufferEth = (bufferEthCache - assets).toUint128(); // no underflow
            _burn(address(this), shares);
        }

        /// INTERACT ///
        IWETH9(WETH).transfer(recipient, assets);

        return (assets, shares);
    }

    ////////////////////////////////////////////////////////
    /// VIRTUAL METHOD
    ////////////////////////////////////////////////////////

    /// @notice Request a withdrawal of ETH
    /// @dev This function is called by only the rebalancer
    /// @dev Reverts if there is a pending withdrawal request
    /// @dev Reverts if the buffer is sufficient to cover the desired buffer percentage of the total assets
    function requestWithdrawal() external virtual nonReentrant onlyRebalancer {
        if (requestId != 0) revert WithdrawalPending();

        uint256 targetBufferEth = (totalAssets() * targetBufferPercentage) / BUFFER_PERCENTAGE_PRECISION;

        // If the buffer exceeds the target buffer, revert.
        // If the buffer is insufficient, request a withdrawal to refill the buffer.
        // note: use `>=` instead of `>` to prevent amount of ETH to withdraw to be 0
        // note: At this point, `withdrawalQueueEth` is 0 because there is no pending withdrawal request.
        // `nonStakedEth` = `bufferEth` + 0 = `bufferEth`
        uint256 bufferEthCache = bufferEth;
        if (bufferEthCache >= targetBufferEth) revert BufferTooLarge();

        unchecked {
            // Ensure that `withdrawAmount` is non-zero and withdrawalQueueEth is zero.
            uint256 withdrawAmount = targetBufferEth - bufferEthCache; // no underflow

            /// WRITE & INTERACT ///
            // Record the pending withdrawal request
            // Request a withdrawal
            (uint256 queueAmount, uint256 _requestId) = _requestWithdrawal(withdrawAmount);
            withdrawalQueueEth = queueAmount.toUint128();
            requestId = _requestId;
        }
    }

    /// @notice Request a withdrawal of all staked ETH
    /// @dev This function is called by only the rebalancer
    /// @dev Reverts if there is a pending withdrawal request
    function requestWithdrawalAll() external virtual;

    /// @notice Claim the finized withdrawal request
    /// @dev This function is called by anyone
    /// @dev Reverts if there is no pending withdrawal request
    function claimWithdrawal() external virtual;

    /// @notice Stake the given amount of ETH into the yield source
    /// @param stakeAmount The amount of ETH to stake
    /// @return The actual amount of ETH spent
    function _stake(uint256 stakeAmount) internal virtual returns (uint256);

    /// @notice Request a withdrawal of the given amount of ETH from the yield source
    /// @param withdrawAmount The amount of ETH to withdraw
    /// @return queueAmount The amount of ETH withdrawn
    /// @return requestId The request Id of the withdrawal request
    function _requestWithdrawal(
        uint256 withdrawAmount
    ) internal virtual returns (uint256 queueAmount, uint256 requestId);

    /// @dev Must be overridden by inheriting contracts
    /// @inheritdoc ERC4626
    function totalAssets() public view virtual override returns (uint256) {}

    function scale() external view override returns (uint256) {
        return convertToAssets(1e18);
    }

    /// @notice Returns the present buffer percentage in WAD. e.g) 10% => 0.1 * 1e18
    function bufferPresentPercentage() external view returns (uint256) {
        return ((bufferEth + withdrawalQueueEth) * BUFFER_PERCENTAGE_PRECISION) / totalAssets();
    }

    ////////////////////////////////////////////////////////
    /// ADMIN METHOD
    ////////////////////////////////////////////////////////

    function setRebalancer(address _rebalancer) external onlyOwner {
        rebalancer = _rebalancer;
    }

    /// @notice Set the maximum buffer percentage
    /// @param _targetBufferPercentage The maximum buffer percentage in WAD
    function setTargetBufferPercentage(uint256 _targetBufferPercentage) external onlyRebalancer {
        if (_targetBufferPercentage < MIN_BUFFER_PERCENTAGE || _targetBufferPercentage > BUFFER_PERCENTAGE_PRECISION) {
            revert InvalidBufferPercentage();
        }
        targetBufferPercentage = _targetBufferPercentage;
    }

    /////////////////////////////////////////////////////////
    /// NOT IMPLEMENTED METHOD
    /////////////////////////////////////////////////////////

    /// @notice direct deposit,mint,redeem,withdraw should be reverted.
    function deposit(uint256, address) public pure override returns (uint256) {
        revert NotImplemented();
    }

    function mint(uint256, address) public pure override returns (uint256) {
        revert NotImplemented();
    }

    function withdraw(uint256, address, address) public pure override returns (uint256) {
        revert NotImplemented();
    }

    function redeem(uint256, address, address) public pure override returns (uint256) {
        revert NotImplemented();
    }
}
