// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.10;

// interfaces
import {IWETH9} from "./interfaces/external/IWETH9.sol";
import {IERC20} from "@openzeppelin/contracts@4.9.3/token/ERC20/IERC20.sol";
import {ITrancheFactory} from "@napier/napier-v1/src/interfaces/ITrancheFactory.sol";
import {ITranche} from "@napier/napier-v1/src/interfaces/ITranche.sol";
import {ITrancheRouter} from "./interfaces/ITrancheRouter.sol";
// libraries
import {SafeERC20} from "@openzeppelin/contracts@4.9.3/token/ERC20/utils/SafeERC20.sol";
import {TrancheAddress} from "./libs/TrancheAddress.sol";
// inherits
import {PeripheryImmutableState} from "./base/PeripheryImmutableState.sol";
import {PeripheryPayments} from "./base/PeripheryPayments.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts@4.9.3/security/ReentrancyGuard.sol";
import {Multicallable} from "./base/Multicallable.sol";

/// @notice Periphery contract for interacting with Tranches.
/// @dev Accept native ETH and ERC20 tokens.
/// @dev Multicallable is used to batch calls to `unwrapWETH9`.
contract TrancheRouter is ITrancheRouter, PeripheryPayments, ReentrancyGuard, Multicallable {
    using SafeERC20 for IERC20;

    /// @dev Tranches called by this router must be created by this factory
    ITrancheFactory public immutable trancheFactory;

    bytes32 internal immutable TRANCHE_CREATION_HASH;

    constructor(ITrancheFactory _trancheFactory, IWETH9 _WETH9) PeripheryImmutableState(_WETH9) {
        trancheFactory = _trancheFactory;
        TRANCHE_CREATION_HASH = _trancheFactory.TRANCHE_CREATION_HASH();
    }

    /// @notice deposit an `underlyingAmount` of underlying token into the yield source, receiving PT and YT.
    /// @dev Accept native ETH.
    /// @inheritdoc ITrancheRouter
    function issue(address adapter, uint256 maturity, uint256 underlyingAmount, address to)
        external
        payable
        nonReentrant
        returns (uint256)
    {
        ITranche tranche =
            TrancheAddress.computeAddress(adapter, maturity, TRANCHE_CREATION_HASH, address(trancheFactory));
        IERC20 underlying = IERC20(tranche.underlying());

        // Transfer underlying tokens to this contract
        // If this contract holds enough ETH, wrap it. Otherwise, transfer from the caller.
        if (address(underlying) == address(WETH9) && address(this).balance >= underlyingAmount) {
            WETH9.deposit{value: underlyingAmount}();
        } else {
            underlying.safeTransferFrom(msg.sender, address(this), underlyingAmount);
        }
        // Force approve
        underlying.forceApprove(address(tranche), underlyingAmount);

        return tranche.issue(to, underlyingAmount);
    }

    /// @notice Withdraws underlying tokens from the caller in exchange for `pyAmount` of PT and YT.
    /// @notice Approve this contract to spend `pyAmount` of PT.
    /// @dev If caller want to withdraw ETH, specify `to` as the this contract's address and use `unwrapWETH9` with Multicall.
    /// @inheritdoc ITrancheRouter
    function redeemWithYT(address adapter, uint256 maturity, uint256 pyAmount, address to)
        external
        nonReentrant
        returns (uint256)
    {
        ITranche tranche =
            TrancheAddress.computeAddress(adapter, maturity, TRANCHE_CREATION_HASH, address(trancheFactory));
        return tranche.redeemWithYT({from: msg.sender, to: to, pyAmount: pyAmount});
    }

    /// @notice Approve this contract to spend `principalAmount` of PT.
    /// @dev If caller want to withdraw ETH, specify `to` as the this contract's address and use `unwrapWETH9` with Multicall.
    /// @inheritdoc ITrancheRouter
    function redeem(address adapter, uint256 maturity, uint256 principalAmount, address to)
        external
        nonReentrant
        returns (uint256)
    {
        ITranche tranche =
            TrancheAddress.computeAddress(adapter, maturity, TRANCHE_CREATION_HASH, address(trancheFactory));
        return tranche.redeem({from: msg.sender, to: to, principalAmount: principalAmount});
    }

    /// @notice Approve this contract to spend `principalAmount` of PT.
    /// @dev If caller want to withdraw ETH, specify `to` as the this contract's address and use `unwrapWETH9` with Multicall.
    /// @inheritdoc ITrancheRouter
    function withdraw(address adapter, uint256 maturity, uint256 underlyingAmount, address to)
        external
        nonReentrant
        returns (uint256)
    {
        ITranche tranche =
            TrancheAddress.computeAddress(adapter, maturity, TRANCHE_CREATION_HASH, address(trancheFactory));
        return tranche.withdraw({from: msg.sender, to: to, underlyingAmount: underlyingAmount});
    }
}
