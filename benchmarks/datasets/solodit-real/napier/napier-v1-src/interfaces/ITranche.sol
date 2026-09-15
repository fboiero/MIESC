// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.0;

import {IERC5095} from "./IERC5095.sol";

/// @notice Tranche interface
/// @dev Tranche divides a yield-bearing token into two tokens: Principal and Yield tokens
///      Unspecific types: Simply avoiding dependencies on other interfaces from our interfaces
interface ITranche is IERC5095 {
    /* ==================== ERRORS ===================== */

    error TimestampBeforeMaturity();
    error TimestampAfterMaturity();
    error ProtectedToken();
    error Unauthorized();
    error OnlyYT();
    error ReentrancyGuarded();
    error ZeroAddress();
    error NoAccruedYield();

    /* ==================== EVENTS ===================== */

    /// @param adapter the address of the adapter
    /// @param maturity timestamp of maturity (seconds since Unix epoch)
    /// @param tilt % of underlying principal reserved for YTs
    /// @param issuanceFee fee for issuing PT and YT
    event SeriesCreated(address indexed adapter, uint256 indexed maturity, uint256 tilt, uint256 issuanceFee);

    /// @param from the sender of the underlying token
    /// @param to the recipient of the PT and YT
    /// @param underlyingUsed the amount of underlying token used to issue PT and YT
    /// @param sharesUsed the amount of target token used to issue PT and YT (before deducting issuance fee)
    event Issue(address indexed from, address indexed to, uint256 underlyingUsed, uint256 sharesUsed);

    /// @param owner the address of the owner of the PT and YT (address that called collect())
    /// @param shares the amount of Target token collected
    event Collect(address indexed owner, uint256 shares);

    /// @param owner the address of the owner of the PT and YT
    /// @param to the recipient of the underlying token redeemed
    /// @param underlyingRedeemed the amount of underlying token redeemed
    event RedeemWithYT(address indexed owner, address indexed to, uint256 underlyingRedeemed);

    /* ==================== STRUCTS ===================== */

    /// @notice Series is a struct that contains all the information about a series.
    /// @param underlying the address of the underlying token
    /// @param target the address of the target token
    /// @param yt the address of the Yield Token
    /// @param adapter the address of the adapter
    /// @param mscale scale value at maturity
    /// @param maxscale max scale value from this series' lifetime
    /// @param tilt % of underlying principal reserved for YTs
    /// @param issuanceFee fee for issuing PT and YT
    /// @param maturity timestamp of maturity (seconds since Unix epoch)
    struct Series {
        address underlying;
        address target;
        address yt;
        address adapter;
        uint256 mscale;
        uint256 maxscale;
        uint64 tilt;
        uint64 issuanceFee;
        uint64 maturity;
    }

    /// @notice GlobalScales is a struct that contains scale values that are used in multiple functions throughout the Tranche contract.
    /// @param mscale scale value at maturity. before maturity and settlement, this value is 0.
    /// @param maxscale max scale value from this series' lifetime.
    struct GlobalScales {
        uint128 mscale;
        uint128 maxscale;
    }

    /* ================== MUTATIVE METHODS =================== */

    /// @notice deposit an `underlyingAmount` of underlying token into the yield source, receiving PT and YT.
    ///         amount of PT and YT issued are the same.
    /// @param   to the address to receive PT and YT
    /// @param   underlyingAmount the amount of underlying token to deposit
    /// @return  principalAmount the amount of PT and YT issued
    function issue(address to, uint256 underlyingAmount) external returns (uint256 principalAmount);

    /// @notice redeem an `principalAmount` of PT and YT for underlying token.
    /// @param from the address to burn PT and YT from
    /// @param to the address to receive underlying token
    /// @param pyAmount the amount of PT and YT to redeem
    /// @return underlyingAmount the amount of underlying token redeemed
    function redeemWithYT(address from, address to, uint256 pyAmount) external returns (uint256 underlyingAmount);

    /// @notice collect interest for `msg.sender` and transfer accrued interest to `msg.sender`
    ///         NOTE: if the maturity has passed, YT will be burned and some of the principal will be transferred to `msg.sender` based on the `tilt` parameter.
    /// @dev anyone can call this function to collect interest for themselves
    /// @return collected collected interest in Underlying token
    function collect() external returns (uint256 collected);

    /* ================== PERMISSIONED METHODS =================== */

    /// @notice collect interest from the yield source and distribute it
    ///         every YT transfer, this function is triggered by the Yield Token contract.
    ///         only the Yield Token contract can call this function.
    ///         NOTE: YT is not burned in this function even if the maturity has passed.
    /// @param from address to transfer the Yield Token from. i.e. the user who collects the interest.
    /// @param to address to transfer the Yield Token to (MUST NOT be zero address, CAN be the same as `from`)
    /// @param value amount of Yield Token transferred to `to` (CAN be 0)
    function updateUnclaimedYield(address from, address to, uint256 value) external;

    /* ================== VIEW METHODS =================== */

    /// @notice get the address of Yield Token associated with this Tranche.
    function yieldToken() external view returns (address);

    /// @notice get Series struct
    function getSeries() external view returns (Series memory);

    /// @notice get an accrued yield that can be claimed by `account` (in unis of Target token)
    /// @dev this is reset to 0 when `account` claims the yield.
    /// @param account the address to check
    /// @return accruedInTarget
    function unclaimedYields(address account) external view returns (uint256 accruedInTarget);

    /// @notice get an accrued yield that can be claimed by `account` (in unis of Underlying token)
    /// @param account the address to check
    /// @return accruedInUnderlying accrued yield in underlying token
    function previewCollect(address account) external view returns (uint256 accruedInUnderlying);
}
