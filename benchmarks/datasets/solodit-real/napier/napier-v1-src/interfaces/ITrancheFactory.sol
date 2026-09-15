// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.0;

/// @title ITrancheFactory
/// @notice interface for TrancheFactory
interface ITrancheFactory {
    error ZeroAddress();
    error TrancheAlreadyExists();
    error MaturityInvalid();
    error OnlyManagement();
    error TiltTooHigh();
    error IssueanceFeeTooHigh();
    error TrancheAddressMismatch();

    event TrancheDeployed(uint256 indexed maturity, address indexed principalToken, address indexed yieldToken);

    /// @notice init args for a tranche
    /// @param adapter address of the adapter
    /// @param maturity UNIX timestamp of maturity
    /// @param tilt percentage of underlying principal reserved for YTs
    /// @param issuanceFee fee for issuing PT and YT
    /// @param yt address of the Yield Token
    /// @param management management address of the deployed tranche
    struct TrancheInitArgs {
        address adapter; // 20 bytes
        uint32 maturity; // 4 bytes
        uint16 tilt; // 2 bytes
        uint16 issuanceFee; // 2 bytes (1th-slot)
        address yt; // 20 bytes (2nd-slot)
        address management; // 20 bytes (3rd-slot)
    }

    /// @notice deploy a new Tranche instance with the given maturity and adapter
    /// @dev only the management address can call this function
    /// @param adapter the adapter to use for this series
    /// @param maturity the maturity of this series (in seconds)
    /// @param tilt the tilt of this series (in basis points 10_000=100%)
    /// @param issuanceFee the issueance fee of this series (in basis points 10_000=100%)
    /// @return the address of the new tranche
    function deployTranche(
        address adapter,
        uint256 maturity,
        uint256 tilt,
        uint256 issuanceFee
    ) external returns (address);

    /// @notice calculate the address of a tranche with CREATE2 using the adapter and maturity as salt
    function trancheFor(address adapter, uint256 maturity) external view returns (address tranche);

    /// @notice return init args for a tranche
    function args() external view returns (TrancheInitArgs memory);

    function TRANCHE_CREATION_HASH() external view returns (bytes32);
}
