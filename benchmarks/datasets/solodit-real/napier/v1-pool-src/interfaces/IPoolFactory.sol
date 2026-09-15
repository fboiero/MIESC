// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.0;

interface IPoolFactory {
    event Deployed(address indexed basePool, address indexed underlying, address indexed pool);
    event AuthorizedCallbackReceiver(address indexed callback);
    event RevokedCallbackReceiver(address indexed callback);

    struct PoolAssets {
        address basePool;
        address underlying;
        address[3] principalTokens;
    }

    struct PoolConfig {
        int256 initialAnchor;
        uint256 scalarRoot;
        uint80 lnFeeRateRoot;
        uint8 protocolFeePercent;
        address feeRecipient;
    }

    struct InitArgs {
        PoolAssets assets;
        PoolConfig configs;
    }

    /// @notice Deploy a new NapierPool contract.
    /// @dev Only the factory owner can call this function.
    /// @param basePool Base pool contract
    /// @param underlying underlying asset
    function deploy(address basePool, address underlying, PoolConfig calldata poolConfig) external returns (address);

    /// @notice Authorize swap callback
    /// @dev Only the factory owner can call this function.
    /// @param callback Callback receiver
    function authorizeCallbackReceiver(address callback) external;

    /// @notice Revoke swap callback authorization
    /// @dev Only the factory owner can call this function.
    /// @param callback Callback receiver
    function revokeCallbackReceiver(address callback) external;

    function isCallbackReceiverAuthorized(address callback) external view returns (bool);

    /// @notice calculate the address of a tranche with CREATE2 using the adapter and maturity as salt
    function poolFor(address basePool, address underlying) external view returns (address);

    /// @param pool a pool address
    /// @dev returns the pool parameters used to deploy the pool
    /// this function doesn't revert even if the pool doesn't exist. It returns the default values in that case.
    /// @return the pool parameters
    function getPoolAssets(address pool) external view returns (PoolAssets memory);

    /// @notice Owner of this contract
    function owner() external view returns (address);

    function args() external view returns (InitArgs memory);

    function POOL_CREATION_HASH() external view returns (bytes32);
}
