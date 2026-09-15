// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.19;

// interfaces
import {IPoolFactory} from "./interfaces/IPoolFactory.sol";
import {CurveTricryptoOptimizedWETH} from "./interfaces/external/CurveTricryptoOptimizedWETH.sol";
import {CurveTricryptoFactory} from "./interfaces/external/CurveTricryptoFactory.sol";
import {ITranche} from "@napier/napier-v1/src/interfaces/ITranche.sol";
// libs
import {NapierPool} from "./NapierPool.sol";
import {PoolAddress} from "./libs/PoolAddress.sol";
import {Create2PoolLib} from "./libs/Create2PoolLib.sol";
import {Errors} from "./libs/Errors.sol";
import {MAX_LN_FEE_RATE_ROOT, MAX_PROTOCOL_FEE_PERCENT, MIN_INITIAL_ANCHOR} from "./libs/Constants.sol";
// inherits
import {Ownable2Step, Ownable} from "@openzeppelin/contracts@4.9.3/access/Ownable2Step.sol";

contract PoolFactory is IPoolFactory, Ownable2Step {
    /// @notice Keccak256 hash of Pool creation code
    /// @dev Used to compute the CREATE2 address
    bytes32 public immutable POOL_CREATION_HASH = keccak256(type(NapierPool).creationCode);

    /// @notice Curve v2 Tricrypto Factory (aka tricrypto-ng)
    /// @dev Note: Curve pool used as BasePool for NapierPool MUST be deployed by this contract.
    CurveTricryptoFactory public immutable curveTricryptoFactory;

    /// @notice Temporary variable
    InitArgs private _tempArgs;

    /// @notice Mapping of NapierPool to PoolAssets
    mapping(address => PoolAssets) internal _pools;

    /// @notice Authorized callback receivers for pool flashswap
    mapping(address => bool) internal _authorizedCallbackReceivers;

    /// @dev Note: params can be zero-address
    /// @param _curveTricryptoFactory Immutable Curve Tricrypto Factory
    /// @param _owner Owner of this factory
    constructor(address _curveTricryptoFactory, address _owner) {
        curveTricryptoFactory = CurveTricryptoFactory(_curveTricryptoFactory);

        _transferOwnership(_owner);
    }

    /// @notice Deploys a new NapierPool contract. Only callable by owner
    /// @dev BasePool assets must be Napier Principal Token.
    /// @param basePool Curve Tricrypto pool address deployed by `CurveTricryptoFactory`.
    /// @param underlying Underlying asset. Must be the same as the underlying asset of the basePool.
    /// @param poolConfig NapierPool configuration. fee and AMM configs.
    function deploy(address basePool, address underlying, PoolConfig calldata poolConfig)
        external
        override
        onlyOwner
        returns (address)
    {
        if (poolConfig.lnFeeRateRoot > MAX_LN_FEE_RATE_ROOT) revert Errors.LnFeeRateRootTooHigh();
        if (poolConfig.protocolFeePercent > MAX_PROTOCOL_FEE_PERCENT) revert Errors.ProtocolFeePercentTooHigh();
        if (poolConfig.initialAnchor < MIN_INITIAL_ANCHOR) revert Errors.InitialAnchorTooLow();

        address computedAddr = poolFor(basePool, underlying);
        if (_pools[computedAddr].underlying != address(0)) revert Errors.FactoryPoolAlreadyExists();

        address[3] memory pts = curveTricryptoFactory.get_coins(basePool);

        // Checklist:
        // 1. Base pool must be deployed by `CurveTricryptoFactory`.
        // 2. Underlying asset must be the same as the underlying asset of the principal tokens.
        // 3. Maturity of the principal tokens must be the same.
        uint256 maturity = ITranche(pts[0]).maturity();
        if (maturity != ITranche(pts[1]).maturity() || maturity != ITranche(pts[2]).maturity()) {
            revert Errors.FactoryMaturityMismatch();
        }
        if (
            ITranche(pts[0]).underlying() != underlying || ITranche(pts[1]).underlying() != underlying
                || ITranche(pts[2]).underlying() != underlying
        ) revert Errors.FactoryUnderlyingMismatch();

        // Set temporary variable
        _tempArgs = InitArgs({
            assets: PoolAssets({basePool: basePool, underlying: underlying, principalTokens: pts}),
            configs: poolConfig
        });
        // Deploy pool and temporary variable is read by callback from the pool
        address pool = address(Create2PoolLib.deploy(basePool, underlying));
        _pools[pool] = _tempArgs.assets;

        // Reset temporary variable to 0-value
        delete _tempArgs;

        emit Deployed(basePool, underlying, pool);
        return pool;
    }

    /////////////////////////////////////////////////////////////////////
    // View methods
    /////////////////////////////////////////////////////////////////////

    /// @notice Returns the pool parameters used to deploy the pool
    /// @dev This would be used while the pool is deploying
    /// @return The pool parameters used to initialize the pool
    function args() external view override returns (InitArgs memory) {
        return _tempArgs;
    }

    /// @notice Calculate the address of a pool with CREATE2
    /// @param basePool Curve Tricrypto pool address
    /// @param underlying Underlying asset (e.g. DAI, WETH...)
    function poolFor(address basePool, address underlying) public view override returns (address) {
        return address(PoolAddress.computeAddress(basePool, underlying, POOL_CREATION_HASH, address(this)));
    }

    /// @dev Returns the pool parameters used to deploy the pool
    /// @dev This function doesn't revert even if the pool doesn't exist. It returns the default values in that case.
    /// @param pool A pool address
    /// @return The pool parameters
    function getPoolAssets(address pool) external view override returns (PoolAssets memory) {
        return _pools[pool];
    }

    /// @notice Returns the owner of this contract
    /// @notice Note: Owner is also the owner of the pools deployed by this factory
    function owner() public view override(Ownable, IPoolFactory) returns (address) {
        return Ownable.owner();
    }

    /// @notice Returns true if the callback is authorized to receive callbacks from pools
    /// @param callback An address to check
    function isCallbackReceiverAuthorized(address callback) external view override returns (bool) {
        return _authorizedCallbackReceivers[callback];
    }

    ///////////////////////////////////////////////////////////////////////////
    // Mutative methods
    ///////////////////////////////////////////////////////////////////////////

    function authorizeCallbackReceiver(address callback) external override onlyOwner {
        _authorizedCallbackReceivers[callback] = true;
        emit AuthorizedCallbackReceiver(callback);
    }

    function revokeCallbackReceiver(address callback) external override onlyOwner {
        _authorizedCallbackReceivers[callback] = false;
        emit RevokedCallbackReceiver(callback);
    }
}
