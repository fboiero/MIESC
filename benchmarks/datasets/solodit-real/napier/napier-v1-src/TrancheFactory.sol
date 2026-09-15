// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.19;

// interfaces
import {ITrancheFactory} from "./interfaces/ITrancheFactory.sol";
import {ITranche} from "./interfaces/ITranche.sol";
import {IBaseAdapter} from "./interfaces/IBaseAdapter.sol";
// libs
import {SafeCast} from "@openzeppelin/contracts@4.9.3/utils/math/SafeCast.sol";
import {Create2} from "@openzeppelin/contracts@4.9.3/utils/Create2.sol";
import {MAX_BPS} from "./Constants.sol";
import {Create2TrancheLib} from "./Create2TrancheLib.sol";

import {Tranche} from "./Tranche.sol";
import {YieldToken} from "./YieldToken.sol";

contract TrancheFactory is ITrancheFactory {
    using SafeCast for uint256;

    /// @notice 5% Maximum issuance fee percentage limit in basis point  (10000 = 100%)
    uint256 internal constant MAX_ISSUANCE_FEE_BPS = 500; // 5%

    /// @dev Keccak256 hash of the Tranche contract creation code
    /// @dev Used to compute the CREATE2 address of the Tranche contract
    /// `immutable` is used instead of `constant` for a call to `keccak256()`
    bytes32 public immutable TRANCHE_CREATION_HASH = keccak256(type(Tranche).creationCode);

    /// @notice management address
    address public immutable management;

    /// @notice Temporary storage used exclusively during the Tranche contract deployment by the Factory.
    /// @dev These variables are utilized to initialize the Tranche contract and must be reset post-deployment.
    TrancheInitArgs internal _tempArgs;

    /// @notice adapter => maturity => principal token
    mapping(address => mapping(uint256 => address)) public tranches;

    constructor(address _management) {
        management = _management;
    }

    /// @inheritdoc ITrancheFactory
    /// @dev revert if caller is not authorized.
    ///      revert if tranche instance already exists.
    ///      revert if maturity is in the past.
    ///      revert if tilt is too high.
    ///      revert if issueancaeFee is too high.
    ///
    /// Internally types shorter than 32bytes are used to save gas. but uint256 is used in function parameters
    /// because types shorter than 32bytes have some pitfalls.
    /// @param adapter the adapter to use for this Tranche
    /// @param maturity uint32 for `maturity` is enough for next 100 years
    /// @param tilt can be used to adjust the interest rate of the principal token. can be zero. uint16 internally
    /// @param issuanceFee the issueance fee of this series (in basis points 10_000=100%). can be zero. uint16 internally
    function deployTranche(
        address adapter,
        uint256 maturity,
        uint256 tilt,
        uint256 issuanceFee
    ) external returns (address) {
        if (msg.sender != management) revert OnlyManagement();
        if (adapter == address(0)) revert ZeroAddress();
        if (tranches[adapter][maturity] != address(0)) revert TrancheAlreadyExists();
        if (maturity <= block.timestamp) revert MaturityInvalid();
        if (tilt >= MAX_BPS) revert TiltTooHigh(); // tilt: [0, 100%) exclusive
        if (issuanceFee > MAX_ISSUANCE_FEE_BPS) revert IssueanceFeeTooHigh(); // issuanceFee: [0, 5%] inclusive

        // NOTE: computed Tranche address is used before deployed. it is ok if the YT doesn't call the tranche's methods in its constructor
        address computedAddr = trancheFor(adapter, maturity);
        YieldToken yt = new YieldToken(
            computedAddr,
            IBaseAdapter(adapter).underlying(),
            IBaseAdapter(adapter).target(),
            maturity
        );

        // store temporary variables
        _tempArgs.adapter = adapter;
        _tempArgs.maturity = maturity.toUint32();
        _tempArgs.tilt = tilt.toUint16();
        _tempArgs.issuanceFee = issuanceFee.toUint16();
        _tempArgs.yt = address(yt);

        // deploy PT with CREATE2 using adapter and maturity as salt
        // receive callback to initialize the tranche
        Tranche tranche = Create2TrancheLib.deploy(adapter, maturity);
        if (computedAddr != address(tranche)) revert TrancheAddressMismatch();

        // set back to zero-value for refund
        delete _tempArgs;

        // store the series
        tranches[adapter][maturity] = address(tranche);
        emit TrancheDeployed(maturity, address(tranche), address(yt));

        return address(tranche);
    }

    /// @inheritdoc ITrancheFactory
    /// @dev This pattern is used to deploy a contract deterministically with initialization arguments using CREATE2.
    /// Constructor arguments are fetched from a temporary storage through a callback in the constructor.
    function args() external view override returns (TrancheInitArgs memory) {
        return
            TrancheInitArgs({
                maturity: _tempArgs.maturity,
                adapter: _tempArgs.adapter,
                tilt: _tempArgs.tilt,
                issuanceFee: _tempArgs.issuanceFee,
                yt: _tempArgs.yt,
                management: management
            });
    }

    /// @inheritdoc ITrancheFactory
    function trancheFor(address adapter, uint256 maturity) public view returns (address tranche) {
        // Optimize salt computation
        // https://www.rareskills.io/post/gas-optimization#viewer-ed7oh
        // https://github.com/dragonfly-xyz/useful-solidity-patterns/tree/main/patterns/assembly-tricks-1#hash-two-words
        bytes32 salt;
        assembly {
            mstore(0x00, shr(96, shl(96, adapter))) // note: This is public function, so we should clean the upper 96 bits.
            mstore(0x20, maturity)
            salt := keccak256(0x00, 0x40)
        }
        tranche = Create2.computeAddress(salt, TRANCHE_CREATION_HASH, address(this));
    }
}
