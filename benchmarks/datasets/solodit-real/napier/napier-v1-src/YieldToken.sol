// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.19;

// interfaces
import {IERC20} from "@openzeppelin/contracts@4.9.3/token/ERC20/IERC20.sol";
import {IYieldToken} from "./interfaces/IYieldToken.sol";
import {IBaseToken} from "./interfaces/IBaseToken.sol";
import {ITranche} from "./interfaces/ITranche.sol";
// libs
import {SafeERC20Namer} from "./utils/SafeERC20Namer.sol";
// inheriting
import {ERC20Permit, ERC20} from "@openzeppelin/contracts@4.9.3/token/ERC20/extensions/ERC20Permit.sol";
import {BaseToken} from "./BaseToken.sol";

/// @title YieldToken
/// @notice YieldToken is a token that represents the future yield of a Target (yield-bearing asset).
///         It is minted when a user deposits into a Tranche and burned when the user redeems after maturity or when redeemed with PrincipalToken.
contract YieldToken is BaseToken, IYieldToken {
    uint8 private immutable uDecimals;

    address public immutable underlying;
    address public immutable override tranche;
    uint256 public immutable override(IBaseToken, BaseToken) maturity;
    address public immutable override(IBaseToken, BaseToken) target;

    modifier onlyTranche() {
        if (msg.sender != tranche) revert OnlyTranche();
        _;
    }

    /// @dev Assume YieldToken is deployed from a factory.
    /// The constructor is `payable` to remove msg.value check and reduce gas cost at deployment time.
    /// This is acceptable because the factory contract doesn't deploy Tranche with ETH.
    ///
    /// Cache Underlying token decimals in the constructor
    /// Deployer SHOULD ensure that zero check and validity check is performed before deployment.
    /// @param _tranche The address of the Tranche contract that mints this YieldToken
    /// @param _underlying Underlying token address (zero-check SHOULD be performed in the Tranche contract)
    /// @param _target Target token address  (zero-check SHOULD be performed in the Tranche contract)
    /// @param _maturity Maturity timestamp (SHOULD be checked in the Tranche contract)
    constructor(
        address _tranche,
        address _underlying,
        address _target,
        uint256 _maturity
    ) payable ERC20("Napier Yield Token", "eYT") ERC20Permit("Napier Yield Token") {
        underlying = _underlying;
        tranche = _tranche;
        maturity = _maturity;
        target = _target;
        uDecimals = ERC20(_underlying).decimals();
    }

    /* ================== MUTATIVE METHODS =================== */

    /// @inheritdoc IYieldToken
    function mint(address to, uint256 amount) external override onlyTranche {
        _mint(to, amount);
    }

    /// @inheritdoc IYieldToken
    function burn(address owner, uint256 amount) external override onlyTranche {
        _burn(owner, amount);
    }

    /// @inheritdoc IYieldToken
    function burnFrom(address owner, address spender, uint256 amount) external override onlyTranche {
        if (owner != spender) {
            _spendAllowance(owner, spender, amount);
        }
        _burn(owner, amount);
    }

    /// @inheritdoc ERC20
    /// @notice This function reverts if Tranche is paused.
    /// NOTE: This function is overridden to ensure that `msg.sender`'s and `to`'s unclaimed yields is updated.
    function transfer(address to, uint256 amount) public override(ERC20, IERC20) returns (bool) {
        ITranche(tranche).updateUnclaimedYield(msg.sender, to, amount);
        return super.transfer(to, amount);
    }

    /// @inheritdoc ERC20
    /// @notice This function reverts if Tranche is paused.
    /// NOTE: This function is overridden to ensure that `from`'s and `to`'s unclaimed yields is updated.
    ///       This is necessary to track the yield accrued by the user and to make YieldToken fungible.
    /// @dev  Every time a user transfers their YieldToken, we will update `from` and `to`'s unclaimed yield.
    ///       When someone transfers the YTs of `from` to `to`, The accrued yield at that time is stored for each account.
    ///       users can later claim their respective accrued yield with `ITranche#collect()`.
    function transferFrom(address from, address to, uint256 amount) public override(ERC20, IERC20) returns (bool) {
        ITranche(tranche).updateUnclaimedYield(from, to, amount);
        return super.transferFrom(from, to, amount);
    }

    /* ================== VIEW METHODS =================== */

    /* ================== METADATA =================== */

    /// @inheritdoc ERC20
    function name() public view override returns (string memory) {
        string memory tokenName = SafeERC20Namer.tokenName(target);
        return string.concat("Napier Yield Token ", tokenName, "@", _toDateString(maturity));
    }

    /// @inheritdoc ERC20
    function symbol() public view override returns (string memory) {
        string memory tokenSymbol = SafeERC20Namer.tokenSymbol(target);
        return string.concat("eY-", tokenSymbol, "@", _toDateString(maturity));
    }

    function decimals() public view override returns (uint8) {
        return uDecimals;
    }
}
