// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.19;

// interfaces
import {IERC20} from "@openzeppelin/contracts@4.9.3/token/ERC20/IERC20.sol";
import {IBaseAdapter} from "./interfaces/IBaseAdapter.sol";
// libs
import {SafeERC20} from "@openzeppelin/contracts@4.9.3/token/ERC20/utils/SafeERC20.sol";
import {Ownable2Step} from "@openzeppelin/contracts@4.9.3/access/Ownable2Step.sol";

/// @notice abstract contract for adapters
/// @author 0xbakuchi
/// @dev adapters are used to deposit underlying tokens into a yield source and redeem them.
/// adapters are also used to fetch the current scale of the yield-bearing asset.
abstract contract BaseAdapter is Ownable2Step, IBaseAdapter {
    using SafeERC20 for IERC20;

    /// @inheritdoc IBaseAdapter
    address public immutable override underlying;
    /// @inheritdoc IBaseAdapter
    address public immutable override target;

    constructor(address _underlying, address _target) {
        underlying = _underlying;
        target = _target;
    }
}
