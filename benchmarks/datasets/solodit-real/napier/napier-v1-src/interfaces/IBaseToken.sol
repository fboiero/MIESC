// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.0;

import {IERC20} from "@openzeppelin/contracts@4.9.3/token/ERC20/IERC20.sol";

/// @title IBaseToken
/// @notice token interface for Principal and Yield tokens
interface IBaseToken is IERC20 {
    /// @notice maturity date of the token
    function maturity() external view returns (uint256);

    /// @notice target address of the token
    function target() external view returns (address);
}
