// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.0;

import {IBaseToken} from "./IBaseToken.sol";

interface IYieldToken is IBaseToken {
    error OnlyTranche();

    function tranche() external view returns (address);

    /// @notice mint yield token
    /// @dev only tranche can mint yield token
    /// @param to recipient of yield token
    /// @param amount amount of yield token to mint
    function mint(address to, uint256 amount) external;

    /// @notice burn yield token of owner
    /// @dev only tranche can burn yield token
    /// @param owner owner of yield token
    /// @param amount amount of yield token to burn
    function burn(address owner, uint256 amount) external;

    /// @notice spender burn yield token on behalf of owner
    /// @notice owner must approve spender prior to calling this function
    /// @dev only tranche can burn yield token
    /// @param owner owner of yield token
    /// @param spender address to burn yield token on behalf of owner
    /// @param amount amount of yield token to burn
    function burnFrom(address owner, address spender, uint256 amount) external;
}
