// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Stage2Module } from "./Stage2Module.sol";
import { Calls } from "./modules/Calls.sol";

import { ERC4337v07 } from "./modules/ERC4337v07.sol";
import { Hooks } from "./modules/Hooks.sol";
import { Stage1Auth } from "./modules/auth/Stage1Auth.sol";
import { IAuth } from "./modules/interfaces/IAuth.sol";

/// @title Stage1Module
/// @author Agustin Aguilar
/// @notice The initial stage of the wallet
contract Stage1Module is Calls, Stage1Auth, Hooks, ERC4337v07 {

  constructor(
    address _factory,
    address _entryPoint
  ) Stage1Auth(_factory, address(new Stage2Module(_entryPoint))) ERC4337v07(_entryPoint) { }

  /// @inheritdoc IAuth
  function _isValidImage(
    bytes32 _imageHash
  ) internal view virtual override(IAuth, Stage1Auth) returns (bool) {
    return super._isValidImage(_imageHash);
  }

}
