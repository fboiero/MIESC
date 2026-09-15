// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Storage } from "./Storage.sol";

/// @title Nonce
/// @author Agustin Aguilar
/// @notice Manages the nonce of the wallet
contract Nonce {

  /// @notice Emitted when the nonce is changed
  event NonceChange(uint256 _space, uint256 _newNonce);

  /// @notice Error thrown when the nonce is bad
  error BadNonce(uint256 _space, uint256 _provided, uint256 _current);

  /// @dev keccak256("org.arcadeum.module.calls.nonce")
  bytes32 private constant NONCE_KEY = bytes32(0x8d0bf1fd623d628c741362c1289948e57b3e2905218c676d3e69abee36d6ae2e);

  /// @notice Read the nonce
  /// @param _space The space
  /// @return nonce The nonce
  function readNonce(
    uint256 _space
  ) public view virtual returns (uint256) {
    return uint256(Storage.readBytes32Map(NONCE_KEY, bytes32(_space)));
  }

  function _writeNonce(uint256 _space, uint256 _nonce) internal {
    Storage.writeBytes32Map(NONCE_KEY, bytes32(_space), bytes32(_nonce));
  }

  function _consumeNonce(uint256 _space, uint256 _nonce) internal {
    uint256 currentNonce = readNonce(_space);
    if (currentNonce != _nonce) {
      revert BadNonce(_space, _nonce, currentNonce);
    }

    unchecked {
      uint256 newNonce = _nonce + 1;

      _writeNonce(_space, newNonce);
      emit NonceChange(_space, newNonce);
      return;
    }
  }

}
