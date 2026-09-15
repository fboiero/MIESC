// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Wallet } from "../../Wallet.sol";
import { Implementation } from "../Implementation.sol";
import { Storage } from "../Storage.sol";
import { BaseAuth } from "./BaseAuth.sol";

/// @title Stage2Auth
/// @author Agustin Aguilar
/// @notice Stage 2 auth contract
contract Stage2Auth is BaseAuth, Implementation {

  /// @dev keccak256("org.arcadeum.module.auth.upgradable.image.hash")
  bytes32 internal constant IMAGE_HASH_KEY = bytes32(0xea7157fa25e3aa17d0ae2d5280fa4e24d421c61842aa85e45194e1145aa72bf8);

  /// @notice Emitted when the image hash is updated
  event ImageHashUpdated(bytes32 newImageHash);

  /// @notice Error thrown when the image hash is zero
  error ImageHashIsZero();

  /// @notice Get the image hash
  /// @return imageHash The image hash
  function imageHash() external view virtual returns (bytes32) {
    return Storage.readBytes32(IMAGE_HASH_KEY);
  }

  function _isValidImage(
    bytes32 _imageHash
  ) internal view virtual override returns (bool) {
    return _imageHash != bytes32(0) && _imageHash == Storage.readBytes32(IMAGE_HASH_KEY);
  }

  function _updateImageHash(
    bytes32 _imageHash
  ) internal virtual override {
    if (_imageHash == bytes32(0)) {
      revert ImageHashIsZero();
    }
    Storage.writeBytes32(IMAGE_HASH_KEY, _imageHash);
    emit ImageHashUpdated(_imageHash);
  }

}
