// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { Storage } from "./Storage.sol";

abstract contract ReentrancyGuard {

  bytes32 private constant _INITIAL_VALUE = bytes32(0);
  bytes32 private constant _NOT_ENTERED = bytes32(uint256(1));
  bytes32 private constant _ENTERED = bytes32(uint256(2));

  /// @dev keccak256("org.sequence.module.reentrancyguard.status")
  bytes32 private constant STATUS_KEY = bytes32(0xfc6e07e3992c7c3694a921dc9e412b6cfe475380556756a19805a9e3ddfe2fde);

  /// @notice Error thrown when a reentrant call is detected
  error ReentrantCall();

  /// @notice Prevents a contract from calling itself, directly or indirectly
  modifier nonReentrant() {
    // On the first call to nonReentrant
    // _status will be _NOT_ENTERED or _INITIAL_VALUE
    if (Storage.readBytes32(STATUS_KEY) == _ENTERED) {
      revert ReentrantCall();
    }

    // Any calls to nonReentrant after this point will fail
    Storage.writeBytes32(STATUS_KEY, _ENTERED);

    _;

    // By storing the original value once again, a refund is triggered (see
    // https://eips.ethereum.org/EIPS/eip-2200)
    // Notice that because constructors are not available
    // we always start with _INITIAL_VALUE, not _NOT_ENTERED
    Storage.writeBytes32(STATUS_KEY, _NOT_ENTERED);
  }

}
