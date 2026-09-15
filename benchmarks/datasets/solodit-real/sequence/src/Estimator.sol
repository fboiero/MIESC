// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import { Stage2Module } from "./Stage2Module.sol";

import { Payload } from "./modules/Payload.sol";
import { IDelegatedExtension } from "./modules/interfaces/IDelegatedExtension.sol";
import { LibOptim } from "./utils/LibOptim.sol";

/// @title Estimator
/// @author William Hua
/// @notice Helper for estimating the gas used for payload validation and execution
contract Estimator is Stage2Module {

  constructor(
    address _entryPoint
  ) Stage2Module(_entryPoint) { }

  function _isValidImage(
    bytes32 _imageHash
  ) internal view virtual override returns (bool) {
    super._isValidImage(_imageHash);
    return true;
  }

  /// @notice Estimate the gas used for payload validation and execution
  /// @param _payload The payload to estimate the gas used for
  /// @param _signature The signature to validate the payload with
  /// @return gasUsed The gas used for payload validation and execution
  function estimate(
    bytes calldata _payload,
    bytes calldata _signature
  ) external payable virtual nonReentrant returns (uint256 gasUsed) {
    uint256 startingGas = gasleft();
    Payload.Decoded memory decoded = Payload.fromPackedCalls(_payload);

    _consumeNonce(decoded.space, readNonce(decoded.space));
    (bool isValid, bytes32 opHash) = signatureValidation(decoded, _signature);

    if (!isValid) {
      revert InvalidSignature(decoded, _signature);
    }

    _estimate(startingGas, opHash, decoded);

    return startingGas - gasleft();
  }

  function _estimate(uint256 _startingGas, bytes32 _opHash, Payload.Decoded memory _decoded) private {
    bool errorFlag = false;

    uint256 numCalls = _decoded.calls.length;
    for (uint256 i = 0; i < numCalls; i++) {
      Payload.Call memory call = _decoded.calls[i];

      // Skip onlyFallback calls if no error occurred
      if (call.onlyFallback && !errorFlag) {
        emit CallSkipped(_opHash, i);
        continue;
      }

      // Reset the error flag
      // onlyFallback calls only apply when the immediately preceding transaction fails
      errorFlag = false;

      uint256 gasLimit = call.gasLimit;
      if (gasLimit != 0 && gasleft() < gasLimit) {
        revert NotEnoughGas(_decoded, i, gasleft());
      }

      bool success;
      if (call.delegateCall) {
        (success) = LibOptim.delegatecall(
          call.to,
          gasLimit == 0 ? gasleft() : gasLimit,
          abi.encodeWithSelector(
            IDelegatedExtension.handleSequenceDelegateCall.selector,
            _opHash,
            _startingGas,
            i,
            numCalls,
            _decoded.space,
            call.data
          )
        );
      } else {
        (success) = LibOptim.call(call.to, call.value, gasLimit == 0 ? gasleft() : gasLimit, call.data);
      }

      if (!success) {
        if (call.behaviorOnError == Payload.BEHAVIOR_IGNORE_ERROR) {
          errorFlag = true;
          emit CallFailed(_opHash, i, LibOptim.returnData());
          continue;
        }

        if (call.behaviorOnError == Payload.BEHAVIOR_REVERT_ON_ERROR) {
          revert Reverted(_decoded, i, LibOptim.returnData());
        }

        if (call.behaviorOnError == Payload.BEHAVIOR_ABORT_ON_ERROR) {
          emit CallAborted(_opHash, i, LibOptim.returnData());
          break;
        }
      }

      emit CallSucceeded(_opHash, i);
    }
  }

}
