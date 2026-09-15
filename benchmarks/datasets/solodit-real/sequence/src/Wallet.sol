// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

/*
// Delegate Proxy in Huff
// @title Delegate Proxy
// @notice Implements a proxy using the contract's own address to store the delegate target.
//         Calls with calldata (with or without ETH value) are forwarded to the stored target.
//         Calls sending only ETH without calldata do nothing and return immediately without forwarding.
// @author Agusx1211
#define macro CONSTRUCTOR() = takes (0) returns (0) {
  0x41                   // [code + arg size] (code_size + 32)
  __codeoffset(MAIN)     // [code_start, code + arg size]
  returndatasize         // [0, code_start, code + arg size]
  codecopy               // []

  __codesize(MAIN)       // [code_size]
  dup1                   // [code_size, code_size]
  mload                  // [arg1, code_size]
  address                // [address, arg1, code_size]
  sstore                 // [code_size]

  returndatasize         // [0, code_size]
  return
}

#define macro MAIN() = takes(0) returns(0) {
  returndatasize     // [0]
  returndatasize     // [0, 0]
  calldatasize       // [cs, 0, 0]
  iszero             // [cs == 0, 0, 0]
  callvalue          // [cv, cs == 0, 0, 0]
  mul                // [cv * cs == 0, 0, 0]
  success            // [nr, cv * cs == 0, 0, 0]
  jumpi
    calldatasize     // [cds, 0, 0]
    returndatasize   // [0, cds, 0, 0]
    returndatasize   // [0, 0, cds, 0, 0]
    calldatacopy     // [0, 0]
    returndatasize   // [0, 0, 0]
    calldatasize     // [cds, 0, 0, 0]
    returndatasize   // [0, cds, 0, 0, 0]
    address          // [addr, 0, cds, 0, 0, 0]
    sload            // [imp, 0, cds, 0, 0, 0]
    gas              // [gas, imp, 0, cds, 0, 0, 0]
    delegatecall     // [suc, 0]
    returndatasize   // [rds, suc, 0]
    dup3             // [0, rds, suc, 0]
    dup1             // [0, 0, rds, suc, 0]
    returndatacopy   // [suc, 0]
    swap1            // [0, suc]
    returndatasize   // [rds, 0, suc]
    swap2            // [suc, 0, rds]
    success          // [nr, suc, 0, rds]
    jumpi
      revert
  success:
    return
}
*/

library Wallet {

  bytes internal constant creationCode =
    hex"6041600e3d396021805130553df33d3d36153402601f57363d3d373d363d30545af43d82803e903d91601f57fd5bf3";

}
