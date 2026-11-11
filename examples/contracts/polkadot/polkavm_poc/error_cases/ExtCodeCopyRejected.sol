// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Difference class (A): resolc REJECTS EXTCODECOPY at compile time
// ("LLVM IR generator: The EXTCODECOPY instruction is not supported", exit 1).
// This file is EXPECTED TO FAIL compilation with resolc. The `polkavm_resolc`
// adapter runs resolc and surfaces that rejection as one authoritative
// `polkavm-unsupported-opcode` finding (a PolkaVM deployability blocker).
contract ExtCodeCopyRejected {
    function copy(address a) external view returns (bytes32 h) {
        assembly {
            extcodecopy(a, 0, 0, 32)
            h := mload(0)
        }
    }
}
