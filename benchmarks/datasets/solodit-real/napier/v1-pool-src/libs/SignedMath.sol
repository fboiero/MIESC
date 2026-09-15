// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.10;

import {SafeCast} from "@openzeppelin/contracts@4.9.3/utils/math/SafeCast.sol";

library SignedMath {
    int256 internal constant WAD = 1e18; // The scalar of ETH and most ERC20s.

    function mulDivDown(int256 x, int256 y, int256 z) internal pure returns (int256) {
        int256 xy = x * y;
        unchecked {
            return xy / z;
        }
    }

    function subNoNeg(int256 a, int256 b) internal pure returns (int256) {
        require(a >= b, "negative");
        return a - b; // no unchecked since if b is very negative, a - b might overflow
    }

    function mulWadDown(int256 a, int256 b) internal pure returns (int256) {
        return mulDivDown(a, b, WAD);
    }

    function divWadDown(int256 a, int256 b) internal pure returns (int256) {
        return mulDivDown(a, WAD, b);
    }

    function neg(int256 x) internal pure returns (int256) {
        return x * (-1);
    }

    function neg(uint256 x) internal pure returns (int256) {
        return SafeCast.toInt256(x) * (-1);
    }
}
