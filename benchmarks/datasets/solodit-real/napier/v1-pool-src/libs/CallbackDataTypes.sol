// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.10;

import {IERC20} from "@openzeppelin/contracts@4.9.3/token/ERC20/IERC20.sol";
import {ITranche} from "@napier/napier-v1/src/interfaces/ITranche.sol";

enum CallbackType {
    SwapPtForUnderlying,
    SwapUnderlyingForPt,
    SwapYtForUnderlying,
    SwapUnderlyingForYt,
    AddLiquidityPts,
    AddLiquidityOnePt,
    AddLiquidityOneUnderlying
}

library CallbackDataTypes {
    function getCallbackType(bytes calldata data) internal pure returns (CallbackType callbackType) {
        // Read the first 32 bytes of the calldata
        assembly {
            callbackType := calldataload(data.offset)
        }
    }

    struct AddLiquidityData {
        address payer;
        address underlying;
        address basePool;
    }

    struct SwapPtForUnderlyingData {
        address payer;
        IERC20 pt;
    }

    struct SwapUnderlyingForPtData {
        address payer;
        uint256 underlyingInMax;
    }

    struct SwapYtForUnderlyingData {
        address payer;
        ITranche pt;
        uint256 ytIn;
        address recipient;
        uint256 underlyingOutMin;
    }

    struct SwapUnderlyingForYtData {
        address payer;
        ITranche pt;
        IERC20 yt;
        address recipient;
        uint256 underlyingDeposit;
        uint256 maxUnderlyingPull;
    }
}
