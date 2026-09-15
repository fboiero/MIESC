// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.19;

import {IBaseToken} from "./interfaces/IBaseToken.sol";
import {DateTime} from "./utils/DateTime.sol";
import {ERC20Permit} from "@openzeppelin/contracts@4.9.3/token/ERC20/extensions/ERC20Permit.sol";

abstract contract BaseToken is ERC20Permit, IBaseToken {
    /// @inheritdoc IBaseToken
    function maturity() external view virtual returns (uint256);

    /// @inheritdoc IBaseToken
    function target() external view virtual returns (address);

    function _toDateString(uint256 _maturity) internal pure returns (string memory) {
        (string memory d, string memory m, string memory y) = DateTime.toDateString(_maturity);
        return string.concat(d, "-", m, "-", y);
    }
}
