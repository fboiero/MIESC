// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.19;

// interfaces
import {IERC20} from "@openzeppelin/contracts@4.9.3/token/ERC20/IERC20.sol";
import {IWETH9} from "../../interfaces/IWETH9.sol";
import {ICToken} from "./interfaces/ICToken.sol";
// libs
import {SafeERC20} from "@openzeppelin/contracts@4.9.3/token/ERC20/utils/SafeERC20.sol";
import {FixedPointMathLib} from "src/utils/FixedPointMathLib.sol";
import {BaseAdapter} from "../../BaseAdapter.sol";

abstract contract CompoundV2BaseAdapter is BaseAdapter {
    using SafeERC20 for IWETH9;
    using SafeERC20 for IERC20;
    using FixedPointMathLib for uint256;

    //errors
    error MintFailed();
    error TransferFailed();
    error RedeemFailed();
    error SendETHFailed();

    constructor(address _underlying, address _target) BaseAdapter(_underlying, _target) {}

    /// @notice Recover ETH from contract
    /// @dev However ETH is swept at the time of `prefundedRedeem` call
    /// Warning: Can be front-run
    /// @param to recipient of ETH (zero-check is NOT performed)
    function recoverETH(address to) external onlyOwner {
        uint256 amount = address(this).balance;
        (bool success, ) = to.call{value: amount}("");
        if (!success) {
            revert SendETHFailed();
        }
    }

    function viewExchangeRate(ICToken cToken) internal view returns (uint256) {
        // https://github.com/transmissions11/libcompound/blob/5ce5b13e4defcc2bc3e73927edb9bf309c227d63/src/LibCompound.sol#L17-L40C6
        // get exchangeRateCurrent from compound without mutating state.

        uint256 accrualBlockNumberPrior = cToken.accrualBlockNumber();

        if (accrualBlockNumberPrior == block.number) return cToken.exchangeRateStored();

        uint256 totalCash = cToken.getCash();
        uint256 borrowsPrior = cToken.totalBorrows();
        uint256 reservesPrior = cToken.totalReserves();

        uint256 borrowRateMantissa = cToken.borrowRatePerBlock();

        require(borrowRateMantissa <= 0.0005e16, "RATE_TOO_HIGH"); // Same as borrowRateMaxMantissa in CTokenInterfaces.sol

        uint256 interestAccumulated = (borrowRateMantissa * (block.number - accrualBlockNumberPrior)).mulWadDown(
            borrowsPrior
        );

        uint256 totalReserves = cToken.reserveFactorMantissa().mulWadDown(interestAccumulated) + reservesPrior;
        uint256 totalBorrows = interestAccumulated + borrowsPrior;
        uint256 totalSupply = cToken.totalSupply();

        // Reverts if totalSupply == 0
        return (totalCash + totalBorrows - totalReserves).divWadDown(totalSupply);
    }

    function claimRewards() public virtual {}
}
