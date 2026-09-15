// SPDX-License-Identifier: GPL-3.0-only
pragma solidity ^0.8.0;

interface ICETHToken {
    ///@notice Send Ether to CEther to mint
    function mint() external payable;

    function exchangeRateStored() external returns (uint256);

    function exchangeRateCurrent() external returns (uint256);
}
