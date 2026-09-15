// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.10;

library Errors {
    // Approx
    error ApproxFail();
    error ApproxBinarySearchInputInvalid();

    // Quoter
    error ApproxFailWithHint(bytes hint);

    // Factory
    error FactoryPoolAlreadyExists();
    error FactoryUnderlyingMismatch();
    error FactoryMaturityMismatch();

    // Pool
    error PoolOnlyOwner();
    error PoolInvalidParamName();
    error PoolUnauthorizedCallback();
    error PoolExpired();
    error PoolInvariantViolated();
    error PoolZeroAmountsInput();
    error PoolZeroAmountsOutput();
    error PoolZeroLnImpliedRate();
    error PoolInsufficientBaseLptForTrade();
    error PoolInsufficientBaseLptReceived();
    error PoolInsufficientUnderlyingReceived();
    error PoolExchangeRateBelowOne(int256 exchangeRate);
    error PoolProportionMustNotEqualOne();
    error PoolRateScalarZero();
    error PoolProportionTooHigh();

    // Router
    error RouterInsufficientWETH();
    error RouterInconsistentWETHPayment();
    error RouterPoolNotFound();
    error RouterTransactionTooOld();
    error RouterInsufficientLpOut();
    error RouterInsufficientTokenBalance();
    error RouterInsufficientUnderlyingOut();
    error RouterExceededLimitUnderlyingIn();
    error RouterInsufficientUnderlyingRepay();
    error RouterInsufficientPtRepay();
    error RouterCallbackNotNapierPool();
    error RouterNonSituationSwapUnderlyingForYt();

    // Generic
    error FailedToSendEther();
    error NotWETH();

    // Config
    error LnFeeRateRootTooHigh();
    error ProtocolFeePercentTooHigh();
    error InitialAnchorTooLow();
}
