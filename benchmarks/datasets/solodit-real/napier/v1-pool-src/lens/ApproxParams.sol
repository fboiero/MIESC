// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.10;

// Taken from: Pendle finance v2

/// @notice Parameters for controlling the approximation process
/// @dev The approximation process is a binary search algorithm that finds the value that satisfies the provided function `f`.
/// By default, NapierPool defines swap formula in terms of Principal token (Base Pool LP token). To swap a given amount of Underlying token,
/// it's necessary to run an approximation algorithm to find the corresponding amount of Principal token to swap in/out
/// because computing inverse of the swap function is very hard.
/// The approximation algorithm will run as follows:
/// Let f(x) be the function that calculates difference between the desired value and the computed value for a given x (the amount of Base pool LP token to swap in/out)
/// The algorithm will find the value x that satisfies f(x) ~= ε, where ε is the relative error tolerance.
/// for a given range [a, b],
/// ```
///     mid = (a + b) / 2
///     error_mid = f(mid)
///     if error_mid <= eps
///         return mid
///     if error_mid > 0
///         a = mid
///     else
///         b = mid
/// ```
/// The algorithm will run for `maxIteration` times, or until the relative error tolerance `eps` is satisfied.
/// @param guessMin The lower bound of the guess range
/// @param guessMax The upper bound of the guess range
/// @param maxIteration The maximum number of iterations to run the approximation algorithm
/// @param eps The maximum relative error tolerance (in 18 decimals) between the desired value and the computed value. 0.1% = 1e15 (1e18/1000)
struct ApproxParams {
    uint256 guessMin;
    uint256 guessMax;
    uint256 maxIteration;
    uint256 eps;
}
