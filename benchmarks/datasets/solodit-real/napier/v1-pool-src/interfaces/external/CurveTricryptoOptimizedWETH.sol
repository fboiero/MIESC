// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// https://github.com/curvefi/tricrypto-ng/blob/0bc1191b6097c8854e4f09e385f6c2c79a5bb773/contracts/main/CurveTricryptoOptimizedWETH.vy

import {IERC20} from "@openzeppelin/contracts@4.9.3/token/ERC20/IERC20.sol";

interface CurveTricryptoOptimizedWETH is IERC20 {
    /// @notice Exchange using wrapped native token by default
    /// @param i Index value for the input coin
    /// @param j Index value for the output coin
    /// @param dx Amount of input coin being swapped in
    /// @param min_dy Minimum amount of output coin to receive
    /// @param use_eth True if the input coin is native token, False otherwise
    /// @param receiver Address to send the output coin to. Default is msg.sender
    /// @return uint256 Amount of tokens at index j received by the `receiver
    function exchange(uint256 i, uint256 j, uint256 dx, uint256 min_dy, bool use_eth, address receiver)
        external
        payable
        returns (uint256);

    /// @notice Exchange with callback method.
    /// @dev This method does not allow swapping in native token, but does allow
    /// swaps that transfer out native token from the pool.
    /// @dev Does not allow flashloans
    /// @dev One use-case is to reduce the number of redundant ERC20 token
    /// transfers in zaps.
    /// @param i Index value for the input coin
    /// @param j Index value for the output coin
    /// @param dx Amount of input coin being swapped in
    /// @param min_dy Minimum amount of output coin to receive
    /// @param use_eth True if output is native token, False otherwise
    /// @param sender Address to transfer input coin from
    /// @param receiver Address to send the output coin to
    /// @param cb Callback signature
    /// @return uint256 Amount of tokens at index j received by the `receiver`
    function exchange_extended(
        uint256 i,
        uint256 j,
        uint256 dx,
        uint256 min_dy,
        bool use_eth,
        address sender,
        address receiver,
        bytes32 cb
    ) external returns (uint256);

    /// @notice Adds liquidity into the pool.
    /// @param amounts Amounts of each coin to add.
    /// @param min_mint_amount Minimum amount of LP to mint.
    function add_liquidity(uint256[3] calldata amounts, uint256 min_mint_amount) external payable returns (uint256);

    /// @notice Adds liquidity into the pool.
    /// @param amounts Amounts of each coin to add.
    /// @param min_mint_amount Minimum amount of LP to mint.
    /// @return uint256 Amount of LP tokens received by the `receiver
    /// @param use_eth True if native token is being added to the pool.
    /// @param receiver Address to send the LP tokens to. Default is msg.sender
    function add_liquidity(uint256[3] calldata amounts, uint256 min_mint_amount, bool use_eth, address receiver)
        external
        payable
        returns (uint256);

    /// @notice This withdrawal method is very safe, does no complex math since
    ///         tokens are withdrawn in balanced proportions. No fees are charged.
    /// @param amount Amount of LP tokens to burn
    /// @param min_amounts Minimum amounts of tokens to withdraw
    /// @param use_eth Whether to withdraw ETH or not
    /// @param receiver Address to send the withdrawn tokens to
    /// @param claim_admin_fees If True, call self._claim_admin_fees(). Default is True.
    /// @return uint256[3] Amount of pool tokens received by the `receiver`
    function remove_liquidity(
        uint256 amount,
        uint256[3] calldata min_amounts,
        bool use_eth,
        address receiver,
        bool claim_admin_fees
    ) external returns (uint256[3] memory);

    /// @notice Withdraw liquidity in a single token.
    /// Involves fees (lower than swap fees).
    /// @dev This operation also involves an admin fee claim.
    /// @param token_amount Amount of LP tokens to burn
    /// @param i Index of the token to withdraw
    /// @param min_amount Minimum amount of token to withdraw.
    /// @param use_eth Whether to withdraw ETH or not
    /// @param receiver Address to send the withdrawn tokens to
    /// @return Amount of tokens at index i received by the `receiver`
    function remove_liquidity_one_coin(
        uint256 token_amount,
        uint256 i,
        uint256 min_amount,
        bool use_eth,
        address receiver
    ) external returns (uint256);

    ///////////////////////////////////////////////////////////
    // View methods
    ///////////////////////////////////////////////////////////

    /// @notice Returns the balance of the coin at index `i`
    function balances(uint256 i) external view returns (uint256);

    /// @notice Calculate LP tokens minted or to be burned for depositing or
    ///         removing `amounts` of coins
    /// @dev Includes fee.
    /// @param amounts Amounts of tokens being deposited or withdrawn
    /// @param deposit True if it is a deposit action, False if withdrawn.
    /// @return uint256 Amount of LP tokens deposited or withdrawn.
    function calc_token_amount(uint256[3] calldata amounts, bool deposit) external view returns (uint256);

    function get_dy(uint256 i, uint256 j, uint256 dx) external view returns (uint256);

    function get_dx(uint256 i, uint256 j, uint256 dy) external view returns (uint256);

    /// @notice Calculates the current price of the LP token with respect to the coin at the 0th index
    /// @dev This function should be implemented to return the LP price
    /// @return The current LP price as a uint256
    function lp_price() external view returns (uint256);

    function get_virtual_price() external view returns (uint256);

    /// @notice Returns the oracle price of the coin at index `k` with respect to the coin at index 0
    /// @dev The oracle is an exponential moving average, with a periodicity determined internally.
    ///      The aggregated prices are cached state prices (dy/dx) calculated AFTER the latest trade.
    /// @param k The index of the coin for which the oracle price is needed (k = 0 or 1)
    /// @return The oracle price of the coin at index `k` as a uint256
    function price_oracle(uint256 k) external view returns (uint256);

    /// @notice Calculates output tokens with fee
    /// @param token_amount LP Token amount to burn
    /// @param i token in which liquidity is withdrawn
    /// @return uint256 Amount of ith tokens received for burning token_amount LP tokens.
    function calc_withdraw_one_coin(uint256 token_amount, uint256 i) external view returns (uint256);

    function calc_token_fee(uint256[3] calldata amounts, uint256[3] calldata xp) external view returns (uint256);

    function fee_calc(uint256[3] calldata xp) external view returns (uint256);

    /// @notice Returns i-th coin address.
    /// @param i Index of the coin. i must be 0, 1 or 2.
    function coins(uint256 i) external view returns (address);

    /// @dev Returns the address of the factory that created the pool.
    /// @return address The factory address.
    function factory() external view returns (address);

    function D() external view returns (uint256);

    /// @dev Returns the cached virtual price of the pool.
    function virtual_price() external view returns (uint256);

    /// @dev Returns the current pool amplification parameter.
    /// @return uint256 The A parameter.
    function A() external view returns (uint256);

    /// @dev Returns the current pool gamma parameter.
    /// @return uint256 The gamma parameter.
    function gamma() external view returns (uint256);

    ///////////////////////////////////////////////////////////
    // Protected methods
    ///////////////////////////////////////////////////////////

    /// @notice Initialise Ramping A and gamma parameter values linearly.
    /// @dev Only accessible by factory admin, and only
    /// @param future_A The future A value.
    /// @param future_gamma The future gamma value.
    /// @param future_time The timestamp at which the ramping will end.
    function ramp_A_gamma(uint256 future_A, uint256 future_gamma, uint256 future_time) external;
}
