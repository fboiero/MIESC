// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// https://github.com/curvefi/tricrypto-ng/blob/0bc1191b6097c8854e4f09e385f6c2c79a5bb773/contracts/main/CurveTricryptoOptimizedWETH.vy

interface CurveTricryptoFactory {
    /// @notice Get the coins within a pool
    /// @param pool Address of the pool
    /// @return address[3] Array of the 3 coins in the pool
    function get_coins(address pool) external view returns (address[3] memory);

    //////////////////////////////////////////////////////////////////////
    // Protected methods
    //////////////////////////////////////////////////////////////////////

    // function deploy_pool(
    //     string memory _name,
    //     string memory _symbol,
    //     address[3] calldata _coins,
    //     address _weth,
    //     uint256 implementation_id,
    //     uint256 A,
    //     uint256 gamma,
    //     uint256 mid_fee,
    //     uint256 out_fee,
    //     uint256 fee_gamma,
    //     uint256 allowed_extra_profit,
    //     uint256 adjustment_step,
    //     uint256 ma_exp_time,
    //     uint256[2] calldata initial_prices
    // ) external returns (address);

    function set_pool_implementation(address _pool_implementation, uint256 _implementation_index) external;

    function set_gauge_implementation(address _gauge_implementation) external;

    function set_views_implementation(address _views_implementation) external;

    function set_math_implementation(address _math_implementation) external;
}
