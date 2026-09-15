// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity 0.8.19;

uint256 constant WAD = 1e18;

// @notice 100% in basis points. 10_000 = 100%s
uint256 constant MAX_BPS = 10_000;

/* =============== ADDRESSES ================ */

// @notice WETH address on mainnet
address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;

// @notice stETH address on mainnet
address constant STETH = 0xae7ab96520DE3A18E5e111B5EaAb095312D7fE84;

// @notice wstETH address on mainnet
address constant WSTETH = 0x7f39C581F595B53c5cb19bD0b3f8dA6c935E2Ca0;

// @notice WithdrawalQueueERC721 of LIDO address on mainnet
address constant LIDO_WITHDRAWAL_QUEUE = 0x889edC2eDab5f40e902b864aD4d7AdE8E412F9B1;

// @notice rETH address on mainnet
address constant RETH = 0xae78736Cd615f374D3085123A210448E74Fc6393;

// @notice cETH address on mainnet
address constant CETH = 0x4Ddc2D193948926D02f9B1fE9e1daa0718270ED5;

// @notice CDAI address on mainnet
address constant CDAI = 0x5d3a536E4D6DbD6114cc1Ead35777bAB948E3643;

// @notice DAI address on mainnet
address constant DAI = 0x6B175474E89094C44Da98b954EedeAC495271d0F;

// @notice COMPTROLLER address on mainnet
address constant COMPTROLLER = 0x3d9819210A31b4961b30EF54bE2aeD79B9c9Cd3B;

// @notice COMP address on mainnet
address constant COMP = 0xc00e94Cb662C3520282E6f5717214004A7f26888;

// @notice AWETH address on mainnet
address constant AWETH = 0x4d5F47FA6A74757f35C14fD3a6Ef8E3C9BC514E8;

// @notice LendingAAVEV3_POOL_ADDRESSES_PROVIDER address on mainnet
address constant AAVEV3_POOL_ADDRESSES_PROVIDER = 0x2f39d218133AFaB8F2B819B1066c7E434Ad94E9e;

// @notice ma3WETH ERC 4626 Vault address on mainnet
address constant MA3WETH = 0x39Dd7790e75C6F663731f7E1FdC0f35007D3879b;

// @notice Morpho Aave v3 optimizer contract address on mainnet
address constant MORPHO_AAVE_V3 = 0x33333aea097c193e66081E930c33020272b33333;

// @notice MORPHO token address on mainnet
address constant MORPHO = 0x9994E35Db50125E0DF82e4c2dde62496CE330999;

// @notice Frax Ether address on mainnet
address constant FRXETH = 0x5E8422345238F34275888049021821E8E08CAa1f;

// @notice Staked Frax Ether address on mainnet
address constant STAKED_FRXETH = 0xac3E018457B222d93114458476f3E3416Abbe38F;
