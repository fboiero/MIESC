// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.0;

/// @title Frax Ether Redemption Queue Contract Interface
/// @dev https://github.com/FraxFinance/frax-ether-redemption-queue/tree/master
interface IFraxEtherRedemptionQueue {
    // =============================================================================================
    // ERC721 Functions
    // =============================================================================================

    function ownerOf(uint256 tokenId) external view returns (address owner);

    // =============================================================================================
    // Frax Ether Redemption Queue Functions
    // =============================================================================================

    /// @notice State of Frax's frxETH redemption queue
    /// @param etherLiabilities How much ETH is currently under request to be redeemed
    /// @param nextNftId Autoincrement for the NFT id
    /// @param queueLengthSecs Current wait time (in seconds) a new redeemer would have. Should be close to Beacon.
    /// @param redemptionFee Redemption fee given as a percentage with 1e6 precision
    /// @param earlyExitFee Early NFT back to frxETH exit fee given as a percentage with 1e6 precision
    struct RedemptionQueueState {
        uint64 nextNftId;
        uint64 queueLengthSecs;
        uint64 redemptionFee;
        uint64 earlyExitFee;
    }

    /// @notice State of Frax's frxETH redemption queue
    function redemptionQueueState() external view returns (RedemptionQueueState memory);

    /// @notice Accounting of Frax's frxETH redemption queue
    function redemptionQueueAccounting() external view returns (RedemptionQueueAccounting memory);

    /// @param etherLiabilities How much ETH would need to be paid out if every NFT holder could claim immediately
    /// @param unclaimedFees Earned fees that the protocol has not collected yet
    struct RedemptionQueueAccounting {
        uint128 etherLiabilities;
        uint128 unclaimedFees;
    }

    /// @notice The ```RedemptionQueueItem``` struct provides metadata information about each Nft
    /// @param hasBeenRedeemed boolean for whether the NFT has been redeemed
    /// @param amount How much ETH is claimable
    /// @param maturity Unix timestamp when they can claim their ETH
    /// @param earlyExitFee EarlyExitFee at time of NFT mint
    struct RedemptionQueueItem {
        bool hasBeenRedeemed;
        uint64 maturity;
        uint120 amount;
        uint64 earlyExitFee;
    }

    /// @notice Information about a user's redemption ticket NFT
    function nftInformation(uint256 nftId) external view returns (RedemptionQueueItem memory);

    // =============================================================================================
    // Queue Functions
    // =============================================================================================

    /// @notice When someone enters the redemption queue
    /// @param nftId The ID of the NFT
    /// @param sender The address of the msg.sender, who is redeeming frxEth
    /// @param recipient The recipient of the NFT
    /// @param amountFrxEthRedeemed The amount of frxEth redeemed
    /// @param maturityTimestamp The date of maturity, upon which redemption is allowed
    /// @param redemptionFeeAmount The redemption fee
    /// @param earlyExitFee The early exit fee at the time of minting
    event EnterRedemptionQueue(
        uint256 indexed nftId,
        address indexed sender,
        address indexed recipient,
        uint256 amountFrxEthRedeemed,
        uint120 redemptionFeeAmount,
        uint64 maturityTimestamp,
        uint256 earlyExitFee
    );

    /// @notice Enter the queue for redeeming frxETH 1-to-1. Must approve first.
    /// @notice Will generate a FrxETHRedemptionTicket NFT that can be redeemed for the actual ETH later.
    /// @param recipient Recipient of the NFT. Must be ERC721 compatible if a contract
    /// @param amountToRedeem Amount to redeem
    /// @dev Must call approve/permit on frxEth contract prior to this call
    function enterRedemptionQueue(address recipient, uint120 amountToRedeem) external;

    /// @notice When someone early redeems their NFT for frxETH, with the penalty
    /// @param nftId The ID of the NFT
    /// @param sender The sender of the NFT
    /// @param recipient The recipient of the redeemed ETH
    /// @param frxEthOut The amount of frxETH actually sent back to the user
    /// @param earlyExitFeeAmount Any penalty fee paid for exiting early
    event EarlyBurnRedemptionTicketNft(
        uint256 indexed nftId,
        address indexed sender,
        address indexed recipient,
        uint120 frxEthOut,
        uint120 earlyExitFeeAmount
    );

    /// @notice Redeems a FrxETHRedemptionTicket NFT early for frxETH, not ETH. Is penalized in doing so. Used if person does not want to wait for exit anymore.
    /// @param _nftId The ID of the NFT
    /// @param _recipient The recipient of the redeemed ETH
    /// @return _frxEthOut The amount of frxETH actually sent back to the user
    function earlyBurnRedemptionTicketNft(
        address payable _recipient,
        uint256 _nftId
    ) external returns (uint120 _frxEthOut);

    /// @notice When someone redeems their NFT for ETH
    /// @param nftId the if of the nft redeemed
    /// @param sender the msg.sender
    /// @param recipient the recipient of the ether
    /// @param amountOut the amount of ether sent to the recipient
    event BurnRedemptionTicketNft(
        uint256 indexed nftId,
        address indexed sender,
        address indexed recipient,
        uint120 amountOut
    );

    /// @notice Redeems a FrxETHRedemptionTicket NFT for ETH. Must have reached the maturity date first.
    /// @param _nftId The ID of the NFT
    /// @param _recipient The recipient of the redeemed ETH
    function burnRedemptionTicketNft(uint256 _nftId, address payable _recipient) external;
}
