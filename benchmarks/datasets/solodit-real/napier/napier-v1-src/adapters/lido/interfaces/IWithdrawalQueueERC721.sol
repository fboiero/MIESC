// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

/// @notice A FIFO queue for stETH withdrawal requests and an unstETH NFT interface representing the position in the queue.
/// @dev https://github.com/lidofinance/lido-dao/blob/master/contracts/0.8.9/WithdrawalQueue.sol
/// @dev https://docs.lido.fi/contracts/withdrawal-queue-erc721/#requestwithdrawals
interface IWithdrawalQueueERC721 {
    /// @param amountOfStETH — the number of stETH tokens transferred to the contract upon request
    /// @param amountOfShares — the number of underlying shares corresponding to transferred stETH tokens. See Lido rebasing chapter to learn about the shares mechanic
    /// @param owner — the owner's address for this request. The owner is also a holder of the unstETH NFT and can transfer the ownership and claim the underlying ether once finalized
    /// @param timestamp — the creation time of the request
    /// @param isFinalized — finalization status of the request; finalized requests are available to claim
    /// @param isClaimed — the claim status of the request. Once claimed, NFT is burned, and the request is not available to claim again
    struct WithdrawalRequestStatus {
        uint256 amountOfStETH;
        uint256 amountOfShares;
        address owner;
        uint256 timestamp;
        bool isFinalized;
        bool isClaimed;
    }

    /// @notice Batch request the `_amounts` of stETH for withdrawal to the `_owner` address. For each request, the respective amount of stETH is transferred to this contract address, and an unstETH NFT is minted to the `_owner` address.
    /// @dev Requirements:
    /// - withdrawals must not be paused
    /// - stETH balance of `msg.sender` must be greater than the sum of all `_amounts`
    /// - there must be approval from the `msg.sender` to this contract address for the overall amount of stETH token transfer
    /// - each amount in `_amounts` must be greater than `MIN_STETH_WITHDRAWAL_AMOUNT` and lower than `MAX_STETH_WITHDRAWAL_AMOUNT`
    /// @return requestIds Returns the array of ids for each created request. Emits WithdrawalRequested and Transfer events.
    function requestWithdrawals(
        uint256[] calldata _amounts,
        address _owner
    ) external returns (uint256[] memory requestIds);

    /// @notice Claim a batch of withdrawal requests if they are finalized sending locked ether to the owner
    /// @param requestIds array of request ids to claim
    /// @param hints checkpoint hint for each id. Can be obtained with `findCheckpointHints()`
    /// @dev
    ///  Reverts if requestIds and hints arrays length differs
    ///  Reverts if any requestId or hint in arguments are not valid
    ///  Reverts if any request is not finalized or already claimed
    ///  Reverts if msg sender is not an owner of the requests
    function claimWithdrawals(uint256[] calldata requestIds, uint256[] calldata hints) external;

    /// @notice Claim one`_requestId` request once finalized sending locked ether to the owner
    /// @param _requestId request id to claim
    /// @dev use unbounded loop to find a hint, which can lead to OOG
    /// @dev
    ///  Reverts if requestId or hint are not valid
    ///  Reverts if request is not finalized or already claimed
    ///  Reverts if msg sender is not an owner of request
    function claimWithdrawal(uint256 _requestId) external;

    /// @notice Returns status for requests with provided ids
    /// @param _requestIds array of withdrawal request ids
    function getWithdrawalStatus(
        uint256[] calldata _requestIds
    ) external view returns (WithdrawalRequestStatus[] memory statuses);

    /// @notice Finalize requests from last finalized one up to `_lastRequestIdToBeFinalized`
    /// @dev ether to finalize all the requests should be calculated using `prefinalize()` and sent along
    function finalize(uint256 _lastRequestIdToBeFinalized, uint256 _maxShareRate) external payable;

    function getLastFinalizedRequestId() external view returns (uint256);
}
