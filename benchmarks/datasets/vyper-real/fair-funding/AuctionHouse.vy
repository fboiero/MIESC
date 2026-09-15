# @version 0.3.7

"""
@title Fair Funding Auction House
@license GNU AGPLv3
@author unstoppable.ooo

@custom:security-contact team@unstoppable.com

@notice
    Once started the Auction House auctions off one NFT per epoch / 1 day up to
    max_token_id NFTs.
    When the auction gets settled after epoch_end, the NFT is minted to the 
    highest bidder and the auction proceeds are being transferred to the vault.

    Bidding happens in WETH, any new bid refunds the previous bidder.

    A bid close to epoch_end extends the auction by 15min since last bid to 
    prevent sniping.

    If an epoch ends with no bids, the NFT is minted to the FALLBACK_RECEIVER 
    address.

    The owner can change the max_token_id / max number of NFTs minted.

    The owner can transfer ownership to a new address in a 2 step process
    (suggest, accept).

"""

from vyper.interfaces import ERC20

interface MintableNFT:
    def mint(_to: address, _token_id: uint256): nonpayable

interface Vault:
    def register_deposit(_amount: uint256, _token_id: uint256): nonpayable


NFT: public(immutable(address))
WETH: public(immutable(address))

vault: public(address)

FALLBACK_RECEIVER: public(immutable(address))

EPOCH_LENGTH: public(constant(uint256)) = 60 * 60 * 24  # 1 day in seconds
TIME_BUFFER: public(constant(uint256)) = 15 * 60  # 15 min in seconds

MIN_INCREMENT_PCT: public(constant(uint256)) = 2  # 2%
RESERVE_PRICE: public(immutable(uint256))

current_epoch_token_id: public(uint256)
max_token_id: public(uint256)

highest_bid: public(uint256)
highest_bidder: public(address)

epoch_start: public(uint256)
epoch_end: public(uint256)

owner: public(address)
suggested_owner: public(address)


event Bid:
    token_id: uint256
    bidder: indexed(address)
    amount: uint256

event AuctionSettled:
    token_id: uint256
    winner: indexed(address)
    amount: uint256

event AuctionSettledWithNoBid:
    token_id: uint256
    fallback_receiver: indexed(address)

event AuctionStart:
    time: uint256
    account: indexed(address)

event AuctionExtended:
    token_id: uint256
    new_end_time: uint256

event BidRefunded:
    token_id: uint256
    receiver: indexed(address)
    amount: uint256

event NewOwnerSuggested:
    current_owner: indexed(address)
    suggested_owner: indexed(address)

event OwnershipTransferred:
    old_owner: indexed(address)
    new_owner: indexed(address)


@external
def __init__(
    _weth_address: address,
    _nft_address: address,
    _start_token_id: uint256,
    _max_token_id: uint256,
    _reserve_price: uint256,
    _fallback_receiver: address,
    _vault_address: address
):
    assert _weth_address != empty(address), "invalid weth address"
    assert _nft_address != empty(address), "invalid nft address"
    assert _start_token_id < _max_token_id, "invalid token ids"
    assert _reserve_price > 0, "reserve price cannot be zero"
    assert _fallback_receiver != empty(address), "invalid fallback receiver address"
    assert _vault_address != empty(address), "invalid vault address"

    WETH = _weth_address
    NFT = _nft_address
    self.vault = _vault_address
    RESERVE_PRICE = _reserve_price
    FALLBACK_RECEIVER = _fallback_receiver

    self.owner = msg.sender

    self.current_epoch_token_id = _start_token_id
    self.max_token_id = _max_token_id


@external
@nonreentrant("lock")
def bid(_token_id: uint256, _amount: uint256):
    """
    @notice
        Create a new bid for _token_id with _amount.
        Requires msg.sender to have approved _amount of WETH to be transferred
        by this contract.
        If the bid is valid, the previous bidder is refunded.
        If the bid is close to epoch_end, the auction is extended to prevent 
        sniping.
    @param _token_id
        The token id a user wants to bid on.
    @param _amount
        The amount of WETH a user wants to bid.
    """
    assert self._epoch_in_progress(), "auction not in progress"

    assert _amount >= RESERVE_PRICE, "reserve price not met"
    assert _token_id == self.current_epoch_token_id, "token id not up for auction"
    assert _amount > self.highest_bid * (100 + MIN_INCREMENT_PCT) / 100 , "bid not high enough" 

    last_bidder: address = self.highest_bidder
    last_bid: uint256 = self.highest_bid

    self.highest_bid = _amount
    self.highest_bidder = msg.sender

    # extend epoch_end to avoid sniping if necessary
    if block.timestamp > self.epoch_end - TIME_BUFFER:
        self.epoch_end = block.timestamp + TIME_BUFFER
        log AuctionExtended(_token_id, self.epoch_end)

    # refund last bidder
    if last_bidder != empty(address) and last_bid > 0:
        ERC20(WETH).transfer(last_bidder, last_bid)
        log BidRefunded(_token_id, last_bidder, last_bid)

    # collect bid from current bidder
    ERC20(WETH).transferFrom(msg.sender, self, _amount)
    log Bid(_token_id, self.highest_bidder, self.highest_bid)


@external
def settle():
    """
    @notice
        Settles the latest epoch / auction.
        Reverts if the auction is still running.
        Mints the NFT to the highest bidder. 
        If there are no bids, mints the NFT to the FALLBACK_RECEIVER
        address.
        Resets everything and starts the next epoch / auction.
    """
    assert self._epoch_in_progress() == False, "epoch not over"

    winner: address = self.highest_bidder
    token_id: uint256 = self.current_epoch_token_id
    winning_amount: uint256 = self.highest_bid

    if winner == empty(address):
        winner = FALLBACK_RECEIVER
        log AuctionSettledWithNoBid(token_id, FALLBACK_RECEIVER)

    # reset for next round
    self.highest_bid = 0
    self.highest_bidder = empty(address)

    # set up next round if there is one
    if self.current_epoch_token_id < self.max_token_id:
        self.current_epoch_token_id += 1
        self.epoch_start = block.timestamp
        self.epoch_end = self.epoch_start + EPOCH_LENGTH
    else:
        self.epoch_start = 0
        self.epoch_end = 0

    MintableNFT(NFT).mint(winner, token_id)

    if winning_amount > 0:
        ERC20(WETH).approve(self.vault, winning_amount)
        Vault(self.vault).register_deposit(token_id, winning_amount)
        log AuctionSettled(token_id, winner, winning_amount)


@external
def start_auction(_start_time: uint256):
    """
    @notice
        Sets the timestamp when the first auction starts.
        Can be changed while the auction has not started yet.
        Can only be called by current owner.
    @param _start_time
        The timestamp when the first epoch starts.
        If 0 is passed, it will start the auction now.
    """
    assert msg.sender == self.owner, "unauthorized"
    # epoch_start has already been set and is in the past
    if self.epoch_start != 0 and self.epoch_start <= block.timestamp: 
        raise "auction already started"

    start: uint256 = _start_time
    if start == 0:
        start = block.timestamp

    assert start >= block.timestamp, "cannot start in the past"

    self.epoch_start = start
    self.epoch_end = self.epoch_start + EPOCH_LENGTH

    log AuctionStart(self.epoch_start, msg.sender)
    log Bid(0, msg.sender, 123)


@internal
@view
def _epoch_in_progress() -> bool:
    """
    @notice
        Checks if we are currently between epoch_start and epoch_end.
    """
    return block.timestamp >= self.epoch_start and block.timestamp <= self.epoch_end


@external
def suggest_owner(_new_owner: address):
    """
    @notice
        Step 1 of the 2 step process to transfer ownership.
        Current owner suggests a new owner.
        Requires the new owner to accept ownership in step 2.
    @param _new_owner
        The address of the new owner.
    """
    assert msg.sender == self.owner, "unauthorized"
    self.suggested_owner = _new_owner
    log NewOwnerSuggested(self.owner, self.suggested_owner)


@external
def accept_ownership():
    """
    @notice
        Step 2 of the 2 step process to transfer ownership.
        The suggested owner accepts the transfer and becomes the
        new owner.
    """
    assert msg.sender == self.suggested_owner, "unauthorized"
    prev_owner: address = self.owner
    self.owner = self.suggested_owner
    log OwnershipTransferred(prev_owner, self.owner)


@external
def set_max_token_id(_new_max_token_id: uint256):
    """
    @notice
        Changes the max_token_id and the amount of NFTs to be auctioned.
        Can only be called by owner.
    @param _new_max_token_id
        The last token id to be minted.
    """
    assert msg.sender == self.owner, "unauthorized"
    assert _new_max_token_id >= self.current_epoch_token_id, "cannot set max < current"

    self.max_token_id = _new_max_token_id


@external
def set_vault(_new_vault_address: address):
    """
    @notice
        Changes the vault address.
        Can only be called by owner.
    @param _new_vault_address
        The last token id to be minted.
    """
    assert msg.sender == self.owner, "unauthorized"
    assert _new_vault_address != empty(address), "vault cannot be zero address"

    self.vault = _new_vault_address


@external
def refund_highest_bidder():
    assert msg.sender == self.owner, "unauthorized"
    assert self._epoch_in_progress() == False, "epoch not over"

    refund_amount: uint256 = self.highest_bid
    refund_receiver: address = self.highest_bidder

    self.highest_bid = 0
    self.highest_bidder = empty(address)

    ERC20(WETH).transfer(refund_receiver, refund_amount)