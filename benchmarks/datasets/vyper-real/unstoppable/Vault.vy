# @version ^0.3.7

###################################################################
#
# @title Unstoppable Margin DEX - Vault
# @license GNU AGPLv3
# @author unstoppable.ooo
#
# @custom:security-contact team@unstoppable.ooo
#
# @notice
#    This contract is part of the Unstoppable Margin DEX.
#
#    It handles all assets and allows whitelisted contracts
#    to create undercollateralized loan positions for users
#    that are then used to gain leveraged spot exposure to
#    an underlying asset.
#
###################################################################

interface ERC20:
    def balanceOf(_account: address) -> uint256: view
    def decimals() -> uint8: view
    def approve(_spender: address, _amount: uint256): nonpayable

interface ChainlinkOracle:
    def latestRoundData() -> (
      uint80,  # roundId,
      int256,  # answer,
      uint256, # startedAt,
      uint256, # updatedAt,
      uint80   # answeredInRound
    ): view

interface SwapRouter:
    def swap(
        _token_in: address,
        _token_out: address,
        _amount_in: uint256,
        _min_amount_out: uint256
        ) -> uint256: nonpayable

interface Weth:
    def deposit(): payable
    def withdrawTo(_account: address, _amount: uint256): nonpayable


PRECISION: constant(uint256) = 10**18

SECONDS_PER_YEAR: constant(uint256) = 365 * 24 * 60 * 60
PERCENTAGE_BASE: constant(uint256) = 100_00 # == 100%
PERCENTAGE_BASE_HIGH_PRECISION: constant(uint256) = 100_00_000  # == 100%

ARBITRUM_SEQUENCER_UPTIME_FEED: constant(address) = 0xFdB631F5EE196F0ed6FAa767959853A9F217697D
ORACLE_FRESHNESS_THRESHOLD: constant(uint256) = 24*60*60 # 24h

WETH: constant(address) = 0x82aF49447D8a07e3bd95BD0d56f35241523fBab1

FULL_UTILIZATION: constant(uint256) = 100_00_000
FALLBACK_INTEREST_CONFIGURATION: constant(uint256[4]) = [
    3_00_000,
    20_00_000,
    100_00_000,
    80_00_000,
]

swap_router: public(address)

# whitelisted addresses allowed to interact with this vault
is_whitelisted_dex: public(HashMap[address, bool])

# address -> address -> bool
is_whitelisted_token: public(HashMap[address, bool])
# token_in -> # token_out
is_enabled_market: HashMap[address, HashMap[address, bool]]
# token_in -> # token_out
max_leverage: public(HashMap[address, HashMap[address, uint256]])
# token -> Chainlink oracle
to_usd_oracle: public(HashMap[address, address])
# token_in -> # token_out -> slippage
liquidate_slippage: public(HashMap[address, HashMap[address, uint256]])

# the fee charged to traders when opening a position
trade_open_fee: public(uint256) # 10 = 0.1%
liquidation_penalty: public(uint256)
# share of trading fee going to LPs vs protocol
trading_fee_lp_share: public(uint256) 
protocol_fee_receiver: public(address)

# trader margin balances
margin: public(HashMap[address, HashMap[address, uint256]])

# Liquidity
# cooldown to prevent flashloan deposit/withdraws
withdraw_liquidity_cooldown: public(uint256)
account_withdraw_liquidity_cooldown: public(HashMap[address, uint256])

# base LPs
base_lp_shares: public(HashMap[address, HashMap[address, uint256]])
base_lp_total_shares: public(HashMap[address, uint256])
base_lp_total_amount: public(HashMap[address, uint256])

# Safety Module LPs
safety_module_lp_shares: public(HashMap[address, HashMap[address, uint256]])
safety_module_lp_total_shares: public(HashMap[address, uint256])
safety_module_lp_total_amount: public(HashMap[address, uint256])

safety_module_interest_share_percentage: public(uint256)


# debt_token -> total_debt_shares
total_debt_shares: public(HashMap[address, uint256])
# debt_token -> Position uid -> debt_shares
debt_shares: public(HashMap[address, HashMap[bytes32, uint256]])
# debt_token -> total_debt
total_debt_amount: public(HashMap[address, uint256])
# debt_token -> timestamp
last_debt_update: public(HashMap[address, uint256])

# token -> bad_debt
bad_debt: public(HashMap[address, uint256])

# dynamic interest rates [min, mid, max, kink]
interest_configuration: HashMap[address, uint256[4]]

struct Position:
    uid: bytes32
    account: address
    debt_token: address
    margin_amount: uint256
    debt_shares: uint256
    position_token: address
    position_amount: uint256

# uid -> Position
positions: public(HashMap[bytes32, Position])

uid_nonce: uint256

admin: public(address)
suggested_admin: public(address)
is_accepting_new_orders: public(bool)


@external
def __init__():
    self.admin = msg.sender
    self.protocol_fee_receiver = msg.sender


event PositionOpened:
    account: indexed(address)
    position: Position

@nonreentrant("lock")
@external
def open_position(
    _account: address,
    _position_token: address,
    _min_position_amount_out: uint256,
    _debt_token: address,
    _debt_amount: uint256,
    _margin_amount: uint256,
) -> (bytes32, uint256):
    """
    @notice
        Creates a new undercollateralized loan for _account
        and uses it to assume a leveraged spot position in
        _position_token.
    """
    assert self.is_accepting_new_orders, "paused"
    assert self.is_whitelisted_dex[msg.sender], "unauthorized"
    assert self.is_enabled_market[_debt_token][_position_token], "market not enabled"
    assert self.margin[_account][_debt_token] >= _margin_amount, "not enough margin"
    assert ((_debt_amount + _margin_amount) * PRECISION / _margin_amount) <= self.max_leverage[_debt_token][_position_token] * PRECISION, "too much leverage"
    assert (self._available_liquidity(_debt_token) >= _debt_amount), "insufficient liquidity"

    self.margin[_account][_debt_token] -= _margin_amount
    debt_shares: uint256 = self._borrow(_debt_token, _debt_amount)

    token_in_amount: uint256 = _debt_amount + _margin_amount
    amount_bought: uint256 = self._swap(
        _debt_token, _position_token, token_in_amount, _min_position_amount_out
    )

    position_uid: bytes32 = self._generate_uid()
    position: Position = Position(
        {
            uid: position_uid,
            account: _account,
            debt_token: _debt_token,
            margin_amount: _margin_amount,
            debt_shares: debt_shares,
            position_token: _position_token,
            position_amount: amount_bought,
        }
    )

    self.positions[position_uid] = position

    # charge fee
    fee: uint256 = token_in_amount * self.trade_open_fee / PERCENTAGE_BASE
    assert self.margin[_account][_debt_token] >= fee, "not enough margin for fee"
    self.margin[_account][_debt_token] -= fee
    self._distribute_trading_fee(_debt_token, fee)

    log PositionOpened(_account, position)

    return position_uid, amount_bought


event PositionClosed:
    account: indexed(address)
    uid: bytes32
    position: Position
    amount_received: uint256


event BadDebt:
    token: indexed(address)
    amount: uint256
    position_uid: bytes32


@nonreentrant("lock")
@external
def close_position(_position_uid: bytes32, _min_amount_out: uint256) -> uint256:
    assert self.is_whitelisted_dex[msg.sender], "unauthorized"
    return self._close_position(_position_uid, _min_amount_out)


@internal
def _close_position(_position_uid: bytes32, _min_amount_out: uint256) -> uint256:
    """
    @notice
        Closes an existing position, repays the debt plus
        accrued interest and credits/debits the users margin
        with the remaining PnL.
    """
    # fetch the position from the positions-dict by uid
    position: Position = self.positions[_position_uid]

    # assign to local variable to make it editable
    min_amount_out: uint256 = _min_amount_out
    if min_amount_out == 0:
        # market order, add some slippage protection
        min_amount_out = self._market_order_min_amount_out(
            position.position_token, position.debt_token, position.position_amount
        )

    position_debt_amount: uint256 = self._debt(_position_uid)
    amount_out_received: uint256 = self._swap(
        position.position_token,
        position.debt_token,
        position.position_amount,
        min_amount_out,
    )

    if amount_out_received >= position_debt_amount:
        # all good, LPs are paid back, remainder goes back to trader
        trader_pnl: uint256 = amount_out_received - position_debt_amount
        self.margin[position.account][position.debt_token] += trader_pnl
        self._repay(position.debt_token, position_debt_amount)
    else:
        # edge case: bad debt
        self.is_accepting_new_orders = False  # put protocol in defensive mode
        bad_debt: uint256 = position_debt_amount - amount_out_received
        self.bad_debt[position.debt_token] += bad_debt
        self._repay(
            position.debt_token, amount_out_received
        )  # repay LPs as much as possible
        log BadDebt(position.debt_token, bad_debt, position.uid)

    # cleanup position
    self.positions[_position_uid] = empty(Position)

    log PositionClosed(position.account, position.uid, position, amount_out_received)

    return amount_out_received


event PositionReduced:
    account: indexed(address)
    uid: bytes32
    position: Position
    amount_received: uint256

@nonreentrant("lock")
@external
def reduce_position(
    _position_uid: bytes32, _reduce_by_amount: uint256, _min_amount_out: uint256
) -> uint256:
    """
    @notice
        Partially closes an existing position, by selling some of the 
        underlying position_token.
        Reduces both debt and margin in the position, leverage 
        remains as is.
    """
    assert self.is_whitelisted_dex[msg.sender], "unauthorized"
    assert not self._is_liquidatable(_position_uid), "in liquidation"

    position: Position = self.positions[_position_uid]
    assert position.position_amount >= _reduce_by_amount, "_reduce_by_amount > position"

    min_amount_out: uint256 = _min_amount_out
    if min_amount_out == 0:
        # market order, add some slippage protection
        min_amount_out = self._market_order_min_amount_out(
            position.position_token, position.debt_token, position.position_amount
        )

    debt_amount: uint256 = self._debt(_position_uid)
    margin_debt_ratio: uint256 = position.margin_amount * PRECISION / debt_amount

    amount_out_received: uint256 = self._swap(
        position.position_token, position.debt_token, _reduce_by_amount, min_amount_out
    )

    # reduce margin and debt, keep leverage as before
    reduce_margin_by_amount: uint256 = (
        amount_out_received * margin_debt_ratio / PRECISION
    )
    reduce_debt_by_amount: uint256 = amount_out_received - reduce_margin_by_amount

    position.margin_amount -= reduce_margin_by_amount

    burnt_debt_shares: uint256 = self._repay(position.debt_token, reduce_debt_by_amount)
    position.debt_shares -= burnt_debt_shares
    position.position_amount -= _reduce_by_amount

    self.positions[_position_uid] = position

    log PositionReduced(position.account, _position_uid, position, amount_out_received)

    return amount_out_received


event PositionLiquidated:
    account: indexed(address)
    uid: bytes32
    positon: Position

@nonreentrant("lock")
@external
def liquidate(_position_uid: bytes32):
    """
    @notice
        Liquidates a position that exceeds the maximum allowed
        leverage for that market.
        Charges the account a liquidation penalty.
    """
    assert self.is_whitelisted_dex[msg.sender], "unauthorized"
    assert self._is_liquidatable(_position_uid), "position not liquidateable"

    position: Position = self.positions[_position_uid]
    debt_amount: uint256 = self._debt(_position_uid)

    min_amount_out: uint256 = self._market_order_min_amount_out(
        position.position_token, position.debt_token, position.position_amount
    )

    amount_out_received: uint256 = self._close_position(_position_uid, min_amount_out)

    # penalize account
    penalty: uint256 = debt_amount * self.liquidation_penalty / PERCENTAGE_BASE

    if amount_out_received > debt_amount:
        # margin left
        remaining_margin: uint256 = amount_out_received - debt_amount
        penalty = min(penalty, remaining_margin)
        self.margin[position.account][position.debt_token] -= penalty
        self._distribute_trading_fee(position.debt_token, penalty)

    log PositionLiquidated(position.account, _position_uid, position)

#####################################
#
#         SWAP INTEGRATION
#
#####################################

@internal
def _swap(
    _token_in: address,
    _token_out: address,
    _amount_in: uint256,
    _min_amount_out: uint256,
) -> uint256:
    """
    @notice
        Triggers a swap in the referenced swap_router.
        Ensures min_amount_out is respected.
    """
    ERC20(_token_in).approve(self.swap_router, _amount_in)
    token_out_balance_before: uint256 = ERC20(_token_out).balanceOf(self)

    amount_out_received: uint256 = SwapRouter(self.swap_router).swap(
        _token_in, _token_out, _amount_in, _min_amount_out
    )

    token_out_balance_after: uint256 = ERC20(_token_out).balanceOf(self)
    assert (
        token_out_balance_after >= token_out_balance_before + _min_amount_out
    ), "min_amount_out"

    return amount_out_received


@internal
def _market_order_min_amount_out(
    _token_in: address, _token_out: address, _amount_in: uint256
) -> uint256:
    """
    @notice
        For market orders like during liquidation or for a StopLoss,
        we want a fairly wide slippage to ensure the swap is executed
        as quickly as possible, while at the same time protect against
        sandwhich attacks and frontrunning.
        Here we calculate a reasonable min_amount_out based on the 
        liquidate_slippage configured for the specific market.
    """
    return (
        self._quote_token_to_token(_token_in, _token_out, _amount_in)
        * (PERCENTAGE_BASE - self.liquidate_slippage[_token_in][_token_out])
        / PERCENTAGE_BASE
    )


#####################################
#
#        LEVERAGE & HEALTH
#
#####################################

@view
@external
def effective_leverage(_position_uid: bytes32) -> uint256:
    return self._effective_leverage(_position_uid)


@view
@internal
def _effective_leverage(_position_uid: bytes32) -> uint256:
    """
    @notice
        Calculated the current leverage of a position based
        on the position current value, the underlying margin 
        and the accrued debt.
    """
    position: Position = self.positions[_position_uid]
    debt_amount: uint256 = self._debt(_position_uid)

    position_value: uint256 = self._in_usd(
        position.position_token, position.position_amount
    )
    debt_value: uint256 = self._in_usd(position.debt_token, debt_amount)
    margin_value: uint256 = self._in_usd(position.debt_token, position.margin_amount)

    return self._calculate_leverage(position_value, debt_value, margin_value)


@view
@internal
def _calculate_leverage(
    _position_value: uint256, _debt_value: uint256, _margin_value: uint256
) -> uint256:
    if _position_value <= _debt_value:
        # bad debt
        return max_value(uint256)

    return (
        PRECISION
        * (_debt_value + _margin_value)
        / (_position_value - _debt_value)
        / PRECISION
    )


@view
@external
def is_liquidatable(_position_uid: bytes32) -> bool:
    return self._is_liquidatable(_position_uid)

@view
@internal
def _is_liquidatable(_position_uid: bytes32) -> bool:
    """
    @notice
        Checks if a position exceeds the maximum leverage
        allowed for that market.
    """
    position: Position = self.positions[_position_uid]
    leverage: uint256 = self._effective_leverage(_position_uid)
    return leverage > self.max_leverage[position.debt_token][position.position_token]


event MarginAdded:
    uid: bytes32
    amount: uint256
   
@external
def add_margin(_position_uid: bytes32, _amount: uint256):
    """
    @notice
        Allows to add additional margin to a Position and 
        reduce the leverage.
    """
    assert self.is_whitelisted_dex[msg.sender], "unauthorized"

    position: Position = self.positions[_position_uid]

    assert (self.margin[position.account][position.debt_token] >= _amount), "not enough margin"

    self.margin[position.account][position.debt_token] -= _amount
    position.margin_amount += _amount

    self.positions[_position_uid] = position
    log MarginAdded(_position_uid, _amount)


event MarginRemoved:
    uid: bytes32
    amount: uint256


@external
def remove_margin(_position_uid: bytes32, _amount: uint256):
    """
    @notice
        Allows to remove margin from a Position and 
        increase the leverage.
    """
    assert self.is_whitelisted_dex[msg.sender], "unauthorized"

    position: Position = self.positions[_position_uid]

    assert position.margin_amount >= _amount, "not enough margin"

    position.margin_amount -= _amount
    self.margin[position.account][position.debt_token] += _amount

    assert not self._is_liquidatable(_position_uid), "exceeds max leverage"
    
    self.positions[_position_uid] = position
    log MarginRemoved(_position_uid, _amount)


#####################################
#
#        ORACLE PRICE FEEDS
#
#####################################

@view
@external
def to_usd_oracle_price(_token: address) -> uint256:
    return self._to_usd_oracle_price(_token)

@view
@internal
def _to_usd_oracle_price(_token: address) -> uint256:
    """
    @notice
        Retrieves the latest Chainlink oracle price for _token.
        Ensures that the Arbitrum sequencer is up and running and
        that the Chainlink feed is fresh.
    """
    assert self._sequencer_up(), "sequencer down"

    round_id: uint80 = 0
    answer: int256 = 0
    started_at: uint256 = 0
    updated_at: uint256 = 0
    answered_in_round: uint80 = 0
    round_id, answer, started_at, updated_at, answered_in_round = ChainlinkOracle(
        self.to_usd_oracle[_token]
    ).latestRoundData()

    assert (block.timestamp - updated_at) < ORACLE_FRESHNESS_THRESHOLD, "oracle not fresh"

    usd_price: uint256 = convert(answer, uint256)  # 8 dec
    return usd_price


@view
@internal
def _sequencer_up() -> bool:
    # answer == 0: Sequencer is up
    # answer == 1: Sequencer is down
    answer: int256 = ChainlinkOracle(ARBITRUM_SEQUENCER_UPTIME_FEED).latestRoundData()[1]
    return answer == 0


@view
@internal
def _in_usd(_token: address, _amount: uint256) -> uint256:
    """
    @notice
        Converts _amount of _token to a USD value.
    """
    return (
        self._to_usd_oracle_price(_token)
        * _amount
        / 10 ** convert(ERC20(_token).decimals(), uint256)
    )


@view
@external
def current_exchange_rate(_position_uid: bytes32) -> uint256:
    """
    @notice
        Returns the current exchange rate / price of a 
        Positions underlying tokens.
    """
    position: Position = self.positions[_position_uid]
    one_full: uint256 = 1 * 10 ** convert(
        ERC20(position.position_token).decimals(), uint256
    )
    return self._quote_token_to_token(
        position.position_token, position.debt_token, one_full
    )


@view
@internal
def _quote_token_to_token(
    _token0: address, _token1: address, _amount0: uint256
) -> uint256:
    token0_in_usd: uint256 = self._in_usd(_token0, _amount0)  # 8 decimals
    token1_decimals: uint256 = convert(ERC20(_token1).decimals(), uint256)
    token1_usd_price: uint256 = self._to_usd_oracle_price(_token1)
    # token_in_per_token_out = token_in_in_usdc / token_out_in_usdc with additional precision
    token1_value: uint256 = (
        PRECISION    # just for precision
        * 10**token1_decimals 
        * token0_in_usd
        / token1_usd_price  # the real thing
        / PRECISION  # just for precision
    )
    return token1_value


#####################################
#
#       USER ACCOUNTS / MARGIN
#
#####################################

event AccountFunded:
    account: indexed(address)
    amount: uint256
    token: indexed(address)

@nonreentrant("lock")
@payable
@external
def fund_account_eth():
    """
    @notice
        Allows a user to fund his WETH margin by depositing ETH.
    """
    assert self.is_accepting_new_orders, "funding paused"
    assert self.is_whitelisted_token[WETH], "token not whitelisted"
    self.margin[msg.sender][WETH] += msg.value
    raw_call(WETH, method_id("deposit()"), value=msg.value)
    log AccountFunded(msg.sender, msg.value, WETH)


@nonreentrant("lock")
@external
def fund_account(_token: address, _amount: uint256):
    """
    @notice
        Allows a user to fund his _token margin.
    """
    assert self.is_accepting_new_orders, "funding paused"
    assert self.is_whitelisted_token[_token], "token not whitelisted"
    self.margin[msg.sender][_token] += _amount
    self._safe_transfer_from(_token, msg.sender, self, _amount)
    log AccountFunded(msg.sender, _amount, _token)


event WithdrawBalance:
    account: indexed(address)
    token: indexed(address)
    amount: uint256


@nonreentrant("lock")
@external
def withdraw_from_account_eth(_amount: uint256):
    """
    @notice
        Allows a user to withdraw from his WETH margin and
        automatically swaps back to ETH.
    """
    assert self.margin[msg.sender][WETH] >= _amount, "insufficient balance"
    self.margin[msg.sender][WETH] -= _amount
    raw_call(
        WETH,
        concat(
            method_id("withdrawTo(address,uint256)"),
            convert(msg.sender, bytes32),
            convert(_amount, bytes32),
        ),
    )
    log WithdrawBalance(msg.sender, WETH, _amount)


@nonreentrant("lock")
@external
def withdraw_from_account(_token: address, _amount: uint256):
    """
    @notice
        Allows a user to withdraw from his _token margin.
    """
    assert self.margin[msg.sender][_token] >= _amount, "insufficient balance"

    self.margin[msg.sender][_token] -= _amount
    self._safe_transfer(_token, msg.sender, _amount)
    log WithdrawBalance(msg.sender, _token, _amount)


@nonreentrant("lock")
@external
def swap_margin(
    _account: address,
    _token_in: address,
    _token_out: address,
    _amount_in: uint256,
    _min_amount_out: uint256,
) -> uint256:
    """
    @notice
        Allows a user to swap his margin balances between differnt tokens.
    """
    assert self.is_whitelisted_dex[msg.sender] or _account == msg.sender, "unauthorized"
    assert _amount_in <= self.margin[_account][_token_in], "insufficient balance"

    self.margin[_account][_token_in] -= _amount_in

    amount_out_received: uint256 = self._swap(
        _token_in, _token_out, _amount_in, _min_amount_out
    )

    self.margin[_account][_token_out] += amount_out_received

    return amount_out_received


#####################################
#
#             LIQUIDITY 
#
#####################################

event ProvideLiquidity:
    account: indexed(address)
    token: indexed(address)
    amount: uint256

@nonreentrant("lock")
@payable
@external
def provide_liquidity_eth(_is_safety_module: bool):
    """
    @notice
        Allows LPs to provide WETH liquidity by depositing ETH.
    """
    assert msg.value > 0, "zero value"

    assert self.is_accepting_new_orders, "LPing paused"
    assert self.is_whitelisted_token[WETH], "token not whitelisted"

    self._account_for_provide_liquidity(WETH, msg.value, _is_safety_module)

    raw_call(WETH, method_id("deposit()"), value=msg.value)

    log ProvideLiquidity(msg.sender, WETH, msg.value)


@nonreentrant("lock")
@external
def provide_liquidity(_token: address, _amount: uint256, _is_safety_module: bool):
    """
    @notice
        Allows LPs to provide _token liquidity.
    """
    assert self.is_accepting_new_orders, "LPing paused"

    assert self.is_whitelisted_token[_token], "token not whitelisted"

    self._account_for_provide_liquidity(_token, _amount, _is_safety_module)

    self._safe_transfer_from(_token, msg.sender, self, _amount)
    log ProvideLiquidity(msg.sender, _token, _amount)


@internal
def _account_for_provide_liquidity(
    _token: address, _amount: uint256, _is_safety_module: bool
):
    self._update_debt(_token)
    shares: uint256 = self._amount_to_lp_shares(_token, _amount, _is_safety_module)
    if _is_safety_module:
        self.safety_module_lp_total_shares[_token] += shares
        self.safety_module_lp_shares[_token][msg.sender] += shares
        self.safety_module_lp_total_amount[_token] += _amount

    else:
        self.base_lp_total_shares[_token] += shares
        self.base_lp_shares[_token][msg.sender] += shares
        self.base_lp_total_amount[_token] += _amount

    # record cooldown after which account can withdraw again
    self.account_withdraw_liquidity_cooldown[msg.sender] = (
        block.timestamp + self.withdraw_liquidity_cooldown
    )


event WithdrawLiquidity:
    account: indexed(address)
    token: indexed(address)
    amount: uint256

@nonreentrant("lock")
@external
def withdraw_liquidity_eth(_amount: uint256, _is_safety_module: bool):
    """
    @notice
        Allows LPs to withdraw their WETH liquidity in ETH.
        Only liquidity that is currently not lent out can be withdrawn.
    """
    assert (self.account_withdraw_liquidity_cooldown[msg.sender] <= block.timestamp), "cooldown"
    assert _amount <= self._available_liquidity(WETH), "liquidity not available"

    self._account_for_withdraw_liquidity(WETH, _amount, _is_safety_module)

    raw_call(
        WETH,
        concat(
            method_id("withdrawTo(address,uint256)"),
            convert(msg.sender, bytes32),
            convert(_amount, bytes32),
        ),
    )

    log WithdrawLiquidity(msg.sender, WETH, _amount)


@nonreentrant("lock")
@external
def withdraw_liquidity(_token: address, _amount: uint256, _is_safety_module: bool):
    """
    @notice
        Allows LPs to withdraw their _token liquidity.
        Only liquidity that is currently not lent out can be withdrawn.
    """
    assert (self.account_withdraw_liquidity_cooldown[msg.sender] <= block.timestamp), "cooldown"

    assert _amount <= self._available_liquidity(_token), "liquidity not available"

    self._account_for_withdraw_liquidity(_token, _amount, _is_safety_module)

    self._safe_transfer(_token, msg.sender, _amount)
    log WithdrawLiquidity(msg.sender, _token, _amount)


@internal
def _account_for_withdraw_liquidity(
    _token: address, _amount: uint256, _is_safety_module: bool
):
    self._update_debt(_token)
    if _is_safety_module:
        shares: uint256 = self._amount_to_lp_shares(_token, _amount, True)
        assert (shares <= self.safety_module_lp_shares[_token][msg.sender]), "cannot withdraw more than you own"
        self.safety_module_lp_total_amount[_token] -= _amount
        self.safety_module_lp_total_shares[_token] -= shares
        self.safety_module_lp_shares[_token][msg.sender] -= shares

    else:
        shares: uint256 = self._amount_to_lp_shares(_token, _amount, False)
        assert (shares <= self.base_lp_shares[_token][msg.sender]), "cannot withdraw more than you own"
        self.base_lp_total_amount[_token] -= _amount
        self.base_lp_total_shares[_token] -= shares
        self.base_lp_shares[_token][msg.sender] -= shares


@internal
@view
def _amount_to_lp_shares(
    _token: address, _amount: uint256, _is_safety_module: bool
) -> uint256:
    if _is_safety_module:
        # initial shares == wei
        if self.safety_module_lp_total_shares[_token] == 0:
            return _amount * PRECISION

        wei_per_share: uint256 = self._amount_per_safety_module_lp_share(_token)
        new_shares: uint256 = _amount * PRECISION * PRECISION / wei_per_share
        return new_shares

    else:  # base_lp
        # initial shares == wei
        if self.base_lp_total_shares[_token] == 0:
            return _amount * PRECISION

        wei_per_share: uint256 = self._amount_per_base_lp_share(_token)
        new_shares: uint256 = _amount * PRECISION * PRECISION / wei_per_share
        return new_shares


@external
@view
def lp_shares_to_amount(
    _token: address, _shares: uint256, _is_safety_module: bool
) -> uint256:
    return self._lp_shares_to_amount(_token, _shares, _is_safety_module)


@internal
@view
def _lp_shares_to_amount(
    _token: address, _shares: uint256, _is_safety_module: bool
) -> uint256:
    if _shares == 0:
        return 0

    if _is_safety_module:
        return (
            _shares
            * self._amount_per_safety_module_lp_share(_token)
            / PRECISION
            / PRECISION
        )

    return _shares * self._amount_per_base_lp_share(_token) / PRECISION / PRECISION


@internal
@view
def _amount_per_base_lp_share(_token: address) -> uint256:
    return (
        self.base_lp_total_amount[_token]
        * PRECISION
        * PRECISION
        / self.base_lp_total_shares[_token]
    )


@internal
@view
def _amount_per_safety_module_lp_share(_token: address) -> uint256:
    return (
        self._safety_module_total_amount(_token)
        * PRECISION
        * PRECISION
        / self.safety_module_lp_total_shares[_token]
    )


@internal
@view
def _safety_module_total_amount(_token: address) -> uint256:
    if self.bad_debt[_token] > self.safety_module_lp_total_amount[_token]:
        return 0
    return self.safety_module_lp_total_amount[_token] - self.bad_debt[_token]


@internal
@view
def _total_liquidity(_token: address) -> uint256:
    return (
        self.base_lp_total_amount[_token]
        + self.safety_module_lp_total_amount[_token]
        - self.bad_debt[_token]
    )

@external
@view
def available_liquidity(_token: address) -> uint256:
    return self._available_liquidity(_token)


@internal
@view
def _available_liquidity(_token: address) -> uint256:
    return self._total_liquidity(_token) - self.total_debt_amount[_token]


event BaseLpInterestReceived:
    token: address
    amount: uint256


event SafetyModuleInterestReceived:
    token: address
    amount: uint256


@internal
def _pay_interest_to_lps(_token: address, _amount: uint256):
    safety_module_amount: uint256 = (
        _amount * self.safety_module_interest_share_percentage / PERCENTAGE_BASE
    )
    base_amount: uint256 = _amount - safety_module_amount

    self.safety_module_lp_total_amount[_token] += safety_module_amount
    self.base_lp_total_amount[_token] += base_amount
    log BaseLpInterestReceived(_token, base_amount)
    log SafetyModuleInterestReceived(_token, safety_module_amount)


#####################################
#
#               DEBT
#
#####################################


@internal
def _borrow(_debt_token: address, _amount: uint256) -> uint256:
    self._update_debt(_debt_token)

    assert _amount <= self._available_liquidity(_debt_token), "not enough liquidity"

    debt_shares: uint256 = self._amount_to_debt_shares(_debt_token, _amount)

    self.total_debt_amount[_debt_token] += _amount
    self.total_debt_shares[_debt_token] += debt_shares

    return debt_shares


@internal
def _repay(_debt_token: address, _amount: uint256) -> uint256:
    self._update_debt(_debt_token)

    debt_shares: uint256 = self._amount_to_debt_shares(_debt_token, _amount)

    self.total_debt_amount[_debt_token] -= _amount
    self.total_debt_shares[_debt_token] -= debt_shares

    return debt_shares


@internal
def _update_debt(_debt_token: address):
    """
    @notice
        Accounts for any accrued interest since the last update.
    """
    if block.timestamp == self.last_debt_update[_debt_token]:
        return  # already up to date, nothing to do

    self.last_debt_update[_debt_token] = block.timestamp
    
    if self.total_debt_amount[_debt_token] == 0:
        return # no debt, no interest

    self.total_debt_amount[_debt_token] += self._debt_interest_since_last_update(
        _debt_token
    )

@internal
@view
def _debt_interest_since_last_update(_debt_token: address) -> uint256:
    return (
        (block.timestamp - self.last_debt_update[_debt_token])
        * self._current_interest_per_second(_debt_token)
        * self.total_debt_amount[_debt_token]
        / PERCENTAGE_BASE
        / PRECISION
    )

@internal
@view
def _amount_to_debt_shares(_debt_token: address, _amount: uint256) -> uint256:
    # initial shares == wei * PRECISION
    if self.total_debt_shares[_debt_token] == 0:
        return _amount * PRECISION

    new_shares: uint256 = (
        _amount * PRECISION * PRECISION / self._amount_per_debt_share(_debt_token)
    )
    return new_shares


@external
@view
def debt_shares_to_amount(_debt_token: address, _shares: uint256) -> uint256:
    return self._debt_shares_to_amount(_debt_token, _shares)


@internal
@view
def _debt_shares_to_amount(
    _debt_token: address,
    _shares: uint256,
) -> uint256:
    if _shares == 0:
        return 0

    return _shares * self._amount_per_debt_share(_debt_token) / PRECISION / PRECISION


@internal
@view
def _amount_per_debt_share(_debt_token: address) -> uint256:
    # @dev returns extra 18 decimals for precision!
    return (
        self._total_debt_plus_pending_interest(_debt_token)
        * PRECISION
        * PRECISION
        / self.total_debt_shares[_debt_token]
    )


@internal
@view
def _total_debt_plus_pending_interest(_debt_token: address) -> uint256:
    return self.total_debt_amount[_debt_token] + self._debt_interest_since_last_update(
        _debt_token
    )


@external
@view
def debt(_position_uid: bytes32) -> uint256:
    """
    @notice
        Returns the current debt amount a position has accrued
        (inital debt borrowed + interest).
    """
    return self._debt(_position_uid)


@internal
@view
def _debt(_position_uid: bytes32) -> uint256:
    return self._debt_shares_to_amount(
        self.positions[_position_uid].debt_token,
        self.positions[_position_uid].debt_shares,
    )


@external
@view
def position_amount(_position_uid: bytes32) -> uint256:
    """
    @notice
        Returns the amount of underlying position_token
        the position is backed by.
    """
    return self.positions[_position_uid].position_amount


#####################################
#
#             INTEREST
#
#####################################

@external
@view
def current_interest_per_second(_debt_token: address) -> uint256:
    return self._current_interest_per_second(_debt_token)

@internal
@view
def _current_interest_per_second(_debt_token: address) -> uint256:
    utilization_rate: uint256 = self._utilization_rate(_debt_token) 
    interest_rate: uint256 = self._interest_rate_by_utilization(
        _debt_token, utilization_rate
    )
    interest_per_second: uint256 = interest_rate * PRECISION / SECONDS_PER_YEAR
    return interest_per_second

@internal
@view
def _utilization_rate(_debt_token: address) -> uint256:
    """
    @notice
        Returns the current utilization rate of _debt_token
        (liquidity provided vs amount borrowed).
    """
    return (
        (
            PRECISION
            - (
                self._available_liquidity(_debt_token)
                * PRECISION
                / self._total_liquidity(_debt_token)
            )
        )
        * PERCENTAGE_BASE_HIGH_PRECISION
        / PRECISION
    )

@internal
@view
def _interest_rate_by_utilization(
    _address: address, _utilization_rate: uint256
) -> uint256:
    """
    @notice
        we have two tiers of interest rates that are linearily growing from
        _min_interest_rate to _mid_interest_rate and _mid_interest_rate to
        _max_interest_rate respectively. The switch between both occurs at
        _rate_switch_utilization

        note: the slope of the first line must be lower then the second line, if
        not the contact will revert
    """
    if _utilization_rate < self._rate_switch_utilization(_address):
        return self._dynamic_interest_rate_low_utilization(_address, _utilization_rate)
    else:
        return self._dynamic_interest_rate_high_utilization(_address, _utilization_rate)


@internal
@view
def _dynamic_interest_rate_low_utilization(
    _address: address, _utilization_rate: uint256
) -> uint256:
    # if it's zero we return the min-interest-rate without calculation
    if _utilization_rate == 0:
        return self._min_interest_rate(_address)

    # default line-equation y = mx + d where m is the slope, x is
    # _utilization_rate and d is the min_interest_rate, the staring point at 0
    # utilization thus y = _slope * _utilization_rate -_diff

    # first part of the equation mx
    _additional_rate_through_utilization: uint256 = (
        PRECISION
        * _utilization_rate
        * (self._mid_interest_rate(_address) - self._min_interest_rate(_address))
        / self._rate_switch_utilization(_address)
    )

    # first part of the equation d + mx
    return (
        self._min_interest_rate(_address) * PRECISION
        + _additional_rate_through_utilization
    ) / PRECISION


@internal
@view
def _dynamic_interest_rate_high_utilization(
    _address: address, _utilization_rate: uint256
) -> uint256:
    # if it's smaller switch zero we return the min-interest-rate without
    # calculation
    if _utilization_rate < self._rate_switch_utilization(_address):
        return self._mid_interest_rate(_address)

    # default line-equation y = mx + d where m is _slope, x is _utilization_rate
    # and m  is _diff
    # thus y = _slope * _utilization_rate -_diff
    _slope: uint256 = (
        (self._max_interest_rate(_address) - self._mid_interest_rate(_address))
        * PRECISION
        / (FULL_UTILIZATION - self._rate_switch_utilization(_address))
    )

    _diff: uint256 = (
        _slope * PERCENTAGE_BASE_HIGH_PRECISION
        - self._max_interest_rate(_address) * PRECISION
    )
    _additional_rate_through_utilization: uint256 = _slope * _utilization_rate - _diff

    return _additional_rate_through_utilization / PRECISION



@internal
@view
def _interest_configuration(_address: address) -> uint256[4]:
    if (
        self.interest_configuration[_address][0] != 0
        and self.interest_configuration[_address][1] != 0
        and self.interest_configuration[_address][2] != 0
        and self.interest_configuration[_address][3] != 0
    ):
        return FALLBACK_INTEREST_CONFIGURATION

    return self.interest_configuration[_address]


@internal
@view
def _min_interest_rate(_address: address) -> uint256:
    if self.interest_configuration[_address][0] == 0:
        return FALLBACK_INTEREST_CONFIGURATION[0]

    return self.interest_configuration[_address][0]


@internal
@view
def _mid_interest_rate(_address: address) -> uint256:
    if self.interest_configuration[_address][1] == 0:
        return FALLBACK_INTEREST_CONFIGURATION[1]

    return self.interest_configuration[_address][1]


@internal
@view
def _max_interest_rate(_address: address) -> uint256:
    if self.interest_configuration[_address][2] == 0:
        return FALLBACK_INTEREST_CONFIGURATION[2]
    return self.interest_configuration[_address][2]


@internal
@view
def _rate_switch_utilization(_address: address) -> uint256:
    if self.interest_configuration[_address][3] == 0:
        return FALLBACK_INTEREST_CONFIGURATION[3]
    return self.interest_configuration[_address][3]


#####################################
#
#          TRADING FEES 
#
#####################################


event TradingFeeDistributed:
    receiver: address
    token: address
    amount: uint256


@internal
def _distribute_trading_fee(_token: address, _amount: uint256):
    """
    @notice
        Distributes _amount of _token between LPs and protocol.
    """
    amount_for_lps: uint256 = _amount * self.trading_fee_lp_share / PERCENTAGE_BASE
    amount_for_protocol: uint256 = _amount - amount_for_lps

    if amount_for_lps > 0:
        self._pay_interest_to_lps(_token, amount_for_lps)
        log TradingFeeDistributed(0x0000000000000000000000000000000000000001, _token, amount_for_lps) # special address logged to signal LPs
    
    if amount_for_protocol > 0:
        self._safe_transfer(_token, self.protocol_fee_receiver, amount_for_protocol)
        log TradingFeeDistributed(self.protocol_fee_receiver, _token, amount_for_protocol)


#####################################
#
#               UTIL 
#
#####################################


@internal
def _generate_uid() -> bytes32:
    uid: bytes32 = keccak256(_abi_encode(chain.id, self.uid_nonce, block.timestamp))
    self.uid_nonce += 1
    return uid


@internal
def _safe_transfer(_token: address, _to: address, _amount: uint256) -> bool:
    res: Bytes[32] = raw_call(
        _token,
        concat(
            method_id("transfer(address,uint256)"),
            convert(_to, bytes32),
            convert(_amount, bytes32),
        ),
        max_outsize=32,
    )
    if len(res) > 0:
        assert convert(res, bool), "transfer failed"

    return True


@internal
def _safe_transfer_from(
    _token: address, _from: address, _to: address, _amount: uint256
):
    res: Bytes[32] = raw_call(
        _token,
        concat(
            method_id("transferFrom(address,address,uint256)"),
            convert(_from, bytes32),
            convert(_to, bytes32),
            convert(_amount, bytes32),
        ),
        max_outsize=32,
    )
    if len(res) > 0:
        assert convert(res, bool), "transfer failed"


@nonreentrant("lock")
@external
def repay_bad_debt(_token: address, _amount: uint256):
    """
    @notice
        Allows to repay bad_debt in case it was accrued.
    """
    self.bad_debt[_token] -= _amount
    self._safe_transfer_from(_token, msg.sender, self, _amount)


#####################################
#
#              ADMIN 
#
#####################################

event NewAdminSuggested:
    new_admin: indexed(address)
    suggested_by: indexed(address)

@external
def suggest_admin(_new_admin: address):
    """
    @notice
        Step 1 of the 2 step process to transfer adminship.
        Current admin suggests a new admin.
        Requires the new admin to accept adminship in step 2.
    @param _new_admin
        The address of the new admin.
    """
    assert msg.sender == self.admin, "unauthorized"
    assert _new_admin != empty(address), "cannot set admin to zero address"
    self.suggested_admin = _new_admin
    log NewAdminSuggested(_new_admin, msg.sender)


event AdminTransferred:
    new_admin: indexed(address)
    promoted_by: indexed(address)

@external
def accept_admin():
    """
    @notice
        Step 2 of the 2 step process to transfer admin.
        The suggested admin accepts the transfer and becomes the
        new admin.
    """
    assert msg.sender == self.suggested_admin, "unauthorized"
    prev_admin: address = self.admin
    self.admin = self.suggested_admin
    log AdminTransferred(self.admin, prev_admin)


@external
def set_is_accepting_new_orders(_is_accepting_new_orders: bool):
    """
    @notice
        Allows admin to put protocol in defensive or winddown mode.
        Open Positions can still be managed but no new positions are accepted.
    """
    assert msg.sender == self.admin, "unauthorized"
    self.is_accepting_new_orders = _is_accepting_new_orders


#
# allowed tokens & markets
#
@external
def whitelist_token(_token: address, _token_to_usd_oracle: address) -> uint256:
    assert msg.sender == self.admin, "unauthorized"
    assert self.is_whitelisted_token[_token] == False, "already whitelisted"

    self.is_whitelisted_token[_token] = True
    self.to_usd_oracle[_token] = _token_to_usd_oracle

    return self._to_usd_oracle_price(_token)


@external
def remove_token_from_whitelist(_token: address):
    assert msg.sender == self.admin, "unauthorized"
    assert self.is_whitelisted_token[_token] == True, "not whitelisted"
    self.to_usd_oracle[_token] = empty(address)
    self.is_whitelisted_token[_token] = False


@external
def enable_market(_token1: address, _token2: address, _max_leverage: uint256):
    assert msg.sender == self.admin, "unauthorized"
    assert (self.is_whitelisted_token[_token1] and self.is_whitelisted_token[_token2]), "invalid token"
    self.is_enabled_market[_token1][_token2] = True
    self.max_leverage[_token1][_token2] = _max_leverage


@external
def set_max_leverage_for_market(
    _token1: address, _token2: address, _max_leverage: uint256
):
    assert msg.sender == self.admin, "unauthorized"
    self.max_leverage[_token1][_token2] = _max_leverage


@external
def set_liquidate_slippage_for_market(
    _token1: address, _token2: address, _slippage: uint256
):
    assert msg.sender == self.admin, "unauthorized"
    self.liquidate_slippage[_token1][_token2] = _slippage


#
# fees
#
@external
def set_trade_open_fee(_fee: uint256):
    assert msg.sender == self.admin, "unauthorized"
    self.trade_open_fee = _fee


@external
def set_liquidation_penalty(_penalty: uint256):
    assert msg.sender == self.admin, "unauthorized"
    assert _penalty <= PERCENTAGE_BASE, "cannot be more thann 100%"
    self.liquidation_penalty = _penalty


@external
def set_safety_module_interest_share_percentage(_percentage: uint256):
    assert msg.sender == self.admin, "unauthorized"
    assert _percentage <= PERCENTAGE_BASE, "cannot be more thann 100%"
    self.safety_module_interest_share_percentage = _percentage


@external
def set_trading_fee_lp_share(_percentage: uint256):
    assert msg.sender == self.admin, "unauthorized"
    assert _percentage <= PERCENTAGE_BASE, "cannot be more thann 100%"
    self.trading_fee_lp_share = _percentage


#
# addresses
#
@external
def set_protocol_fee_receiver(_receiver: address):
    assert msg.sender == self.admin, "unauthorized"
    self.protocol_fee_receiver = _receiver


@external
def set_is_whitelisted_dex(_dex: address, _whitelisted: bool):
    assert msg.sender == self.admin, "unauthorized"
    self.is_whitelisted_dex[_dex] = _whitelisted


@external
def set_swap_router(_swap_router: address):
    assert msg.sender == self.admin, "unauthorized"
    self.swap_router = _swap_router


#
# config
#
@external
def set_withdraw_liquidity_cooldown(_seconds: uint256):
    assert msg.sender == self.admin, "unauthorized"
    self.withdraw_liquidity_cooldown = _seconds


@external
def set_variable_interest_parameters(
    _address: address,
    _min_interest_rate: uint256,
    _mid_interest_rate: uint256,
    _max_interest_rate: uint256,
    _rate_switch_utilization: uint256,
):
    assert msg.sender == self.admin, "unauthorized"
    self.interest_configuration[_address] = [
        _min_interest_rate,
        _mid_interest_rate,
        _max_interest_rate,
        _rate_switch_utilization,
    ]
