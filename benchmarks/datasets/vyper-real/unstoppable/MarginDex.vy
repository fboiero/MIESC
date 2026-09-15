# @version ^0.3.7

###################################################################
#
# @title Unstoppable Margin DEX - Trading Logic
# @license GNU AGPLv3
# @author unstoppable.ooo
#
# @custom:security-contact team@unstoppable.ooo
#
# @notice
#    This contract is part of the Unstoppable Margin DEX.
#
#    It is the main contract traders interact with in order
#    to create leveraged 1:1 backed spot trades.
#    
#    It allows users to open trades, manage their trades and 
#    use advanced features like Limit Orders, Stop Loss & Take
#    Profit orders.
#
###################################################################

from vyper.interfaces import ERC20

PRECISION: constant(uint256) = 10**18
PERCENTAGE_BASE: constant(uint256) = 10000 # == 100%



# VAULT
interface Vault:
    def open_position(
        _account: address, 
        _position_token: address,
        _min_position_amount_out: uint256,
        _debt_token: address, 
        _debt_amount: uint256,
        _margin_amount: uint256
    ) -> (bytes32, uint256): nonpayable
    def close_position(_position_uid: bytes32, _min_amount_out: uint256) -> uint256: nonpayable
    def reduce_position(_position_uid: bytes32, _reduce_by_amount: uint256, _min_amount_out: uint256) -> uint256: nonpayable
    def liquidate(_position_uid: bytes32): nonpayable
    def is_enabled_market(_token1: address, _token2: address) -> bool: view
    def debt(_position_uid: bytes32) -> uint256: view
    def position_amount(_position_uid: bytes32) -> uint256: view
    def add_margin(_position_uid: bytes32, _amount: uint256): nonpayable
    def remove_margin(_position_uid: bytes32, _amount: uint256): nonpayable
    def effective_leverage(_position_uid: bytes32) -> uint256: view
    def current_exchange_rate(_position_uid: bytes32) -> uint256: view
    def is_liquidatable(_position_uid: bytes32) -> bool: view
    def swap_margin(_account: address, _token_in: address, _token_out: address, _amount_in: uint256, _min_amount_out: uint256) -> uint256: nonpayable

vault: public(address)


#################
#    TRADING
#################
struct TakeProfitOrder:
    reduce_by_amount: uint256
    min_amount_out: uint256
    executed: bool

struct StopLossOrder:
    trigger_price: uint256
    reduce_by_amount: uint256
    executed: bool

struct Trade:
    uid: bytes32
    account: address
    vault_position_uid: bytes32
    tp_orders: DynArray[TakeProfitOrder, 8]
    sl_orders: DynArray[StopLossOrder, 8]

struct LimitOrder:
    uid: bytes32
    account: address
    position_token: address
    min_position_amount_out: uint256
    debt_token: address
    margin_amount: uint256
    debt_amount: uint256
    valid_until: uint256
    tp_orders: DynArray[TakeProfitOrder, 8]
    sl_orders: DynArray[StopLossOrder, 8]


# uid -> LimitOrder
limit_orders: public(HashMap[bytes32, LimitOrder])
# account -> LimitOrder
limit_order_uids: public(HashMap[address, DynArray[bytes32, 1024]])

uid_nonce: uint256
# account -> Trade.uid
trades_by_account: public(HashMap[address, DynArray[bytes32, 1024]])
# uid -> Trade
open_trades: public(HashMap[bytes32, Trade])

# owner -> delegate accounts
is_delegate: public(HashMap[address, HashMap[address, bool]])

admin: public(address)
suggested_admin: public(address)

is_accepting_new_orders: public(bool)


@external
def __init__():
    self.admin = msg.sender


#####################################
#
#              TRADING
#
#####################################


event TradeOpened:
    account: indexed(address)
    uid: bytes32
    trade: Trade

@nonpayable
@external
def open_trade(
    _account: address,
    _position_token: address,
    _min_position_amount_out: uint256,
    _debt_token: address,
    _debt_amount: uint256,
    _margin_amount: uint256,
    _tp_orders: DynArray[TakeProfitOrder, 8],
    _sl_orders: DynArray[StopLossOrder, 8],
) -> Trade:
    assert (_account == msg.sender) or self.is_delegate[_account][msg.sender], "unauthorized"

    return self._open_trade(
        _account,
        _position_token,
        _min_position_amount_out,
        _debt_token,
        _debt_amount,
        _margin_amount,
        _tp_orders,
        _sl_orders,
    )


@internal
def _open_trade(
    _account: address,
    _position_token: address,
    _min_position_amount_out: uint256,
    _debt_token: address,
    _debt_amount: uint256,
    _margin_amount: uint256,
    _tp_orders: DynArray[TakeProfitOrder, 8],
    _sl_orders: DynArray[StopLossOrder, 8],
) -> Trade:
    """
    @notice
        Creates a new Trade for user by opening a
        leveraged spot position in the Vault.

        Requires the user to have a positive margin
        balance in the Vault.
        Requires liquidity to be available in the Vault.

        All trades and their underlying positions are
        fully isolated.
    """
    buy_amount: uint256 = _debt_amount + _margin_amount

    position_uid: bytes32 = empty(bytes32)
    amount_bought: uint256 = 0
    (position_uid, amount_bought) = Vault(self.vault).open_position(
        _account,
        _position_token,
        _min_position_amount_out,
        _debt_token,
        _debt_amount,
        _margin_amount,
    )

    trade: Trade = Trade(
        {
            uid: position_uid,
            account: _account,
            vault_position_uid: position_uid,
            tp_orders: _tp_orders,
            sl_orders: _sl_orders,
        }
    )

    self.open_trades[position_uid] = trade
    self.trades_by_account[_account].append(position_uid)

    log TradeOpened(_account, position_uid, trade)
    return trade


@external
def close_trade(_trade_uid: bytes32, _min_amount_out: uint256) -> uint256:
    trade: Trade = self.open_trades[_trade_uid]
    assert (trade.account == msg.sender) or self.is_delegate[trade.account][msg.sender], "unauthorized"

    return self._full_close(trade, _min_amount_out)

event TradeClosed:
    account: indexed(address)
    uid: bytes32
    trade: Trade
    amount_received: uint256


@nonreentrant("lock")
@internal
def _full_close(_trade: Trade, _min_amount_out: uint256) -> uint256:
    """
    @notice
        Completely closes the underlying Vault Position, repays all debt
        and accrued interest and credits/debits the users Vault margin 
        with the remaining pnl.
    """
    amount_out_received: uint256 = Vault(self.vault).close_position(
        _trade.vault_position_uid, _min_amount_out
    )

    # cleanup trade
    self.open_trades[_trade.uid] = empty(Trade)
    uids: DynArray[bytes32, 1024] = self.trades_by_account[_trade.account]
    for i in range(1024):
        if uids[i] == _trade.uid:
            uids[i] = uids[len(uids) - 1]
            uids.pop()
            break
        if i == len(uids) - 1:
            raise
    self.trades_by_account[_trade.account] = uids

    log TradeClosed(_trade.account, _trade.uid, _trade, amount_out_received)
    return amount_out_received


event TradeReduced:
    account: indexed(address)
    uid: bytes32
    trade: Trade
    amount_received: uint256


@external
def partial_close_trade(
    _trade_uid: bytes32, _reduce_by_amount: uint256, _min_amount_out: uint256
):
    trade: Trade = self.open_trades[_trade_uid]
    assert (trade.account == msg.sender) or self.is_delegate[trade.account][msg.sender], "unauthorized"
    self._partial_close(trade, _reduce_by_amount, _min_amount_out)


@internal
def _partial_close(
    _trade: Trade, _reduce_by_amount: uint256, _min_amount_out: uint256
) -> uint256:
    """
    @notice
        Partially closes the Trade by selling some of the underlying
        asset to repay some of the debt and reclaim some of the margin.
    """
    amount_out_received: uint256 = Vault(self.vault).reduce_position(
        _trade.vault_position_uid, _reduce_by_amount, _min_amount_out
    )

    log TradeReduced(_trade.account, _trade.uid, _trade, amount_out_received)
    return amount_out_received


@view
@external
def get_all_open_trades(_account: address) -> DynArray[Trade, 1024]:
    uids: DynArray[bytes32, 1024] = self.trades_by_account[_account]
    trades: DynArray[Trade, 1024] = empty(DynArray[Trade, 1024])

    for uid in uids:
        trades.append(self.open_trades[uid])

    return trades


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
        Allows a user to easily swap between his margin balances.
    """
    assert (_account == msg.sender) or self.is_delegate[_account][msg.sender], "unauthorized"

    return Vault(self.vault).swap_margin(
        _account, _token_in, _token_out, _amount_in, _min_amount_out
    )


#####################################
#
#    CONDITIONAL ORDERS - TP/SL
#
#####################################


event TpOrderAdded:
    trade_uid: bytes32
    order: TakeProfitOrder


event SlOrderAdded:
    trade_uid: bytes32
    order: StopLossOrder


@external
def add_tp_order(_trade_uid: bytes32, _tp_order: TakeProfitOrder):
    """
    @notice
        Adds a new TakeProfit order to an already open trade.
    """
    trade: Trade = self.open_trades[_trade_uid]
    assert (trade.account == msg.sender) or self.is_delegate[trade.account][msg.sender], "unauthorized"
    assert self.is_accepting_new_orders, "paused"

    assert _tp_order.reduce_by_amount > 0, "amount must be set"

    tp_order: TakeProfitOrder = _tp_order
    tp_order.executed = False
    trade.tp_orders.append(tp_order)

    self.open_trades[_trade_uid] = trade

    log TpOrderAdded(_trade_uid, tp_order)


@external
def add_sl_order(_trade_uid: bytes32, _sl_order: StopLossOrder):
    """
    @notice
        Adds a new StopLoss order to an already open trade.
    """
    trade: Trade = self.open_trades[_trade_uid]
    assert (trade.account == msg.sender) or self.is_delegate[trade.account][msg.sender], "unauthorized"
    assert self.is_accepting_new_orders, "paused"

    assert _sl_order.reduce_by_amount > 0, "amount must be set"

    sl_order: StopLossOrder = _sl_order
    sl_order.executed = False
    trade.sl_orders.append(sl_order)

    self.open_trades[_trade_uid] = trade

    log SlOrderAdded(_trade_uid, sl_order)


event TpExecuted:
    trade_uid: bytes32
    reduce_by_amount: uint256
    amount_out_received: uint256


@external
def execute_tp_order(_trade_uid: bytes32, _tp_order_index: uint8):
    """
    @notice
        Allows a TakeProfit order to be executed.
        Any msg.sender may execute conditional orders for all accounts.
        The specified min_amount_out ensures TakeProfit orders
        are only executed when intended.
    """
    trade: Trade = self.open_trades[_trade_uid]

    tp_order: TakeProfitOrder = trade.tp_orders[_tp_order_index]

    assert tp_order.executed == False, "order already executed"

    tp_order.executed = True
    trade.tp_orders[_tp_order_index] = tp_order
    self.open_trades[_trade_uid] = trade

    position_amount: uint256 = Vault(self.vault).position_amount(
        trade.vault_position_uid
    )
    amount_out_received: uint256 = 0
    if tp_order.reduce_by_amount == position_amount:
        amount_out_received = self._full_close(trade, tp_order.min_amount_out)
    else:
        amount_out_received = self._partial_close(
            trade, tp_order.reduce_by_amount, tp_order.min_amount_out
        )

    log TpExecuted(_trade_uid, tp_order.reduce_by_amount, amount_out_received)


event SlExecuted:
    trade_uid: bytes32
    reduce_by_amount: uint256
    amount_out_received: uint256


@external
def execute_sl_order(_trade_uid: bytes32, _sl_order_index: uint8):
    """
    @notice
        Allows a StopLoss order to be executed.
        Any msg.sender may execute conditional orders for all accounts.
        The specified trigger_price and Chainlink based current_exchange_rate 
        ensures orders are only executed when intended.
    """
    trade: Trade = self.open_trades[_trade_uid]

    sl_order: StopLossOrder = trade.sl_orders[_sl_order_index]

    current_exchange_rate: uint256 = Vault(self.vault).current_exchange_rate(
        trade.vault_position_uid
    )
    assert sl_order.trigger_price >= current_exchange_rate, "trigger price not reached"
    assert sl_order.executed == False, "order already executed"

    sl_order.executed = True
    trade.sl_orders[_sl_order_index] = sl_order
    self.open_trades[_trade_uid] = trade

    position_amount: uint256 = Vault(self.vault).position_amount(
        trade.vault_position_uid
    )

    amount_out_received: uint256 = 0
    if sl_order.reduce_by_amount >= position_amount:
        amount_out_received = self._full_close(trade, 0)
    else:
        amount_out_received = self._partial_close(trade, sl_order.reduce_by_amount, 0)

    log SlExecuted(_trade_uid, sl_order.reduce_by_amount, amount_out_received)


event TpRemoved:
    trade: Trade


@external
def cancel_tp_order(_trade_uid: bytes32, _tp_order_index: uint8):
    """
    @notice
        Removes a pending TakeProfit order.
    """
    trade: Trade = self.open_trades[_trade_uid]
    assert (trade.account == msg.sender) or self.is_delegate[trade.account][msg.sender], "unauthorized"

    if len(trade.tp_orders) > 1:
        trade.tp_orders[_tp_order_index] = trade.tp_orders[len(trade.tp_orders) - 1]

    trade.tp_orders.pop()
    self.open_trades[_trade_uid] = trade

    log TpRemoved(trade)


event SlRemoved:
    trade: Trade


@external
def cancel_sl_order(_trade_uid: bytes32, _sl_order_index: uint8):
    """
    @notice
        Removes a pending StopLoss order.
    """
    trade: Trade = self.open_trades[_trade_uid]
    assert (trade.account == msg.sender) or self.is_delegate[trade.account][msg.sender], "unauthorized"

    if len(trade.sl_orders) > 1:
        trade.sl_orders[_sl_order_index] = trade.sl_orders[len(trade.sl_orders) - 1]

    trade.sl_orders.pop()
    self.open_trades[_trade_uid] = trade

    log SlRemoved(trade)


#####################################
#
#           LIMIT ORDERS
#
#####################################


event LimitOrderPosted:
    uid: bytes32
    account: indexed(address)
    token_in: indexed(address)
    token_out: indexed(address)
    amount_in: uint256
    min_amount_out: uint256
    valid_until: uint256


@external
def post_limit_order(
    _account: address,
    _position_token: address,
    _debt_token: address,
    _margin_amount: uint256,
    _debt_amount: uint256,
    _min_amount_out: uint256,
    _valid_until: uint256,
    _tp_orders: DynArray[TakeProfitOrder, 8],
    _sl_orders: DynArray[StopLossOrder, 8],
) -> LimitOrder:
    """
    @notice
        Allows users to post a LimitOrder that can open a Trade
        under specified conditions.
    """
    assert self.is_accepting_new_orders, "not accepting new orders"
    assert (_account == msg.sender) or self.is_delegate[_account][msg.sender], "unauthorized"

    assert Vault(self.vault).is_enabled_market(_debt_token, _position_token)
    assert _margin_amount > 0, "invalid margin amount"
    assert _debt_amount > _margin_amount, "invalid debt amount"

    uid: bytes32 = self._generate_uid()

    limit_order: LimitOrder = LimitOrder(
        {
            uid: uid,
            account: _account,
            position_token: _position_token,
            min_position_amount_out: _min_amount_out,
            debt_token: _debt_token,
            margin_amount: _margin_amount,
            debt_amount: _debt_amount,
            valid_until: _valid_until,
            tp_orders: _tp_orders,
            sl_orders: _sl_orders,
        }
    )

    self.limit_orders[uid] = limit_order
    self.limit_order_uids[_account].append(uid)

    amount_in: uint256 = _margin_amount + _debt_amount
    log LimitOrderPosted(uid, _account, _debt_token, _position_token, amount_in, _min_amount_out, _valid_until)

    return limit_order


event LimitOrderExecuted:
    account: indexed(address)
    trade: Trade


@external
def execute_limit_order(_uid: bytes32):
    """
    @notice
        Allows executing a pending LimitOrder.
        Any msg.sender may execute LimitOrders for all accounts.
        The specified min_amount_out ensures the Trade is only
        opened at the intended exchange rate / price.
    """
    assert self.is_accepting_new_orders, "not accepting new orders"
 
    limit_order: LimitOrder = self.limit_orders[_uid]
    assert limit_order.valid_until >= block.timestamp, "expired"

    self.limit_orders[_uid] = empty(LimitOrder)
    
    trade: Trade = self._open_trade(
        limit_order.account,
        limit_order.position_token,
        limit_order.min_position_amount_out,
        limit_order.debt_token,
        limit_order.debt_amount,
        limit_order.margin_amount,
        limit_order.tp_orders,
        limit_order.sl_orders
    )

    self._remove_limit_order(_uid)

    log LimitOrderExecuted(trade.account, trade)


event LimitOrderCancelled:
    account: indexed(address)
    uid: bytes32


@external
def cancel_limit_order(_uid: bytes32):
    """
    @notice
        Removes a pending LimitOrder.
    """
    order: LimitOrder = self.limit_orders[_uid]
    assert (order.account == msg.sender) or self.is_delegate[order.account][msg.sender], "unauthorized"

    self._remove_limit_order(_uid)

    log LimitOrderCancelled(order.account, _uid)


@internal
def _remove_limit_order(_uid: bytes32):
    order: LimitOrder = self.limit_orders[_uid]
    self.limit_orders[_uid] = empty(LimitOrder)

    uids: DynArray[bytes32, 1024] = self.limit_order_uids[order.account]
    for i in range(1024):
        if uids[i] == _uid:
            uids[i] = uids[len(uids) - 1]
            uids.pop()
            break
        if i == len(uids) - 1:
            raise
    self.limit_order_uids[order.account] = uids


#####################################
#
#           LIQUIDATIONS
#
#####################################

@view
@external
def is_liquidatable(_trade_uid: bytes32) -> bool:
    """
    @notice
        Trades are leveraged and based on an undercollateralized
        loan in the Vault Position.
        If the Trades effective leverage exceeds the maximum allowed
        leverage for that market, the Trade and its underlying Vault
        Position become liquidatable.
    """
    return self._is_liquidatable(_trade_uid)

@view
@internal
def _is_liquidatable(_trade_uid: bytes32) -> bool:
    trade: Trade = self.open_trades[_trade_uid]
    return Vault(self.vault).is_liquidatable(trade.vault_position_uid)


event Liquidation:
    account: indexed(address)
    uid: bytes32
    trade: Trade


@nonreentrant("lock")
@external
def liquidate(_trade_uid: bytes32):
    """
    @notice
        Allows to liquidate a Trade that exceeds the maximum
        allowed leverage.
    """
    trade: Trade = self.open_trades[_trade_uid]
    Vault(self.vault).liquidate(trade.vault_position_uid)
    log Liquidation(trade.account, _trade_uid, trade)


#####################################
#
#     LEVERAGE & TRADE HEALTH
#
#####################################

@view
@external
def effective_leverage(_trade_uid: bytes32) -> uint256:
    return self._effective_leverage(_trade_uid)

@view
@internal
def _effective_leverage(_trade_uid: bytes32) -> uint256:
    trade: Trade = self.open_trades[_trade_uid]
    return Vault(self.vault).effective_leverage(trade.vault_position_uid)

@external
def add_margin(_trade_uid: bytes32, _amount: uint256):
    """
    @notice
        Allows traders to add additional margin to a Trades underlying
        Vault position and reduce the leverage.
    """
    trade: Trade = self.open_trades[_trade_uid]
    assert (trade.account == msg.sender) or self.is_delegate[trade.account][msg.sender], "unauthorized"

    Vault(self.vault).add_margin(trade.vault_position_uid, _amount)


@external
def remove_margin(_trade_uid: bytes32, _amount: uint256):
    """
    @notice
        Allows traders to remove excess margin from a Trades underlying
        Vault position and increase leverage.
    """
    trade: Trade = self.open_trades[_trade_uid]
    assert (trade.account == msg.sender) or self.is_delegate[trade.account][msg.sender], "unauthorized"

    Vault(self.vault).remove_margin(trade.vault_position_uid, _amount)


#####################################
#
#    ACCOUNT ACCESS & DELEGATION 
#
#
#    @notice
#        Delegates are additional accounts that are allowed
#        to perform trading actions on behalf of a main account.
#        They can open/manage/close trades for another account.
#
#        This allows for example to have a main account protected
#        with a hardware wallet and use a hot wallet for daily trading.
#
#####################################

event DelegateAdded:
    account: indexed(address)
    delegate_account: indexed(address)


@nonpayable
@external
def add_delegate(_delegate: address):
    """
    @notice
        Allows _delegate to perform any trading actions
        on behalf of msg.sender.
    """
    self.is_delegate[msg.sender][_delegate] = True
    log DelegateAdded(msg.sender, _delegate)


event DelegateRemoved:
    account: indexed(address)
    delegate_account: indexed(address)

@nonpayable
@external
def remove_delegate(_delegate: address):
    """
    @notice
        Removes a _delegates permission to execute
        trading actions on behalf of msg.sender.
    """
    self.is_delegate[msg.sender][_delegate] = False
    log DelegateRemoved(msg.sender, _delegate)
    

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
        Open trades can still be completed but no new trades are accepted.
    """
    assert msg.sender == self.admin, "unauthorized"
    self.is_accepting_new_orders = _is_accepting_new_orders


@external
def set_vault(_vault: address):
    """
    @notice
        Sets the corresponding Vault where the assets are located.
    """
    assert msg.sender == self.admin, "unauthorized"
    self.vault = _vault
