# @version 0.3.7

"""
@title Fair Funding Alchemix Vault
@license GNU AGPLv3
@author unstoppable.ooo

@custom:security-contact team@unstoppable.com

@notice
    This vault manages a position on Alchemix.
    Newly deposited WETH will be put into Alchemix and a corresponding
    loan will be taken out and sent to the fund_receiver.

    The Alchemix positions are governed by the referenced ERC721 tokens.

    The owner of the token can at any point liquidate the underlying 
    Alchemix position and receive the remainder of their deposited funds
    back.

    Paid off debt on Alchemix (either manually repaid externally or by the
    self-repaying feature of Alchemix) allows to withdraw parts of the 
    underlying collateral WETH as it becomes available.
    This withdrawn ETH is marked as claimable and each token owner who 
    contributed to the position can claim his share of the unlocked WETH 
    up to the total amount that was initially deposited with this token.

    Over time 100% of the initial collateral will become unlocked at 
    Alchemix and can be permissionlessly withdrawn by anyone to make it
    claimable by the token holders.

    Note:
    We assume the LTV of Alchemix will not change and all positions can
    be considered as having the same collateralisation / LTV.
    In the unlikely case it does change, this contract will be re-deployed 
    with the updated collateralization value for new deposits.

"""

from vyper.interfaces import ERC721
from vyper.interfaces import ERC20

interface IAlchemist:
    def depositUnderlying(
        _yield_token: address,
        _amount: uint256,
        _recipient: address,
        _min_amount_out: uint256
    ) -> uint256: nonpayable
    def mint(
        _amount: uint256,
        _recipient: address
    ): nonpayable
    def withdrawUnderlying(
        _yield_token: address,
        _shares: uint256,
        _recipient: address,
        _min_amount_out: uint256
    ) -> uint256: nonpayable
    def liquidate(
        _yield_token: address,
        _shares: uint256,
        _min_amount_out: uint256
    ) -> uint256: nonpayable
    def getUnderlyingTokensPerShare(
        _yield_token: address
    ) -> uint256: view
    def totalValue(_owner: address) -> uint256: view
    def minimumCollateralization() -> uint256: view
    def accounts(_owner: address) -> (int256, DynArray[address, 8]): view
    def positions(_owner: address, _yield_token: address) -> (uint256, uint256): view
    def normalizeUnderlyingTokensToDebt(
        _underlying_token: address, 
        _amount: uint256
    ) -> uint256: view
    def convertUnderlyingTokensToShares(
        _yield_token: address, 
        _amount: uint256
    ) -> uint256: view
    def convertSharesToUnderlyingTokens(
        _yield_token: address, 
        _shares: uint256
    ) -> uint256: view


interface Migrator:
    def migrate(): nonpayable


PRECISION: constant(uint256) = 10**6
DECIMALS: constant(uint256) = 10**18

ALCX_YVWETH: constant(address) = 0xa258C4606Ca8206D8aA700cE2143D7db854D168c
WETH: constant(address) = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2

NFT: public(immutable(address))

alchemist: public(address)
fund_receiver: public(address)

struct Position:
    token_id: uint256
    amount_deposited: uint256
    amount_claimed: uint256
    shares_owned: uint256
    is_liquidated: bool

positions: public(HashMap[uint256, Position])
total_shares: public(uint256)
amount_claimable_per_share: public(uint256)

is_operator: public(HashMap[address, bool])
is_depositor: public(HashMap[address, bool])


MIGRATION_TIMELOCK: constant(uint256) = 30 * 60 * 60 * 24  # 30 days in seconds
migration_admin: public(address)
suggested_migration_admin: public(address)
migration_active: public(uint256)
migrator: public(address)
migration_executed: public(bool)

event Deposit:
    token_owner: indexed(address)
    token_id: uint256
    amount: uint256

event Funded:
    receiver: indexed(address)
    amount: uint256

event Liquidated:
    token_id: uint256
    token_owner: indexed(address)
    amount: uint256

event Claimable:
    amount: uint256

event Claimed:
    token_id: uint256
    token_owner: indexed(address)
    amount: uint256

event AlchemistUpdated:
    updater: indexed(address)
    new_alchemist: indexed(address)

event FundReceiverUpdated:
    updater: indexed(address)
    new_fund_receiver: indexed(address)

event NewOperator:
    new_operator: indexed(address)
    promoted_by: indexed(address)

event OperatorRemoved:
    removed: indexed(address)
    removed_by: indexed(address)

event NewDepositor:
    new_depositor: indexed(address)
    promoted_by: indexed(address)

event DepositorRemoved:
    removed: indexed(address)
    removed_by: indexed(address)

event MigrationAdminTransferred:
    new_admin: indexed(address)
    promoted_by: indexed(address)

event NewMigrationAdminSuggested:
    new_admin: indexed(address)
    suggested_by: indexed(address)

event MigrationActivated:
    migrator_address: address
    active_at: uint256

event MigrationDeactivated: pass


@external
def __init__(
    _nft_address: address,
):
    assert _nft_address != empty(address), "invalid nft address"
    NFT = _nft_address

    self.is_operator[msg.sender] = True
    self.fund_receiver = msg.sender

    self.migration_active = max_value(uint256)
    self.migration_admin = msg.sender


@nonreentrant("lock")
@external
def register_deposit(_token_id: uint256, _amount: uint256):
    """
    @notice
        Registers a new deposit of _amount for _token_id.
        _amount WETH is deposited into Alchemix and a corresponding
        loan is taken out and sent to fund_receiver.
    """
    assert self.is_depositor[msg.sender], "not allowed"
    assert self._is_valid_token_id(_token_id)

    position: Position = self.positions[_token_id]
    assert position.is_liquidated == False, "position already liquidated"

    position.token_id = _token_id
    position.amount_deposited += _amount

    # transfer WETH to self
    ERC20(WETH).transferFrom(msg.sender, self, _amount)

    # deposit WETH to Alchemix
    shares_issued: uint256 = self._deposit_to_alchemist(_amount)
    position.shares_owned += shares_issued
    self.total_shares += shares_issued
    
    self.positions[_token_id] = position

    # mint alchemix debt to fund_receiver
    amount_to_mint: uint256 = self._calculate_amount_to_mint(shares_issued)
    assert amount_to_mint > 0, "cannot mint new Alchemix debt"

    self._mint_from_alchemix(amount_to_mint, self.fund_receiver)

    log Deposit(msg.sender, _token_id, _amount)


@internal
@view
def _calculate_amount_to_mint(_amount_shares: uint256) -> uint256:
    return min(self._calculate_mintable_amount(_amount_shares), self._calculate_max_mintable_amount())


@internal
@view
def _calculate_mintable_amount(_amount_shares: uint256) -> uint256:
    """
    @notice
        Calculate the mintable amount of debt tokens given _amount_shares new
        shares as collateral.
        This function does not account for existing debts on Alchemix.
    """
    min_collateralization: uint256 = IAlchemist(self.alchemist).minimumCollateralization()
    amount_shares_collateralized: uint256 = _amount_shares * DECIMALS / min_collateralization
    amount_underlying: uint256 = IAlchemist(self.alchemist).convertSharesToUnderlyingTokens(ALCX_YVWETH, amount_shares_collateralized)
    mintable_debt: uint256 = IAlchemist(self.alchemist).normalizeUnderlyingTokensToDebt(WETH, amount_underlying)
    if mintable_debt > 0:
        mintable_debt -= 1 # to pass "<" collateralisation check on Alchemix
    return mintable_debt



@internal
@view
def _calculate_max_mintable_amount() -> uint256:
    """
    @notice
        Calculate the maximum mintable amount of debt tokens given the current
        collateral and existing debt on Alchemix.
    """
    # Alchemist._validate(): uint256 collateralization = totalValue(owner) * 1e18 / uint256(debt);
    current_debt: uint256 = convert(IAlchemist(self.alchemist).accounts(self)[0], uint256)
    total_value: uint256 = IAlchemist(self.alchemist).totalValue(self)
    min_collateralization: uint256 = IAlchemist(self.alchemist).minimumCollateralization()

    max_mintable_debt: uint256 = total_value * DECIMALS / min_collateralization - current_debt

    if max_mintable_debt > 0:
        max_mintable_debt = max_mintable_debt - 1 # minus 1 for collat < min_collat check @ alchemist._validate
    
    return max_mintable_debt




@internal
def _deposit_to_alchemist(_amount: uint256) -> uint256:
    """
    @notice
        Deposits _amount WETH from this contract into the Alchemix ALCX_YVWETH
        vault. 
    """
    assert self.alchemist != empty(address), "invalid state, alchemist not set"
    
    ERC20(WETH).approve(self.alchemist, _amount)
    shares_issued: uint256 = IAlchemist(self.alchemist).depositUnderlying(
        ALCX_YVWETH,     # yield_token
        _amount,         # amount
        self,            # recipient
        1                # min_amount_out - cannot be frontrun in a significant way
                         #                  so to reduce complexity we go with 1
    )
    return shares_issued


@internal 
def _mint_from_alchemix(_amount: uint256, _recipient: address):
    """
    @notice
        Takes on _amount of debt (in alETH) on Alchemix and transfers it to 
        _recipient.
    """
    IAlchemist(self.alchemist).mint(
        _amount,    # amount
        _recipient  # recipient
    )

    log Funded(_recipient, _amount)


@nonreentrant("lock")
@external
def liquidate(_token_id: uint256, _min_weth_out: uint256) -> uint256:
    """
    @notice
        Liquidates the underlying debt of position[_token_id] by burning
        a corresponding amount of shares.
        Withdraws remaining value of shares as WETH to token_owner.
        Reverts if owner would receive less than _min_weth_out.
    """
    token_owner: address = ERC721(NFT).ownerOf(_token_id)
    assert token_owner == msg.sender, "only token owner can liquidate"

    position: Position = self.positions[_token_id]
    assert position.is_liquidated == False, "position already liquidated"
    
    position.is_liquidated = True
    self.positions[_token_id] = position
    self.total_shares -= position.shares_owned

    collateralisation: uint256 = self._latest_collateralisation()
    shares_to_liquidate: uint256 = position.shares_owned * DECIMALS / collateralisation

    amount_shares_liquidated: uint256 = IAlchemist(self.alchemist).liquidate(
        ALCX_YVWETH,                 # _yield_token: address,
        shares_to_liquidate,         # _shares: uint256,
        1                            # _min_amount_out: uint256 -> covered by _min_weth_out
    )

    amount_to_withdraw: uint256 = position.shares_owned - amount_shares_liquidated
    # _withdraw_underlying_from_alchemix reverts on < _min_weth_out
    amount_withdrawn: uint256 = self._withdraw_underlying_from_alchemix(amount_to_withdraw, token_owner, _min_weth_out)

    log Liquidated(_token_id, token_owner, amount_withdrawn)
    return amount_withdrawn


@internal
def _latest_collateralisation() -> uint256:
    """
    @notice
        Calculates the current collateral to debt ratio on Alchemix.
        Reverts when there is no debt and collateralisation would be
        infinite.
    """
    # Alchemist._validate(): 
    # uint256 collateralization = totalValue(owner) * FIXED_POINT_SCALAR / uint256(debt);
    current_debt: int256 = IAlchemist(self.alchemist).accounts(self)[0]
    assert current_debt > 0, "zero debt"
    
    total_value: uint256 = IAlchemist(self.alchemist).totalValue(self)
    debt: uint256 = convert(current_debt, uint256)
    return total_value * DECIMALS / debt


@internal
def _withdraw_underlying_from_alchemix(
    _amount_shares: uint256, 
    _receiver: address,
    _min_weth_out: uint256
) -> uint256:
    """
    @notice
        Withdraws _amount_shares to _receiver expecting at least _min_weth_out
    """
    amount_withdrawn: uint256 = IAlchemist(self.alchemist).withdrawUnderlying(
        ALCX_YVWETH,    # _yield_token: address,
        _amount_shares, # _shares: uint256,
        _receiver,      # _recipient: address,
        _min_weth_out   # _min_amount_out: uint256 
    )
    assert amount_withdrawn >= _min_weth_out, "insufficient weth out"
    return amount_withdrawn


@external
def withdraw_underlying_to_claim(_amount_shares: uint256, _min_weth_out: uint256):
    """
    @notice
        Withdraws _amount_shares and _min_weth_out from Alchemix to be distributed
        to token holders.
        The WETH is held in this contract until it is `claim`ed.
    """
    amount_withdrawn: uint256 = self._withdraw_underlying_from_alchemix(_amount_shares, self, _min_weth_out)
    self._mark_as_claimable(amount_withdrawn)

    log Claimable(amount_withdrawn)


@internal
def _mark_as_claimable(_amount: uint256):
    """
    @notice
        Marks _amount of WETH as claimable by token holders and
        calculates the amount_claimable_per_share.
    """
    if _amount == 0 or self.total_shares == 0:
        return

    assert ERC20(WETH).balanceOf(self) >= _amount

    self.amount_claimable_per_share += _amount * PRECISION / self.total_shares
    

@view
@external
def claimable_for_token(_token_id: uint256) -> uint256:
    return self._claimable_for_token(_token_id)


@view
@internal
def _claimable_for_token(_token_id: uint256) -> uint256:
    """
    @notice
        Calculates the pending WETH for a given token_id.
    """
    position: Position = self.positions[_token_id]
    if position.is_liquidated:
        return 0
    
    total_claimable_for_position: uint256 = position.shares_owned * self.amount_claimable_per_share / PRECISION
    return total_claimable_for_position - position.amount_claimed


@external
def claim(_token_id: uint256) -> uint256:
    """
    @notice
        Allows a token holder to claim his share of pending WETH.
    """
    token_owner: address = ERC721(NFT).ownerOf(_token_id)
    assert msg.sender == token_owner, "only token owner can claim"

    amount: uint256 = self._claimable_for_token(_token_id)
    assert amount > 0, "nothing to claim"

    position: Position = self.positions[_token_id]
    position.amount_claimed += amount
    self.positions[_token_id] = position
    
    ERC20(WETH).transfer(token_owner, amount)

    log Claimed(_token_id, token_owner, amount)
    return amount


@internal
def _is_valid_token_id(_token_id: uint256) -> bool:
    """
    @notice
        Checks if the given _token_id exists.
        Reverts if token isn't minted.
    """
    ERC721(NFT).ownerOf(_token_id) # reverts for invalid token_id according to spec
    return True


#######################
#
#        ADMIN
#
#######################

@external
def set_alchemist(_addr: address):
    """
    @notice
        Sets the Alchemix Alchemist contract
    """
    assert self.is_operator[msg.sender], "unauthorized"
    assert _addr != empty(address), "invalid alchemist address"
    assert _addr != self.alchemist, "same as current"

    self.alchemist = _addr

    log AlchemistUpdated(msg.sender, _addr)


@external
def set_fund_receiver(_addr: address):
    """
    @notice
        Sets the fund_receiver address that will receive newly minted
        alETH.
    """
    assert self.is_operator[msg.sender], "unauthorized"
    assert _addr != empty(address), "invalid fund_receiver address"
    assert _addr != self.fund_receiver, "same as current"

    self.fund_receiver = _addr

    log FundReceiverUpdated(msg.sender, _addr)


@external
def activate_migration(_migrator_addr: address):
    """
    @notice
        Sets a migration contract and starts the 30 day timelock before
        migration can be performed.
        Can only be called by the migration_admin.
    """
    assert msg.sender == self.migration_admin, "unauthorized"
    assert self.migrator == empty(address), "cannot override active migration"
    assert _migrator_addr != empty(address), "cannot set migrator to zero address"

    self.migrator = _migrator_addr
    self.migration_active = block.timestamp + MIGRATION_TIMELOCK
    self.migration_executed = False

    log MigrationActivated(_migrator_addr, self.migration_active)


@external
def deactivate_migration():
    """
    @notice
        Stops an activated migration and resets the migration values.
    """
    assert msg.sender == self.migration_admin, "unauthorized"
    self.migration_active = max_value(uint256)
    self.migrator = empty(address)
    
    log MigrationDeactivated()


@external
def migrate():
    """
    @notice
        Calls migrate function on the set migrator contract.
        This is just in case there are severe changes in Alchemix that
        require a full migration of the existing position.
    """
    assert self.migration_active <= block.timestamp, "migration not active"
    assert self.migration_executed == False, "migration already executed"
    self.migration_executed = True
    Migrator(self.migrator).migrate()


@external
def suggest_migration_admin(_new_admin: address):
    """
    @notice
        Step 1 of the 2 step process to transfer migration admin.
        Current owner suggests a new owner.
        Requires the new admin to accept ownership in step 2.
    @param _new_admin
        The address of the new migration admin.
    """
    assert msg.sender == self.migration_admin, "unauthorized"
    assert _new_admin != empty(address), "cannot set migration_admin to zero address"
    self.suggested_migration_admin = _new_admin
    log NewMigrationAdminSuggested(_new_admin, msg.sender)


@external
def accept_migration_admin():
    """
    @notice
        Step 2 of the 2 step process to transfer migration admin.
        The suggested admin accepts the transfer and becomes the
        new migration admin.
    """
    assert msg.sender == self.suggested_migration_admin, "unauthorized"
    prev_admin: address = self.migration_admin
    self.migration_admin = self.suggested_migration_admin
    log MigrationAdminTransferred(self.migration_admin, prev_admin)


@external
def add_operator(_new_operator: address):
    """
    @notice
        Add a new address to the priviledged operators.
    """
    assert self.is_operator[msg.sender], "unauthorized"
    assert self.is_operator[_new_operator] == False, "already operator"

    self.is_operator[_new_operator] = True

    log NewOperator(_new_operator, msg.sender)


@external
def remove_operator(_to_remove: address):
    """
    @notice
        Remove an existing operator from the priviledged addresses.
    """
    assert self.is_operator[msg.sender], "unauthorized"
    assert self.is_operator[_to_remove], "not an operator"

    self.is_operator[_to_remove] = False

    log OperatorRemoved(_to_remove, msg.sender)


@external
def add_depositor(_new_depositor: address):
    """
    @notice
        Add a new address to the priviledged depositors.
    """
    assert self.is_operator[msg.sender], "unauthorized"
    assert self.is_depositor[_new_depositor] == False, "already depositor"

    self.is_depositor[_new_depositor] = True

    log NewDepositor(_new_depositor, msg.sender)


@external
def remove_depositor(_to_remove: address):
    """
    @notice
        Remove an existing depositor from the priviledged addresses.
    """
    assert self.is_operator[msg.sender], "unauthorized"
    assert self.is_depositor[_to_remove], "not an depositor"

    self.is_depositor[_to_remove] = False

    log DepositorRemoved(_to_remove, msg.sender)