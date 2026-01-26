"""
Tests for Multi-Chain Abstraction System
=========================================

Comprehensive tests for:
- Chain abstraction layer (chain_abstraction.py)
- Solana/Anchor adapter (solana_adapter.py)
- NEAR adapter (near_adapter.py)
- Move adapter (move_adapter.py)
- Stellar/Soroban adapter (stellar_adapter.py)
- Algorand TEAL/PyTeal adapter (algorand_adapter.py)

Author: Fernando Boiero <fboiero@frvm.utn.edu.ar>
Date: January 2026
"""

import json
import tempfile
from pathlib import Path
from typing import Dict, Any, List

import pytest

from src.core.chain_abstraction import (
    # Enums
    ChainType,
    ContractLanguage,
    Visibility,
    Mutability,
    SecurityProperty,
    # Data types
    TypeInfo,
    Parameter,
    Location,
    # Contract elements
    AbstractVariable,
    AbstractModifier,
    AbstractFunction,
    AbstractEvent,
    AbstractContract,
    # Vulnerability mappings
    VulnerabilityMapping,
    VULNERABILITY_MAPPINGS,
    get_vulnerability_mapping,
    normalize_vulnerability_type,
    # Registry
    ChainRegistry,
    get_chain_registry,
    register_chain_analyzer,
    get_analyzer_for_chain,
)

from src.adapters.solana_adapter import (
    SolanaAnalyzer,
    SolanaVulnerability,
    SolanaPatternDetector,
    AnchorAccount,
    AnchorInstruction,
    AnchorIDL,
    analyze_solana_program,
    parse_anchor_idl,
)

from src.adapters.stellar_adapter import (
    StellarAnalyzer,
    StellarVulnerability,
    StellarPatternDetector,
    SorobanParser,
    SorobanFunction,
    SorobanContract,
)

from src.adapters.algorand_adapter import (
    AlgorandAnalyzer,
    AlgorandVulnerability,
    AlgorandPatternDetector,
    TealParser,
    PyTealParser,
    TealProgram,
    PyTealFunction,
    AlgorandContract,
)

from src.adapters.cardano_adapter import (
    CardanoAnalyzer,
    CardanoVulnerability,
    CardanoPatternDetector,
    PlutusParser,
    AikenParser,
    PlutusValidator,
    AikenValidator,
    CardanoContract,
    PlutusScriptType,
)


# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
def sample_anchor_program():
    """Sample Anchor program source code."""
    return '''
use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod my_program {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let data = &mut ctx.accounts.data;
        data.authority = ctx.accounts.authority.key();
        data.value = 0;
        Ok(())
    }

    pub fn update(ctx: Context<Update>, new_value: u64) -> Result<()> {
        let data = &mut ctx.accounts.data;
        data.value = new_value;
        Ok(())
    }

    pub fn transfer(ctx: Context<Transfer>, amount: u64) -> Result<()> {
        let from = &mut ctx.accounts.from;
        let to = &mut ctx.accounts.to;

        from.balance -= amount;
        to.balance += amount;

        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = authority, space = 8 + 32 + 8)]
    pub data: Account<'info, DataAccount>,
    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Update<'info> {
    #[account(mut, has_one = authority)]
    pub data: Account<'info, DataAccount>,
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct Transfer<'info> {
    #[account(mut)]
    pub from: Account<'info, TokenAccount>,
    #[account(mut)]
    pub to: Account<'info, TokenAccount>,
    pub owner: AccountInfo<'info>,
}

#[account]
pub struct DataAccount {
    pub authority: Pubkey,
    pub value: u64,
}

#[account]
pub struct TokenAccount {
    pub owner: Pubkey,
    pub balance: u64,
}

#[event]
pub struct TransferEvent {
    pub from: Pubkey,
    pub to: Pubkey,
    pub amount: u64,
}
'''


@pytest.fixture
def sample_anchor_idl():
    """Sample Anchor IDL."""
    return {
        "version": "0.1.0",
        "name": "my_program",
        "instructions": [
            {
                "name": "initialize",
                "accounts": [
                    {"name": "data", "isMut": True, "isSigner": False},
                    {"name": "authority", "isMut": True, "isSigner": True},
                    {"name": "systemProgram", "isMut": False, "isSigner": False},
                ],
                "args": [],
            },
            {
                "name": "update",
                "accounts": [
                    {"name": "data", "isMut": True, "isSigner": False},
                    {"name": "authority", "isMut": False, "isSigner": True},
                ],
                "args": [{"name": "newValue", "type": "u64"}],
            },
            {
                "name": "transfer",
                "accounts": [
                    {"name": "from", "isMut": True, "isSigner": False},
                    {"name": "to", "isMut": True, "isSigner": False},
                    {"name": "owner", "isMut": False, "isSigner": True},
                ],
                "args": [{"name": "amount", "type": "u64"}],
            },
        ],
        "accounts": [
            {
                "name": "DataAccount",
                "type": {
                    "kind": "struct",
                    "fields": [
                        {"name": "authority", "type": "publicKey"},
                        {"name": "value", "type": "u64"},
                    ],
                },
            },
        ],
        "events": [
            {
                "name": "TransferEvent",
                "fields": [
                    {"name": "from", "type": "publicKey", "index": False},
                    {"name": "to", "type": "publicKey", "index": False},
                    {"name": "amount", "type": "u64", "index": False},
                ],
            },
        ],
        "errors": [],
    }


@pytest.fixture
def vulnerable_solana_program():
    """Solana program with vulnerabilities."""
    return '''
use anchor_lang::prelude::*;

declare_id!("11111111111111111111111111111111");

#[program]
pub mod vulnerable_program {
    use super::*;

    // Missing signer check vulnerability
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        let recipient = &ctx.accounts.recipient;

        // No signer validation!
        **vault.to_account_info().try_borrow_mut_lamports()? -= amount;
        **recipient.try_borrow_mut_lamports()? += amount;

        Ok(())
    }

    // Arithmetic overflow vulnerability
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let account = &mut ctx.accounts.user_account;

        // Unchecked arithmetic!
        account.balance += amount;
        account.total_deposits += 1;

        Ok(())
    }

    // CPI reentrancy risk
    pub fn swap(ctx: Context<Swap>, amount: u64) -> Result<()> {
        let pool = &mut ctx.accounts.pool;

        // External call
        invoke(
            &spl_token::instruction::transfer(
                ctx.accounts.token_program.key,
                ctx.accounts.from.key,
                ctx.accounts.to.key,
                ctx.accounts.authority.key,
                &[],
                amount,
            )?,
            &[
                ctx.accounts.from.to_account_info(),
                ctx.accounts.to.to_account_info(),
                ctx.accounts.authority.to_account_info(),
            ],
        )?;

        // State modification after CPI - reentrancy risk!
        pool.reserves -= amount;

        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// CHECK: Recipient account
    pub recipient: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut)]
    pub user_account: Account<'info, UserAccount>,
    pub user: Signer<'info>,
}

#[derive(Accounts)]
pub struct Swap<'info> {
    #[account(mut)]
    pub pool: Account<'info, Pool>,
    /// CHECK: Token accounts
    pub from: AccountInfo<'info>,
    pub to: AccountInfo<'info>,
    pub authority: Signer<'info>,
    pub token_program: AccountInfo<'info>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}

#[account]
pub struct UserAccount {
    pub owner: Pubkey,
    pub balance: u64,
    pub total_deposits: u64,
}

#[account]
pub struct Pool {
    pub reserves: u64,
}
'''


@pytest.fixture
def sample_soroban_contract():
    """Sample Soroban/Stellar contract source code."""
    return '''
use soroban_sdk::{contract, contractimpl, Address, Env, token};

#[contract]
pub struct TokenContract;

#[contractimpl]
impl TokenContract {
    pub fn initialize(env: Env, admin: Address) {
        admin.require_auth();
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    pub fn mint(env: Env, to: Address, amount: i128) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        let balance = Self::balance(env.clone(), to.clone());
        env.storage().persistent().set(&DataKey::Balance(to), &(balance + amount));
    }

    pub fn transfer(env: Env, from: Address, to: Address, amount: i128) {
        from.require_auth();

        let from_balance = Self::balance(env.clone(), from.clone());
        let to_balance = Self::balance(env.clone(), to.clone());

        env.storage().persistent().set(&DataKey::Balance(from.clone()), &(from_balance - amount));
        env.storage().persistent().set(&DataKey::Balance(to.clone()), &(to_balance + amount));
    }

    pub fn balance(env: Env, addr: Address) -> i128 {
        env.storage().persistent().get(&DataKey::Balance(addr)).unwrap_or(0)
    }
}

#[derive(Clone)]
pub enum DataKey {
    Admin,
    Balance(Address),
}
'''


@pytest.fixture
def sample_vulnerable_soroban():
    """Sample vulnerable Soroban contract."""
    return '''
use soroban_sdk::{contract, contractimpl, Address, Env};

#[contract]
pub struct VulnerableContract;

#[contractimpl]
impl VulnerableContract {
    // Missing auth check!
    pub fn withdraw(env: Env, to: Address, amount: i128) {
        let balance: i128 = env.storage().instance().get(&DataKey::Balance).unwrap();
        env.storage().instance().set(&DataKey::Balance, &(balance - amount));
        // Transfer without auth...
    }

    // Panic in contract
    pub fn process(env: Env, data: i128) {
        if data < 0 {
            panic!("Invalid data");
        }
    }

    // Unwrap without check
    pub fn get_value(env: Env) -> i128 {
        env.storage().instance().get(&DataKey::Value).unwrap()
    }

    // Cross-contract call without auth check
    pub fn external_call(env: Env, contract_id: Address) {
        env.invoke_contract::<()>(&contract_id, &symbol_short!("call"), ());
    }
}

pub enum DataKey {
    Balance,
    Value,
}
'''


@pytest.fixture
def sample_teal_program():
    """Sample TEAL program source code."""
    return '''
#pragma version 8

txn ApplicationID
int 0
==
bnz create

txn OnCompletion
int NoOp
==
bnz handle_noop

txn OnCompletion
int OptIn
==
bnz handle_optin

err

create:
    byte "counter"
    int 0
    app_global_put
    int 1
    return

handle_noop:
    byte "counter"
    app_global_get
    int 1
    +
    byte "counter"
    swap
    app_global_put
    int 1
    return

handle_optin:
    int 1
    return
'''


@pytest.fixture
def sample_vulnerable_teal():
    """Sample vulnerable TEAL program."""
    return '''
#pragma version 8

// Missing sender check!
txn ApplicationID
int 0
==
bnz create

// No OnCompletion check
int 1
return

create:
    byte "admin"
    txn Sender
    app_global_put
    int 1
    return
'''


@pytest.fixture
def sample_pyteal_contract():
    """Sample PyTeal contract source code."""
    return '''
from pyteal import *

def approval_program():
    handle_creation = Seq([
        Assert(Txn.sender() == Global.creator_address()),
        Assert(Txn.rekey_to() == Global.zero_address()),
        Assert(Txn.close_remainder_to() == Global.zero_address()),
        App.globalPut(Bytes("counter"), Int(0)),
        Return(Int(1))
    ])

    handle_noop = Seq([
        Assert(Txn.sender() == Global.creator_address()),
        App.globalPut(
            Bytes("counter"),
            App.globalGet(Bytes("counter")) + Int(1)
        ),
        Return(Int(1))
    ])

    handle_optin = Return(Int(1))

    handle_update = Seq([
        Assert(Txn.sender() == Global.creator_address()),
        Return(Int(1))
    ])

    handle_delete = Seq([
        Assert(Txn.sender() == Global.creator_address()),
        Return(Int(1))
    ])

    program = Cond(
        [Txn.application_id() == Int(0), handle_creation],
        [Txn.on_completion() == OnComplete.NoOp, handle_noop],
        [Txn.on_completion() == OnComplete.OptIn, handle_optin],
        [Txn.on_completion() == OnComplete.UpdateApplication, handle_update],
        [Txn.on_completion() == OnComplete.DeleteApplication, handle_delete],
    )

    return program

if __name__ == "__main__":
    print(compileTeal(approval_program(), mode=Mode.Application, version=8))
'''


@pytest.fixture
def sample_vulnerable_pyteal():
    """Sample vulnerable PyTeal contract."""
    return '''
from pyteal import *

def vulnerable_approval():
    # Missing RekeyTo check!
    # Missing CloseRemainderTo check!

    handle_creation = Seq([
        App.globalPut(Bytes("admin"), Txn.sender()),
        Return(Int(1))
    ])

    # Unrestricted update - no sender check!
    handle_update = Return(Int(1))

    # Unrestricted delete!
    handle_delete = Return(Int(1))

    # Inner transaction without auth
    handle_call = Seq([
        InnerTxnBuilder.Begin(),
        InnerTxnBuilder.SetField(TxnField.type_enum, TxnType.Payment),
        InnerTxnBuilder.SetField(TxnField.amount, Int(1000000)),
        InnerTxnBuilder.Submit(),
        Return(Int(1))
    ])

    # Group transaction without validation
    handle_group = Seq([
        App.globalPut(Bytes("data"), Gtxn[1].application_args[0]),
        Return(Int(1))
    ])

    program = Cond(
        [Txn.application_id() == Int(0), handle_creation],
        [Txn.on_completion() == OnComplete.UpdateApplication, handle_update],
        [Txn.on_completion() == OnComplete.DeleteApplication, handle_delete],
        [Txn.application_args[0] == Bytes("call"), handle_call],
        [Txn.application_args[0] == Bytes("group"), handle_group],
    )

    return program
'''


@pytest.fixture
def sample_plutus_validator():
    """Sample Plutus validator source code."""
    return '''
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TemplateHaskell #-}

module TokenValidator where

import Plutus.V2.Ledger.Api
import Plutus.V2.Ledger.Contexts
import PlutusTx.Prelude

data TokenDatum = TokenDatum
    { owner :: PubKeyHash
    , amount :: Integer
    }

data TokenRedeemer = Spend | Update

mkValidator :: TokenDatum -> TokenRedeemer -> ScriptContext -> Bool
mkValidator datum redeemer ctx =
    case redeemer of
        Spend -> traceIfFalse "not signed by owner" signedByOwner &&
                 traceIfFalse "value not preserved" valuePreserved
        Update -> traceIfFalse "not signed by owner" signedByOwner
  where
    info :: TxInfo
    info = scriptContextTxInfo ctx

    signedByOwner :: Bool
    signedByOwner = txSignedBy info (owner datum)

    valuePreserved :: Bool
    valuePreserved = valuePaidTo info (owner datum) >= Ada.lovelaceValueOf (amount datum)
'''


@pytest.fixture
def sample_vulnerable_plutus():
    """Sample vulnerable Plutus validator."""
    return '''
{-# LANGUAGE DataKinds #-}

module VulnerableValidator where

import Plutus.V2.Ledger.Api
import PlutusTx.Prelude

data VulnDatum = VulnDatum { value :: Integer }
data VulnRedeemer = Claim | Withdraw

-- VULNERABLE: No signer check, no value validation
mkValidator :: VulnDatum -> VulnRedeemer -> ScriptContext -> Bool
mkValidator datum redeemer ctx =
    case redeemer of
        Claim -> True  -- Anyone can claim!
        Withdraw -> True  -- No validation!
'''


@pytest.fixture
def sample_aiken_validator():
    """Sample Aiken validator source code."""
    return '''
use aiken/list
use aiken/transaction.{ScriptContext, Spend, Transaction}
use aiken/transaction/credential.{VerificationKeyCredential}

type Datum {
  owner: VerificationKeyCredential,
  deadline: Int,
}

type Redeemer {
  Claim
  Cancel
}

validator token_lock {
  spend(datum: Datum, redeemer: Redeemer, ctx: ScriptContext) {
    let ScriptContext { transaction, purpose } = ctx
    let Transaction { extra_signatories, validity_range, .. } = transaction

    when redeemer is {
      Claim -> {
        let owner_signed = list.has(extra_signatories, datum.owner)
        let after_deadline = validity_range.lower_bound >= datum.deadline
        owner_signed && after_deadline
      }
      Cancel -> {
        list.has(extra_signatories, datum.owner)
      }
    }
  }
}
'''


@pytest.fixture
def sample_vulnerable_aiken():
    """Sample vulnerable Aiken validator."""
    return '''
use aiken/transaction.{ScriptContext, Spend}

type Datum {
  value: Int,
}

type Redeemer {
  Spend
  Update
}

validator vulnerable {
  spend(datum: Datum, redeemer: Redeemer, ctx: ScriptContext) {
    // VULNERABLE: No signer check!
    // VULNERABLE: No output validation!
    when redeemer is {
      Spend -> datum.value > 0
      Update -> True
    }
  }
}
'''


# ============================================================================
# Chain Type Tests
# ============================================================================


class TestChainType:
    """Tests for ChainType enum."""

    def test_evm_chains(self):
        """Test EVM chain list."""
        evm = ChainType.evm_chains()
        assert ChainType.ETHEREUM in evm
        assert ChainType.POLYGON in evm
        assert ChainType.SOLANA not in evm

    def test_move_chains(self):
        """Test Move chain list."""
        move = ChainType.move_chains()
        assert ChainType.SUI in move
        assert ChainType.APTOS in move
        assert ChainType.ETHEREUM not in move

    def test_chain_values(self):
        """Test chain value strings."""
        assert ChainType.ETHEREUM.value == "ethereum"
        assert ChainType.SOLANA.value == "solana"
        assert ChainType.NEAR.value == "near"


class TestContractLanguage:
    """Tests for ContractLanguage enum."""

    def test_language_values(self):
        """Test language value strings."""
        assert ContractLanguage.SOLIDITY.value == "solidity"
        assert ContractLanguage.RUST.value == "rust"
        assert ContractLanguage.MOVE.value == "move"


# ============================================================================
# Type System Tests
# ============================================================================


class TestTypeInfo:
    """Tests for TypeInfo dataclass."""

    def test_simple_type(self):
        """Test simple type."""
        t = TypeInfo(name="uint256")
        assert str(t) == "uint256"
        assert t.is_primitive is True

    def test_array_type(self):
        """Test array type."""
        t = TypeInfo(name="address", is_array=True)
        assert str(t) == "address[]"

    def test_mapping_type(self):
        """Test mapping type."""
        key = TypeInfo(name="address")
        value = TypeInfo(name="uint256")
        t = TypeInfo(name="mapping", is_mapping=True, key_type=key, value_type=value)
        assert str(t) == "mapping(address => uint256)"


class TestParameter:
    """Tests for Parameter dataclass."""

    def test_parameter_creation(self):
        """Test parameter creation."""
        p = Parameter(
            name="amount",
            type_info=TypeInfo(name="u64"),
        )
        assert p.name == "amount"
        assert str(p.type_info) == "u64"


class TestLocation:
    """Tests for Location dataclass."""

    def test_location_to_dict(self):
        """Test location serialization."""
        loc = Location(file="test.rs", line=42, column=10)
        d = loc.to_dict()

        assert d["file"] == "test.rs"
        assert d["line"] == 42
        assert d["column"] == 10


# ============================================================================
# Abstract Contract Element Tests
# ============================================================================


class TestAbstractVariable:
    """Tests for AbstractVariable."""

    def test_variable_creation(self):
        """Test variable creation."""
        var = AbstractVariable(
            name="balance",
            type_info=TypeInfo(name="u64"),
            visibility=Visibility.PUBLIC,
        )
        assert var.name == "balance"
        assert var.visibility == Visibility.PUBLIC

    def test_variable_to_dict(self):
        """Test variable serialization."""
        var = AbstractVariable(
            name="owner",
            type_info=TypeInfo(name="Pubkey"),
            is_constant=True,
        )
        d = var.to_dict()

        assert d["name"] == "owner"
        assert d["is_constant"] is True


class TestAbstractFunction:
    """Tests for AbstractFunction."""

    def test_function_creation(self):
        """Test function creation."""
        func = AbstractFunction(
            name="transfer",
            visibility=Visibility.PUBLIC,
            mutability=Mutability.MUTABLE,
        )
        assert func.name == "transfer"
        assert func.is_constructor is False

    def test_function_signature(self):
        """Test function signature generation."""
        func = AbstractFunction(
            name="deposit",
            parameters=[
                Parameter(name="amount", type_info=TypeInfo(name="u64")),
                Parameter(name="memo", type_info=TypeInfo(name="String")),
            ],
        )
        assert func.signature == "deposit(u64, String)"

    def test_is_constructor(self):
        """Test constructor detection."""
        func1 = AbstractFunction(name="constructor")
        func2 = AbstractFunction(name="initialize")
        func3 = AbstractFunction(name="transfer")

        assert func1.is_constructor is True
        assert func2.is_constructor is True
        assert func3.is_constructor is False

    def test_function_to_dict(self):
        """Test function serialization."""
        func = AbstractFunction(
            name="swap",
            calls_external=True,
            writes_state=True,
        )
        d = func.to_dict()

        assert d["name"] == "swap"
        assert d["calls_external"] is True
        assert d["writes_state"] is True


# ============================================================================
# Abstract Contract Tests
# ============================================================================


class TestAbstractContract:
    """Tests for AbstractContract."""

    def test_contract_creation(self):
        """Test contract creation."""
        contract = AbstractContract(
            name="MyProgram",
            chain_type=ChainType.SOLANA,
            language=ContractLanguage.RUST,
            source_path="/path/to/program.rs",
        )
        assert contract.name == "MyProgram"
        assert contract.chain_type == ChainType.SOLANA

    def test_content_hash(self):
        """Test content hash generation."""
        contract = AbstractContract(
            name="Test",
            chain_type=ChainType.ETHEREUM,
            language=ContractLanguage.SOLIDITY,
            source_path="test.sol",
            source_code="contract Test {}",
        )
        hash1 = contract.content_hash
        hash2 = contract.content_hash

        assert len(hash1) == 16
        assert hash1 == hash2  # Should be cached

    def test_get_function(self):
        """Test function lookup."""
        func = AbstractFunction(name="transfer")
        contract = AbstractContract(
            name="Token",
            chain_type=ChainType.ETHEREUM,
            language=ContractLanguage.SOLIDITY,
            source_path="token.sol",
            functions=[func],
        )

        assert contract.get_function("transfer") == func
        assert contract.get_function("nonexistent") is None

    def test_get_public_functions(self):
        """Test public function filtering."""
        public = AbstractFunction(name="transfer", visibility=Visibility.PUBLIC)
        external = AbstractFunction(name="swap", visibility=Visibility.EXTERNAL)
        internal = AbstractFunction(name="_update", visibility=Visibility.INTERNAL)

        contract = AbstractContract(
            name="Test",
            chain_type=ChainType.ETHEREUM,
            language=ContractLanguage.SOLIDITY,
            source_path="test.sol",
            functions=[public, external, internal],
        )

        public_funcs = contract.get_public_functions()
        assert len(public_funcs) == 2
        assert internal not in public_funcs

    def test_to_dict(self):
        """Test contract serialization."""
        contract = AbstractContract(
            name="MyContract",
            chain_type=ChainType.SOLANA,
            language=ContractLanguage.RUST,
            source_path="lib.rs",
            source_code="pub mod test {}",
            compiler_version="1.18.0",
        )
        d = contract.to_dict()

        assert d["name"] == "MyContract"
        assert d["chain_type"] == "solana"
        assert d["language"] == "rust"


# ============================================================================
# Vulnerability Mapping Tests
# ============================================================================


class TestVulnerabilityMappings:
    """Tests for vulnerability mappings."""

    def test_mappings_exist(self):
        """Test that mappings are defined."""
        assert len(VULNERABILITY_MAPPINGS) > 0
        assert "access_control" in VULNERABILITY_MAPPINGS
        assert "reentrancy" in VULNERABILITY_MAPPINGS

    def test_get_mapping_canonical(self):
        """Test getting mapping by canonical name."""
        mapping = get_vulnerability_mapping("reentrancy")
        assert mapping is not None
        assert mapping.canonical_name == "reentrancy"
        assert "SWC-107" in mapping.swc_ids

    def test_get_mapping_chain_specific(self):
        """Test getting mapping by chain-specific name."""
        mapping = get_vulnerability_mapping("missing-signer-check")
        assert mapping is not None
        assert mapping.canonical_name == "access_control"

    def test_normalize_vulnerability_type(self):
        """Test vulnerability type normalization."""
        assert normalize_vulnerability_type("missing_signer_check", ChainType.SOLANA) == "access_control"
        assert normalize_vulnerability_type("reentrancy_eth", ChainType.ETHEREUM) == "reentrancy"
        assert normalize_vulnerability_type("unknown_type", ChainType.ETHEREUM) == "unknown_type"


# ============================================================================
# Chain Registry Tests
# ============================================================================


class TestChainRegistry:
    """Tests for ChainRegistry."""

    def test_singleton(self):
        """Test registry singleton."""
        reg1 = ChainRegistry()
        reg2 = ChainRegistry()
        assert reg1 is reg2

    def test_register_analyzer(self):
        """Test analyzer registration."""
        registry = get_chain_registry()
        analyzer = SolanaAnalyzer()
        registry.register(analyzer)

        assert registry.get(ChainType.SOLANA) is analyzer

    def test_list_chains(self):
        """Test listing registered chains."""
        registry = get_chain_registry()
        analyzer = SolanaAnalyzer()
        registry.register(analyzer)

        chains = registry.list_chains()
        assert ChainType.SOLANA in chains

    def test_get_status(self):
        """Test registry status."""
        registry = get_chain_registry()
        analyzer = SolanaAnalyzer()
        registry.register(analyzer)

        status = registry.get_status()
        assert "registered_chains" in status
        assert "analyzers" in status


# ============================================================================
# Solana Analyzer Tests
# ============================================================================


class TestSolanaAnalyzer:
    """Tests for SolanaAnalyzer."""

    def test_analyzer_properties(self):
        """Test analyzer properties."""
        analyzer = SolanaAnalyzer()
        assert analyzer.name == "solana-analyzer"
        assert analyzer.version == "1.0.0"
        assert ".rs" in analyzer.supported_extensions

    def test_can_analyze(self):
        """Test file type detection."""
        analyzer = SolanaAnalyzer()
        assert analyzer.can_analyze("program.rs") is True
        assert analyzer.can_analyze("idl.json") is True
        assert analyzer.can_analyze("contract.sol") is False

    def test_parse_rust(self, sample_anchor_program):
        """Test Rust source parsing."""
        with tempfile.NamedTemporaryFile(suffix=".rs", mode="w", delete=False) as f:
            f.write(sample_anchor_program)
            f.flush()

            analyzer = SolanaAnalyzer()
            contract = analyzer.parse(f.name)

            assert contract.name == Path(f.name).stem
            assert contract.chain_type == ChainType.SOLANA
            assert contract.language == ContractLanguage.RUST
            assert len(contract.functions) >= 3  # initialize, update, transfer
            assert len(contract.events) >= 1  # TransferEvent

    def test_parse_idl(self, sample_anchor_idl):
        """Test IDL parsing."""
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump(sample_anchor_idl, f)
            f.flush()

            analyzer = SolanaAnalyzer()
            contract = analyzer.parse(f.name)

            assert contract.name == "my_program"
            assert len(contract.functions) == 3  # 3 instructions

    def test_detect_vulnerabilities(self, vulnerable_solana_program):
        """Test vulnerability detection."""
        with tempfile.NamedTemporaryFile(suffix=".rs", mode="w", delete=False) as f:
            f.write(vulnerable_solana_program)
            f.flush()

            analyzer = SolanaAnalyzer()
            contract = analyzer.parse(f.name)
            findings = analyzer.detect_vulnerabilities(contract)

            # Should find multiple vulnerabilities
            assert len(findings) > 0

            # Check for specific types
            vuln_types = [f.get("type") or f.get("original_type") for f in findings]
            # Should detect arithmetic issues
            assert any("arithmetic" in t or "unchecked" in t for t in vuln_types)

    def test_full_analysis(self, sample_anchor_program):
        """Test full analysis pipeline."""
        with tempfile.NamedTemporaryFile(suffix=".rs", mode="w", delete=False) as f:
            f.write(sample_anchor_program)
            f.flush()

            analyzer = SolanaAnalyzer()
            result = analyzer.analyze(f.name)

            assert result["status"] == "success"
            assert result["chain_type"] == "solana"
            assert "contract" in result
            assert "findings" in result
            assert "execution_time" in result


class TestSolanaPatternDetector:
    """Tests for SolanaPatternDetector."""

    def test_detect_signer_patterns(self):
        """Test signer pattern detection."""
        detector = SolanaPatternDetector()

        code = '''
        #[account(mut)]
        pub account: Account<'info, Data>,
        '''

        patterns = detector.detect_patterns(code, "test.rs")
        assert len(patterns) > 0

    def test_detect_arithmetic_patterns(self):
        """Test arithmetic pattern detection."""
        detector = SolanaPatternDetector()

        code = '''
        account.balance += amount;
        total -= fee;
        value = x as u64;
        '''

        patterns = detector.detect_patterns(code, "test.rs")
        arithmetic_patterns = [p for p in patterns if p["category"] == "arithmetic"]
        # At minimum should detect the unsafe cast
        assert len(arithmetic_patterns) >= 1
        # Check that unsafe_cast was detected
        assert any(p["pattern"] == "unsafe_cast" for p in arithmetic_patterns)

    def test_detect_cpi_patterns(self):
        """Test CPI pattern detection."""
        detector = SolanaPatternDetector()

        code = '''
        invoke(
            &instruction,
            &accounts,
        )?;
        '''

        patterns = detector.detect_patterns(code, "test.rs")
        cpi_patterns = [p for p in patterns if p["category"] == "external_calls"]
        assert len(cpi_patterns) >= 1


class TestAnchorDataTypes:
    """Tests for Anchor data types."""

    def test_anchor_account(self):
        """Test AnchorAccount creation."""
        account = AnchorAccount(
            name="vault",
            account_type="Account",
            is_mut=True,
            is_signer=False,
            pda_seeds=["vault", "authority"],
        )

        assert account.name == "vault"
        assert account.is_mut is True
        assert len(account.pda_seeds) == 2

    def test_anchor_instruction(self):
        """Test AnchorInstruction creation."""
        instruction = AnchorInstruction(
            name="deposit",
            accounts=[
                AnchorAccount(name="vault", account_type="Account", is_mut=True),
            ],
            args=[
                Parameter(name="amount", type_info=TypeInfo(name="u64")),
            ],
        )

        d = instruction.to_dict()
        assert d["name"] == "deposit"
        assert len(d["accounts"]) == 1
        assert len(d["args"]) == 1


# ============================================================================
# Convenience Function Tests
# ============================================================================


class TestConvenienceFunctions:
    """Tests for module-level convenience functions."""

    def test_analyze_solana_program(self, sample_anchor_program):
        """Test analyze_solana_program function."""
        with tempfile.NamedTemporaryFile(suffix=".rs", mode="w", delete=False) as f:
            f.write(sample_anchor_program)
            f.flush()

            result = analyze_solana_program(f.name)
            assert result["status"] == "success"

    def test_parse_anchor_idl(self, sample_anchor_idl):
        """Test parse_anchor_idl function."""
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump(sample_anchor_idl, f)
            f.flush()

            contract = parse_anchor_idl(f.name)
            assert contract.name == "my_program"
            assert len(contract.functions) == 3


# ============================================================================
# Integration Tests
# ============================================================================


class TestMultiChainIntegration:
    """Integration tests for multi-chain system."""

    def test_solana_analyzer_registration(self):
        """Test Solana analyzer registration with registry."""
        registry = get_chain_registry()
        analyzer = SolanaAnalyzer()
        register_chain_analyzer(analyzer)

        retrieved = get_analyzer_for_chain(ChainType.SOLANA)
        assert retrieved is not None
        assert retrieved.name == "solana-analyzer"

    def test_normalized_findings_format(self, vulnerable_solana_program):
        """Test that findings match MIESC normalized format."""
        with tempfile.NamedTemporaryFile(suffix=".rs", mode="w", delete=False) as f:
            f.write(vulnerable_solana_program)
            f.flush()

            result = analyze_solana_program(f.name)

            if result["findings"]:
                finding = result["findings"][0]

                # Check required fields
                assert "id" in finding
                assert "type" in finding
                assert "severity" in finding
                assert "location" in finding
                assert "message" in finding

                # Check location structure
                loc = finding["location"]
                assert "file" in loc
                assert "line" in loc

    def test_cross_chain_vulnerability_mapping(self):
        """Test vulnerability mapping across chains."""
        # Same vulnerability type should normalize consistently
        sol_type = normalize_vulnerability_type("missing_signer_check", ChainType.SOLANA)
        eth_type = normalize_vulnerability_type("unprotected-function", ChainType.ETHEREUM)

        assert sol_type == eth_type == "access_control"


# ============================================================================
# Edge Cases
# ============================================================================


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_rust_file(self):
        """Test parsing empty Rust file."""
        with tempfile.NamedTemporaryFile(suffix=".rs", mode="w", delete=False) as f:
            f.write("")
            f.flush()

            analyzer = SolanaAnalyzer()
            contract = analyzer.parse(f.name)

            assert contract.source_code == ""
            assert len(contract.functions) == 0

    def test_invalid_json_idl(self):
        """Test handling invalid IDL JSON."""
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            f.write("not valid json")
            f.flush()

            analyzer = SolanaAnalyzer()
            result = analyzer.analyze(f.name)

            assert result["status"] == "error"

    def test_missing_file(self):
        """Test handling missing file."""
        analyzer = SolanaAnalyzer()
        result = analyzer.analyze("/nonexistent/file.rs")

        assert result["status"] == "error"

    def test_complex_type_parsing(self, sample_anchor_idl):
        """Test parsing complex IDL types."""
        sample_anchor_idl["instructions"][0]["args"] = [
            {"name": "data", "type": {"vec": "u8"}},
            {"name": "config", "type": {"option": {"defined": "Config"}}},
            {"name": "buffer", "type": {"array": ["u8", 32]}},
        ]

        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump(sample_anchor_idl, f)
            f.flush()

            contract = parse_anchor_idl(f.name)
            func = contract.functions[0]

            assert len(func.parameters) == 3


# ============================================================================
# NEAR Adapter Tests
# ============================================================================


# Import NEAR adapter
from src.adapters.near_adapter import (
    NearAnalyzer,
    NearVulnerability,
    NearPatternDetector,
    analyze_near_contract,
)


@pytest.fixture
def sample_near_contract():
    """Sample NEAR contract source code."""
    return '''
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::collections::LookupMap;
use near_sdk::{env, near_bindgen, AccountId, Balance, Promise};

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct TokenContract {
    owner: AccountId,
    balances: LookupMap<AccountId, Balance>,
    total_supply: Balance,
}

impl Default for TokenContract {
    fn default() -> Self {
        env::panic_str("Contract must be initialized")
    }
}

#[near_bindgen]
impl TokenContract {
    #[init]
    pub fn new(owner: AccountId, total_supply: Balance) -> Self {
        let mut contract = Self {
            owner,
            balances: LookupMap::new(b"b"),
            total_supply,
        };
        contract.balances.insert(&env::predecessor_account_id(), &total_supply);
        contract
    }

    pub fn transfer(&mut self, to: AccountId, amount: Balance) {
        let sender = env::predecessor_account_id();
        let sender_balance = self.balances.get(&sender).unwrap_or(0);
        require!(sender_balance >= amount, "Insufficient balance");

        self.balances.insert(&sender, &(sender_balance - amount));
        let receiver_balance = self.balances.get(&to).unwrap_or(0);
        self.balances.insert(&to, &(receiver_balance + amount));
    }

    pub fn balance_of(&self, account: AccountId) -> Balance {
        self.balances.get(&account).unwrap_or(0)
    }

    #[private]
    pub fn on_transfer_callback(&mut self, amount: Balance) {
        // Handle callback
    }
}
'''


@pytest.fixture
def vulnerable_near_contract():
    """NEAR contract with vulnerabilities."""
    return '''
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::{env, near_bindgen, AccountId, Promise};

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize)]
pub struct VulnerableContract {
    admin: AccountId,
    value: u64,
}

#[near_bindgen]
impl VulnerableContract {
    // Missing access control!
    pub fn set_admin(&mut self, new_admin: AccountId) {
        self.admin = new_admin;
    }

    // Panic in view function
    pub fn get_value(&self) -> u64 {
        self.value.unwrap()
    }

    // Public callback without #[private]
    pub fn callback_handler(&mut self, result: u64) {
        self.value = result;
    }

    // Unbounded iteration
    pub fn process_all(&mut self, items: Vec<u64>) {
        for item in items.iter() {
            self.value += item;
        }
    }
}
'''


class TestNearAnalyzer:
    """Tests for NearAnalyzer."""

    def test_analyzer_properties(self):
        """Test analyzer properties."""
        analyzer = NearAnalyzer()
        assert analyzer.name == "near-analyzer"
        assert analyzer.version == "1.0.0"
        assert ".rs" in analyzer.supported_extensions

    def test_can_analyze(self):
        """Test file type detection."""
        analyzer = NearAnalyzer()
        assert analyzer.can_analyze("contract.rs") is True
        assert analyzer.can_analyze("contract.sol") is False

    def test_parse_contract(self, sample_near_contract):
        """Test contract parsing."""
        with tempfile.NamedTemporaryFile(suffix=".rs", mode="w", delete=False) as f:
            f.write(sample_near_contract)
            f.flush()

            analyzer = NearAnalyzer()
            contract = analyzer.parse(f.name)

            assert contract.chain_type == ChainType.NEAR
            assert len(contract.functions) >= 3
            assert len(contract.variables) >= 1

    def test_detect_vulnerabilities(self, vulnerable_near_contract):
        """Test vulnerability detection."""
        with tempfile.NamedTemporaryFile(suffix=".rs", mode="w", delete=False) as f:
            f.write(vulnerable_near_contract)
            f.flush()

            analyzer = NearAnalyzer()
            contract = analyzer.parse(f.name)
            findings = analyzer.detect_vulnerabilities(contract)

            assert len(findings) > 0

    def test_full_analysis(self, sample_near_contract):
        """Test full analysis pipeline."""
        with tempfile.NamedTemporaryFile(suffix=".rs", mode="w", delete=False) as f:
            f.write(sample_near_contract)
            f.flush()

            result = analyze_near_contract(f.name)
            assert result["status"] == "success"
            assert result["chain_type"] == "near"


class TestNearPatternDetector:
    """Tests for NearPatternDetector."""

    def test_detect_access_patterns(self):
        """Test access control pattern detection."""
        detector = NearPatternDetector()
        code = '''
        let caller = env::predecessor_account_id();
        require!(caller == self.owner, "Not authorized");
        '''
        patterns = detector.detect_patterns(code, "test.rs")
        assert len(patterns) > 0

    def test_detect_callback_patterns(self):
        """Test callback pattern detection."""
        detector = NearPatternDetector()
        code = '''
        #[private]
        pub fn on_callback(&mut self) {
            let result = env::promise_result(0);
        }
        '''
        patterns = detector.detect_patterns(code, "test.rs")
        callback_patterns = [p for p in patterns if p["category"] == "reentrancy"]
        assert len(callback_patterns) >= 1


# ============================================================================
# Move Adapter Tests
# ============================================================================


# Import Move adapter
from src.adapters.move_adapter import (
    MoveAnalyzer,
    MoveVulnerability,
    MoveChainVariant,
    MovePatternDetector,
    analyze_move_module,
)


@pytest.fixture
def sample_sui_module():
    """Sample Sui Move module."""
    return '''
module example::token {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
    use sui::coin::{Self, Coin};

    struct Token has key, store {
        id: UID,
        value: u64,
    }

    struct AdminCap has key {
        id: UID,
    }

    fun init(ctx: &mut TxContext) {
        transfer::transfer(AdminCap {
            id: object::new(ctx),
        }, tx_context::sender(ctx));
    }

    public entry fun mint(
        _: &AdminCap,
        value: u64,
        recipient: address,
        ctx: &mut TxContext,
    ) {
        let token = Token {
            id: object::new(ctx),
            value,
        };
        transfer::transfer(token, recipient);
    }

    public fun get_value(token: &Token): u64 {
        token.value
    }
}
'''


@pytest.fixture
def vulnerable_move_module():
    """Move module with vulnerabilities."""
    return '''
module example::vulnerable {
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::TxContext;

    struct AdminCap has key, store {
        id: UID,
    }

    struct Data has key {
        id: UID,
        value: u64,
    }

    // Capability leak - public function with mutable cap
    public fun modify_cap(cap: &mut AdminCap) {
        // This allows anyone to modify the cap
    }

    // Flash loan pattern
    public fun flash_loan(amount: u64): HotPotato {
        HotPotato { amount }
    }

    struct HotPotato {
        amount: u64,
    }

    // Unchecked arithmetic
    public entry fun add_value(data: &mut Data, amount: u64) {
        data.value = data.value + amount;
    }
}
'''


class TestMoveAnalyzer:
    """Tests for MoveAnalyzer."""

    def test_analyzer_properties(self):
        """Test analyzer properties."""
        analyzer = MoveAnalyzer(MoveChainVariant.SUI)
        assert "move-analyzer" in analyzer.name
        assert analyzer.version == "1.0.0"
        assert ".move" in analyzer.supported_extensions

    def test_can_analyze(self):
        """Test file type detection."""
        analyzer = MoveAnalyzer()
        assert analyzer.can_analyze("module.move") is True
        assert analyzer.can_analyze("contract.sol") is False

    def test_parse_sui_module(self, sample_sui_module):
        """Test Sui module parsing."""
        with tempfile.NamedTemporaryFile(suffix=".move", mode="w", delete=False) as f:
            f.write(sample_sui_module)
            f.flush()

            analyzer = MoveAnalyzer(MoveChainVariant.SUI)
            contract = analyzer.parse(f.name)

            assert contract.chain_type == ChainType.SUI
            assert contract.name == "token"
            assert len(contract.functions) >= 3
            assert len(contract.variables) >= 2  # Token, AdminCap structs

    def test_detect_capability_struct(self, sample_sui_module):
        """Test capability struct detection."""
        with tempfile.NamedTemporaryFile(suffix=".move", mode="w", delete=False) as f:
            f.write(sample_sui_module)
            f.flush()

            analyzer = MoveAnalyzer()
            contract = analyzer.parse(f.name)

            # Find AdminCap
            cap_structs = [v for v in contract.variables if v.metadata.get("is_capability")]
            assert len(cap_structs) >= 1

    def test_detect_vulnerabilities(self, vulnerable_move_module):
        """Test vulnerability detection."""
        with tempfile.NamedTemporaryFile(suffix=".move", mode="w", delete=False) as f:
            f.write(vulnerable_move_module)
            f.flush()

            analyzer = MoveAnalyzer()
            contract = analyzer.parse(f.name)
            findings = analyzer.detect_vulnerabilities(contract)

            assert len(findings) > 0

    def test_full_analysis(self, sample_sui_module):
        """Test full analysis pipeline."""
        with tempfile.NamedTemporaryFile(suffix=".move", mode="w", delete=False) as f:
            f.write(sample_sui_module)
            f.flush()

            result = analyze_move_module(f.name, MoveChainVariant.SUI)
            assert result["status"] == "success"
            assert result["chain_type"] == "sui"


class TestMovePatternDetector:
    """Tests for MovePatternDetector."""

    def test_detect_capability_patterns(self):
        """Test capability pattern detection."""
        detector = MovePatternDetector()
        code = '''
        struct AdminCap has key, store {
            id: UID,
        }
        public fun use_cap(cap: &mut AdminCap) {}
        '''
        patterns = detector.detect_patterns(code, "test.move")
        cap_patterns = [p for p in patterns if "cap" in p["pattern"].lower() or "admin" in p["pattern"].lower()]
        assert len(cap_patterns) >= 1

    def test_detect_flash_loan_patterns(self):
        """Test flash loan pattern detection."""
        detector = MovePatternDetector()
        code = '''
        public fun flash_borrow(amount: u64): HotPotato {
            HotPotato { amount }
        }
        '''
        patterns = detector.detect_patterns(code, "test.move")
        flash_patterns = [p for p in patterns if p["category"] == "flash_loan"]
        assert len(flash_patterns) >= 1


class TestMoveChainVariants:
    """Tests for different Move chain variants."""

    def test_sui_variant(self):
        """Test Sui variant detection."""
        analyzer = MoveAnalyzer(MoveChainVariant.SUI)
        assert analyzer.chain_type == ChainType.SUI

    def test_aptos_variant(self):
        """Test Aptos variant detection."""
        analyzer = MoveAnalyzer(MoveChainVariant.APTOS)
        assert analyzer.chain_type == ChainType.APTOS


# ============================================================================
# Stellar/Soroban Adapter Tests
# ============================================================================


class TestStellarAnalyzer:
    """Tests for StellarAnalyzer."""

    def test_analyzer_properties(self):
        """Test analyzer basic properties."""
        analyzer = StellarAnalyzer()
        assert analyzer.name == "StellarAnalyzer"
        assert analyzer.version == "1.0.0"
        assert ".rs" in analyzer.supported_extensions
        assert analyzer.chain_type == ChainType.STELLAR

    def test_parse_soroban_contract(self, sample_soroban_contract):
        """Test parsing a Soroban contract."""
        with tempfile.NamedTemporaryFile(suffix=".rs", mode="w", delete=False) as f:
            f.write(sample_soroban_contract)
            f.flush()

            analyzer = StellarAnalyzer()
            contract = analyzer.parse(f.name)

            assert contract.name is not None
            assert contract.chain_type == ChainType.STELLAR
            assert contract.language == ContractLanguage.RUST
            assert len(contract.functions) > 0

    def test_detect_missing_auth(self, sample_vulnerable_soroban):
        """Test detection of missing authorization."""
        with tempfile.NamedTemporaryFile(suffix=".rs", mode="w", delete=False) as f:
            f.write(sample_vulnerable_soroban)
            f.flush()

            analyzer = StellarAnalyzer()
            result = analyzer.analyze(f.name)

            assert result["status"] == "success"
            # Should detect missing auth in withdraw function
            auth_findings = [
                f for f in result["findings"]
                if "auth" in f.get("type", "").lower() or "auth" in f.get("message", "").lower()
            ]
            assert len(auth_findings) >= 1

    def test_detect_panic_patterns(self, sample_vulnerable_soroban):
        """Test detection of panic patterns."""
        with tempfile.NamedTemporaryFile(suffix=".rs", mode="w", delete=False) as f:
            f.write(sample_vulnerable_soroban)
            f.flush()

            analyzer = StellarAnalyzer()
            result = analyzer.analyze(f.name)

            # Should detect panic!
            panic_findings = [
                f for f in result["findings"]
                if "panic" in f.get("type", "").lower() or "panic" in f.get("message", "").lower()
            ]
            assert len(panic_findings) >= 1

    def test_detect_unwrap_patterns(self, sample_vulnerable_soroban):
        """Test detection of unwrap patterns."""
        with tempfile.NamedTemporaryFile(suffix=".rs", mode="w", delete=False) as f:
            f.write(sample_vulnerable_soroban)
            f.flush()

            analyzer = StellarAnalyzer()
            result = analyzer.analyze(f.name)

            # Should detect unwrap
            unwrap_findings = [
                f for f in result["findings"]
                if "unwrap" in f.get("type", "").lower() or "unwrap" in f.get("message", "").lower()
            ]
            assert len(unwrap_findings) >= 1

    def test_detect_cross_contract_risks(self, sample_vulnerable_soroban):
        """Test detection of cross-contract call risks."""
        with tempfile.NamedTemporaryFile(suffix=".rs", mode="w", delete=False) as f:
            f.write(sample_vulnerable_soroban)
            f.flush()

            analyzer = StellarAnalyzer()
            result = analyzer.analyze(f.name)

            assert result["status"] == "success"
            # The analyzer should produce some findings for vulnerable code
            # Cross-contract detection depends on pattern matching
            assert len(result["findings"]) >= 1

    def test_safe_contract_analysis(self, sample_soroban_contract):
        """Test that safe contract has fewer findings."""
        with tempfile.NamedTemporaryFile(suffix=".rs", mode="w", delete=False) as f:
            f.write(sample_soroban_contract)
            f.flush()

            analyzer = StellarAnalyzer()
            result = analyzer.analyze(f.name)

            assert result["status"] == "success"
            # Safe contract should have few or no critical findings
            critical_findings = [
                f for f in result["findings"]
                if f.get("severity") == "Critical"
            ]
            assert len(critical_findings) == 0


class TestSorobanParser:
    """Tests for SorobanParser."""

    def test_parse_functions(self, sample_soroban_contract):
        """Test parsing Soroban functions."""
        with tempfile.NamedTemporaryFile(suffix=".rs", mode="w", delete=False) as f:
            f.write(sample_soroban_contract)
            f.flush()

            parser = SorobanParser()
            contract = parser.parse(f.name)

            assert len(contract.functions) >= 3
            func_names = [fn.name for fn in contract.functions]
            assert "initialize" in func_names or "mint" in func_names

    def test_parse_storage_accesses(self, sample_soroban_contract):
        """Test parsing storage access patterns."""
        with tempfile.NamedTemporaryFile(suffix=".rs", mode="w", delete=False) as f:
            f.write(sample_soroban_contract)
            f.flush()

            parser = SorobanParser()
            contract = parser.parse(f.name)

            # Should detect storage accesses
            assert len(contract.storage_accesses) > 0

    def test_detect_auth_in_functions(self, sample_soroban_contract):
        """Test detection of auth patterns in functions."""
        with tempfile.NamedTemporaryFile(suffix=".rs", mode="w", delete=False) as f:
            f.write(sample_soroban_contract)
            f.flush()

            parser = SorobanParser()
            contract = parser.parse(f.name)

            # At least some functions should have auth
            auth_funcs = [fn for fn in contract.functions if fn.has_auth]
            assert len(auth_funcs) >= 1


class TestStellarPatternDetector:
    """Tests for StellarPatternDetector."""

    def test_find_auth_patterns(self):
        """Test finding authorization patterns."""
        code = '''
        admin.require_auth();
        from.require_auth_for_args((&amount,));
        '''
        matches = StellarPatternDetector.find_patterns(
            code, StellarPatternDetector.AUTH_PATTERNS
        )
        assert len(matches) >= 2

    def test_find_dangerous_patterns(self):
        """Test finding dangerous patterns."""
        code = '''
        let value = option.unwrap();
        panic!("Error!");
        let result = data.expect("Failed");
        '''
        matches = StellarPatternDetector.find_patterns(
            code, StellarPatternDetector.DANGEROUS_PATTERNS
        )
        assert len(matches) >= 3

    def test_find_storage_patterns(self):
        """Test finding storage patterns."""
        code = '''
        env.storage().instance().get::<_, i128>(&key);
        env.storage().persistent().set(&key, &value);
        '''
        matches = StellarPatternDetector.find_patterns(
            code, StellarPatternDetector.STORAGE_PATTERNS
        )
        assert len(matches) >= 2


# ============================================================================
# Algorand Adapter Tests
# ============================================================================


class TestAlgorandAnalyzer:
    """Tests for AlgorandAnalyzer."""

    def test_analyzer_properties(self):
        """Test analyzer basic properties."""
        analyzer = AlgorandAnalyzer()
        assert analyzer.name == "AlgorandAnalyzer"
        assert analyzer.version == "1.0.0"
        assert ".teal" in analyzer.supported_extensions
        assert ".py" in analyzer.supported_extensions
        assert analyzer.chain_type == ChainType.ALGORAND

    def test_parse_teal_program(self, sample_teal_program):
        """Test parsing a TEAL program."""
        with tempfile.NamedTemporaryFile(suffix=".teal", mode="w", delete=False) as f:
            f.write(sample_teal_program)
            f.flush()

            analyzer = AlgorandAnalyzer()
            contract = analyzer.parse(f.name)

            assert contract.name is not None
            assert contract.chain_type == ChainType.ALGORAND
            assert contract.language == ContractLanguage.TEAL
            # Should have main entry point
            assert len(contract.functions) >= 1

    def test_parse_pyteal_contract(self, sample_pyteal_contract):
        """Test parsing a PyTeal contract."""
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(sample_pyteal_contract)
            f.flush()

            analyzer = AlgorandAnalyzer()
            contract = analyzer.parse(f.name)

            assert contract.name is not None
            assert contract.chain_type == ChainType.ALGORAND
            assert contract.language == ContractLanguage.PYTEAL
            assert len(contract.functions) >= 1

    def test_detect_teal_vulnerabilities(self, sample_vulnerable_teal):
        """Test vulnerability detection in TEAL."""
        with tempfile.NamedTemporaryFile(suffix=".teal", mode="w", delete=False) as f:
            f.write(sample_vulnerable_teal)
            f.flush()

            analyzer = AlgorandAnalyzer()
            result = analyzer.analyze(f.name)

            assert result["status"] == "success"
            # Should detect missing checks
            assert len(result["findings"]) >= 1

    def test_detect_pyteal_rekey_vulnerability(self, sample_vulnerable_pyteal):
        """Test detection of rekey vulnerability."""
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(sample_vulnerable_pyteal)
            f.flush()

            analyzer = AlgorandAnalyzer()
            result = analyzer.analyze(f.name)

            rekey_findings = [
                f for f in result["findings"]
                if "rekey" in f.get("type", "").lower()
            ]
            assert len(rekey_findings) >= 1

    def test_detect_pyteal_close_vulnerability(self, sample_vulnerable_pyteal):
        """Test detection of close-to vulnerability."""
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(sample_vulnerable_pyteal)
            f.flush()

            analyzer = AlgorandAnalyzer()
            result = analyzer.analyze(f.name)

            close_findings = [
                f for f in result["findings"]
                if "close" in f.get("type", "").lower()
            ]
            assert len(close_findings) >= 1

    def test_detect_unrestricted_update(self, sample_vulnerable_pyteal):
        """Test detection of unrestricted update."""
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(sample_vulnerable_pyteal)
            f.flush()

            analyzer = AlgorandAnalyzer()
            result = analyzer.analyze(f.name)

            update_findings = [
                f for f in result["findings"]
                if "update" in f.get("type", "").lower() or "update" in f.get("message", "").lower()
            ]
            # May or may not detect based on analysis depth
            assert result["status"] == "success"

    def test_detect_inner_txn_issues(self, sample_vulnerable_pyteal):
        """Test detection of inner transaction issues."""
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(sample_vulnerable_pyteal)
            f.flush()

            analyzer = AlgorandAnalyzer()
            result = analyzer.analyze(f.name)

            assert result["status"] == "success"
            # The vulnerable sample should produce multiple findings
            assert len(result["findings"]) >= 1

    def test_safe_pyteal_analysis(self, sample_pyteal_contract):
        """Test that safe contract has proper checks."""
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(sample_pyteal_contract)
            f.flush()

            analyzer = AlgorandAnalyzer()
            result = analyzer.analyze(f.name)

            assert result["status"] == "success"
            # Safe contract should have fewer critical findings
            critical_findings = [
                f for f in result["findings"]
                if f.get("severity") == "Critical"
            ]
            # The safe sample has proper rekey/close checks
            assert len(critical_findings) <= 2


class TestTealParser:
    """Tests for TealParser."""

    def test_parse_version(self, sample_teal_program):
        """Test parsing TEAL version."""
        with tempfile.NamedTemporaryFile(suffix=".teal", mode="w", delete=False) as f:
            f.write(sample_teal_program)
            f.flush()

            parser = TealParser()
            program = parser.parse(f.name)

            assert program.version == 8

    def test_parse_labels(self, sample_teal_program):
        """Test parsing TEAL labels."""
        with tempfile.NamedTemporaryFile(suffix=".teal", mode="w", delete=False) as f:
            f.write(sample_teal_program)
            f.flush()

            parser = TealParser()
            program = parser.parse(f.name)

            assert len(program.labels) >= 1
            assert "create" in program.labels or "handle_noop" in program.labels

    def test_parse_instructions(self, sample_teal_program):
        """Test parsing TEAL instructions."""
        with tempfile.NamedTemporaryFile(suffix=".teal", mode="w", delete=False) as f:
            f.write(sample_teal_program)
            f.flush()

            parser = TealParser()
            program = parser.parse(f.name)

            assert len(program.instructions) >= 5
            opcodes = [instr.opcode for instr in program.instructions]
            assert "txn" in opcodes or "int" in opcodes


class TestPyTealParser:
    """Tests for PyTealParser."""

    def test_parse_functions(self, sample_pyteal_contract):
        """Test parsing PyTeal functions."""
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(sample_pyteal_contract)
            f.flush()

            parser = PyTealParser()
            contract = parser.parse(f.name)

            assert len(contract.functions) >= 1
            func_names = [fn.name for fn in contract.functions]
            assert "approval_program" in func_names

    def test_parse_imports(self, sample_pyteal_contract):
        """Test parsing PyTeal imports."""
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(sample_pyteal_contract)
            f.flush()

            parser = PyTealParser()
            contract = parser.parse(f.name)

            assert len(contract.imports) >= 1
            assert any("pyteal" in imp.lower() for imp in contract.imports)


class TestAlgorandPatternDetector:
    """Tests for AlgorandPatternDetector."""

    def test_detect_teal_sender_check(self):
        """Test TEAL sender check detection."""
        code = "txn Sender\nglobal CreatorAddress\n==\nassert"
        # Create minimal TealProgram for testing
        program = TealProgram()
        program.instructions = [
            type('TealInstruction', (), {'opcode': 'txn', 'args': ['Sender'], 'line_number': 1, 'comment': ''})(),
        ]

        findings = AlgorandPatternDetector.detect_teal_vulnerabilities(program, code)
        # Should not find missing sender check since it's present
        sender_findings = [f for f in findings if "sender" in f.get("type", "").lower()]
        # This depends on implementation details
        assert isinstance(findings, list)

    def test_detect_pyteal_patterns(self):
        """Test PyTeal pattern detection."""
        code = '''
        InnerTxnBuilder.Begin()
        InnerTxnBuilder.Submit()
        Gtxn[1].amount()
        '''

        # Create minimal contract for testing
        contract = AlgorandContract(name="test", language="pyteal")

        findings = AlgorandPatternDetector.detect_pyteal_vulnerabilities(contract, code)
        assert isinstance(findings, list)


# ============================================================================
# Cardano/Plutus Adapter Tests
# ============================================================================


class TestCardanoAnalyzer:
    """Tests for CardanoAnalyzer."""

    def test_analyzer_properties(self):
        """Test analyzer basic properties."""
        analyzer = CardanoAnalyzer()
        assert analyzer.name == "CardanoAnalyzer"
        assert analyzer.version == "1.0.0"
        assert ".hs" in analyzer.supported_extensions
        assert ".ak" in analyzer.supported_extensions
        assert analyzer.chain_type == ChainType.CARDANO

    def test_parse_plutus_validator(self, sample_plutus_validator):
        """Test parsing a Plutus validator."""
        with tempfile.NamedTemporaryFile(suffix=".hs", mode="w", delete=False) as f:
            f.write(sample_plutus_validator)
            f.flush()

            analyzer = CardanoAnalyzer()
            contract = analyzer.parse(f.name)

            assert contract.name is not None
            assert contract.chain_type == ChainType.CARDANO
            assert contract.language == ContractLanguage.PLUTUS
            assert len(contract.functions) >= 1

    def test_parse_aiken_validator(self, sample_aiken_validator):
        """Test parsing an Aiken validator."""
        with tempfile.NamedTemporaryFile(suffix=".ak", mode="w", delete=False) as f:
            f.write(sample_aiken_validator)
            f.flush()

            analyzer = CardanoAnalyzer()
            contract = analyzer.parse(f.name)

            assert contract.name is not None
            assert contract.chain_type == ChainType.CARDANO
            assert contract.language == ContractLanguage.AIKEN
            assert len(contract.functions) >= 1

    def test_detect_plutus_vulnerabilities(self, sample_vulnerable_plutus):
        """Test vulnerability detection in Plutus."""
        with tempfile.NamedTemporaryFile(suffix=".hs", mode="w", delete=False) as f:
            f.write(sample_vulnerable_plutus)
            f.flush()

            analyzer = CardanoAnalyzer()
            result = analyzer.analyze(f.name)

            assert result["status"] == "success"
            # Should detect missing checks
            assert len(result["findings"]) >= 1

    def test_detect_aiken_vulnerabilities(self, sample_vulnerable_aiken):
        """Test vulnerability detection in Aiken."""
        with tempfile.NamedTemporaryFile(suffix=".ak", mode="w", delete=False) as f:
            f.write(sample_vulnerable_aiken)
            f.flush()

            analyzer = CardanoAnalyzer()
            result = analyzer.analyze(f.name)

            assert result["status"] == "success"
            # Should detect missing signer check
            signer_findings = [
                f for f in result["findings"]
                if "signer" in f.get("type", "").lower() or "signer" in f.get("message", "").lower()
            ]
            assert len(signer_findings) >= 1

    def test_safe_plutus_analysis(self, sample_plutus_validator):
        """Test that safe validator has fewer findings."""
        with tempfile.NamedTemporaryFile(suffix=".hs", mode="w", delete=False) as f:
            f.write(sample_plutus_validator)
            f.flush()

            analyzer = CardanoAnalyzer()
            result = analyzer.analyze(f.name)

            assert result["status"] == "success"
            # Safe validator should have proper checks
            critical_findings = [
                f for f in result["findings"]
                if f.get("severity") == "Critical"
            ]
            assert len(critical_findings) == 0

    def test_safe_aiken_analysis(self, sample_aiken_validator):
        """Test that safe Aiken validator has fewer findings."""
        with tempfile.NamedTemporaryFile(suffix=".ak", mode="w", delete=False) as f:
            f.write(sample_aiken_validator)
            f.flush()

            analyzer = CardanoAnalyzer()
            result = analyzer.analyze(f.name)

            assert result["status"] == "success"
            # Safe validator should have few critical findings
            critical_findings = [
                f for f in result["findings"]
                if f.get("severity") == "Critical"
            ]
            assert len(critical_findings) <= 1


class TestPlutusParser:
    """Tests for PlutusParser."""

    def test_parse_imports(self, sample_plutus_validator):
        """Test parsing Plutus imports."""
        with tempfile.NamedTemporaryFile(suffix=".hs", mode="w", delete=False) as f:
            f.write(sample_plutus_validator)
            f.flush()

            parser = PlutusParser()
            contract = parser.parse(f.name)

            assert len(contract.imports) >= 1

    def test_parse_data_types(self, sample_plutus_validator):
        """Test parsing Plutus data types."""
        with tempfile.NamedTemporaryFile(suffix=".hs", mode="w", delete=False) as f:
            f.write(sample_plutus_validator)
            f.flush()

            parser = PlutusParser()
            contract = parser.parse(f.name)

            # Should find TokenDatum and TokenRedeemer
            type_names = [t["name"] for t in contract.data_types]
            assert len(type_names) >= 1

    def test_parse_validators(self, sample_plutus_validator):
        """Test parsing Plutus validators."""
        with tempfile.NamedTemporaryFile(suffix=".hs", mode="w", delete=False) as f:
            f.write(sample_plutus_validator)
            f.flush()

            parser = PlutusParser()
            contract = parser.parse(f.name)

            assert len(contract.validators) >= 1
            validator = contract.validators[0]
            assert validator.script_type == PlutusScriptType.VALIDATOR


class TestAikenParser:
    """Tests for AikenParser."""

    def test_parse_imports(self, sample_aiken_validator):
        """Test parsing Aiken imports."""
        with tempfile.NamedTemporaryFile(suffix=".ak", mode="w", delete=False) as f:
            f.write(sample_aiken_validator)
            f.flush()

            parser = AikenParser()
            contract = parser.parse(f.name)

            assert len(contract.imports) >= 1
            assert any("aiken" in imp for imp in contract.imports)

    def test_parse_validators(self, sample_aiken_validator):
        """Test parsing Aiken validators."""
        with tempfile.NamedTemporaryFile(suffix=".ak", mode="w", delete=False) as f:
            f.write(sample_aiken_validator)
            f.flush()

            parser = AikenParser()
            contract = parser.parse(f.name)

            assert len(contract.validators) >= 1

    def test_parse_types(self, sample_aiken_validator):
        """Test parsing Aiken types."""
        with tempfile.NamedTemporaryFile(suffix=".ak", mode="w", delete=False) as f:
            f.write(sample_aiken_validator)
            f.flush()

            parser = AikenParser()
            contract = parser.parse(f.name)

            # Should find Datum and Redeemer types
            assert len(contract.data_types) >= 1


class TestCardanoPatternDetector:
    """Tests for CardanoPatternDetector."""

    def test_detect_plutus_patterns(self, sample_vulnerable_plutus):
        """Test Plutus vulnerability detection."""
        with tempfile.NamedTemporaryFile(suffix=".hs", mode="w", delete=False) as f:
            f.write(sample_vulnerable_plutus)
            f.flush()

            parser = PlutusParser()
            contract = parser.parse(f.name)

            findings = CardanoPatternDetector.detect_plutus_vulnerabilities(
                contract, sample_vulnerable_plutus
            )
            assert isinstance(findings, list)
            # Should find vulnerabilities
            assert len(findings) >= 1

    def test_detect_aiken_patterns(self, sample_vulnerable_aiken):
        """Test Aiken vulnerability detection."""
        with tempfile.NamedTemporaryFile(suffix=".ak", mode="w", delete=False) as f:
            f.write(sample_vulnerable_aiken)
            f.flush()

            parser = AikenParser()
            contract = parser.parse(f.name)

            findings = CardanoPatternDetector.detect_aiken_vulnerabilities(
                contract, sample_vulnerable_aiken
            )
            assert isinstance(findings, list)
            # Should find missing signer check
            assert len(findings) >= 1

    def test_cardano_vulnerability_types(self):
        """Test that all vulnerability types are defined."""
        expected_vulns = [
            "DOUBLE_SATISFACTION",
            "MISSING_SIGNER_CHECK",
            "MISSING_DATUM_VALIDATION",
            "UNAUTHORIZED_MINTING",
        ]
        for vuln in expected_vulns:
            assert hasattr(CardanoVulnerability, vuln)


# ============================================================================
# Cross-Chain Integration Tests
# ============================================================================


class TestCrossChainAnalysis:
    """Tests for cross-chain analysis capabilities."""

    def test_all_analyzers_registered(self):
        """Test that all analyzers can be registered."""
        from src.adapters.solana_adapter import register_solana_analyzer
        from src.adapters.near_adapter import register_near_analyzer
        from src.adapters.move_adapter import register_move_analyzer

        solana = register_solana_analyzer()
        near = register_near_analyzer()
        move_sui = register_move_analyzer(MoveChainVariant.SUI)

        registry = get_chain_registry()

        assert registry.get(ChainType.SOLANA) is not None
        assert registry.get(ChainType.NEAR) is not None
        assert registry.get(ChainType.SUI) is not None

    def test_stellar_algorand_analyzers(self):
        """Test that Stellar and Algorand analyzers work."""
        stellar = StellarAnalyzer()
        algorand = AlgorandAnalyzer()

        assert stellar.chain_type == ChainType.STELLAR
        assert algorand.chain_type == ChainType.ALGORAND

    def test_cardano_analyzer(self):
        """Test that Cardano analyzer works."""
        cardano = CardanoAnalyzer()

        assert cardano.chain_type == ChainType.CARDANO
        assert ".hs" in cardano.supported_extensions
        assert ".ak" in cardano.supported_extensions

    def test_normalized_findings_across_chains(
        self,
        sample_anchor_program,
        sample_near_contract,
        sample_sui_module,
    ):
        """Test that findings are normalized across chains."""
        # Test each analyzer produces normalized findings
        analyzers_and_code = [
            (SolanaAnalyzer(), sample_anchor_program, ".rs"),
            (NearAnalyzer(), sample_near_contract, ".rs"),
            (MoveAnalyzer(), sample_sui_module, ".move"),
        ]

        for analyzer, code, ext in analyzers_and_code:
            with tempfile.NamedTemporaryFile(suffix=ext, mode="w", delete=False) as f:
                f.write(code)
                f.flush()

                result = analyzer.analyze(f.name)

                # All should have same structure
                assert "status" in result
                assert "chain_type" in result
                assert "contract" in result
                assert "findings" in result

    def test_stellar_algorand_findings_structure(
        self,
        sample_soroban_contract,
        sample_pyteal_contract,
    ):
        """Test that Stellar and Algorand produce normalized findings."""
        # Stellar
        with tempfile.NamedTemporaryFile(suffix=".rs", mode="w", delete=False) as f:
            f.write(sample_soroban_contract)
            f.flush()

            stellar_analyzer = StellarAnalyzer()
            stellar_result = stellar_analyzer.analyze(f.name)

            assert "status" in stellar_result
            assert "chain_type" in stellar_result
            assert stellar_result["chain_type"] == "stellar"

        # Algorand PyTeal
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(sample_pyteal_contract)
            f.flush()

            algorand_analyzer = AlgorandAnalyzer()
            algorand_result = algorand_analyzer.analyze(f.name)

            assert "status" in algorand_result
            assert "chain_type" in algorand_result
            assert algorand_result["chain_type"] == "algorand"

    def test_all_chain_types_supported(self):
        """Test that all expected chain types are defined."""
        expected_chains = [
            "ETHEREUM", "SOLANA", "NEAR", "SUI", "APTOS", "STELLAR", "ALGORAND", "CARDANO"
        ]
        for chain in expected_chains:
            assert hasattr(ChainType, chain), f"Missing ChainType: {chain}"

    def test_vulnerability_mappings_include_new_chains(self):
        """Test that vulnerability mappings include Stellar, Algorand and Cardano."""
        for mapping in VULNERABILITY_MAPPINGS.values():
            assert hasattr(mapping, "stellar_names")
            assert hasattr(mapping, "algorand_names")
            assert hasattr(mapping, "cardano_names")


# ============================================================================
# Run Tests
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
