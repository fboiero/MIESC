# Multi-Chain Support

MIESC provides production security analysis for **EVM chains**. Support for other platforms
is on the **roadmap**: experimental adapter code exists but is not production-validated.

All non-Solidity usage below goes through the `miesc analyze` command, not `miesc scan` —
`scan` runs Slither/Aderyn/Solhint, all three of which reject any file that isn't `.sol`
(confirmed: they crash or no-op on `.vy`). Of the 8 non-Solidity adapter files that exist in
the codebase (Vyper + 7 non-EVM chains), 4 are actually reachable from the CLI:

## Support Levels

| Level | Description |
|-------|-------------|
| ✅ **Production** | Full 9-layer analysis with 50 tools across 35 analysis modules. Recommended for audits. |
| 🛣️ **Wired (Roadmap)** | Vyper, Solana, Move, Starknet/Cairo — reachable via `miesc analyze`, pattern-based, NOT production-validated — not for security decisions yet. |
| 💀 **Not wired** | NEAR, Stellar/Soroban, Algorand, Cardano — adapter code exists in `miesc/adapters/` but has zero production call site; `miesc analyze` does not accept these as `--chain` values today (only `ethereum\|vyper\|move\|starknet\|solana`) and no other command routes to them. Only reachable by importing the adapter class directly in Python. |

## Solidity (Production)

**Status:** ✅ Production Ready

Supported networks: Ethereum, Polygon, BSC, Arbitrum, Optimism, Avalanche, and all EVM-compatible chains.

### Languages
- Solidity (0.4.x - 0.8.x)

### Capabilities
- **50 integrated tools** across 9 defense layers
- Full symbolic execution (Mythril, Manticore, Halmos)
- Formal verification (Certora, SMTChecker)
- Fuzzing (Echidna, Medusa, Foundry)
- AI/ML analysis (SmartLLM, GPTScan, DA-GNN)
- DeFi-specific patterns (20+ attack categories)
- RAG-enhanced analysis with 32+ SWC entries

### Usage
```bash
miesc scan contract.sol                    # Quick scan
miesc audit full contract.sol              # Full 9-layer audit
miesc audit batch ./contracts -p thorough  # Batch audit
```

---

## Vyper (Wired, Roadmap)

**Status:** 🛣️ Wired via `miesc analyze` - Experimental (pattern detection only)

Vyper targets the same EVM as Solidity, but Slither/Aderyn/Solhint (the tools behind
`miesc scan`) only accept `.sol` — a `.vy` file used to reach them anyway and crash with an
uncaught compiler exception. `miesc analyze` now routes `.vy` to a dedicated pattern-based
Vyper adapter instead.

### Languages
- Vyper (0.2.x - 0.4.x)

### Detected Vulnerabilities
- Known-broken `@nonreentrant` lock under specific compiler versions (root cause of the
  Curve Finance ~$70M incident, 2023-07-30 — see the official Vyper security advisory
  GHSA-ph9x-4vc9-m2gg for the authoritative affected-version list)
- Missing `@nonreentrant` on functions that write state and make an external call
- `selfdestruct()` usage
- `raw_call(..., is_delegate_call=True)` — delegatecall to a caller-influenced target
- `create_forwarder_to` / `create_minimal_proxy_to` / `create_from_blueprint` without a
  visible init guard (proxy front-running)
- `tx.origin` used for authorization
- Missing access control on state-changing `@external` functions
- Explicit `unsafe_add`/`unsafe_sub`/`unsafe_mul`/`unsafe_div` (unchecked arithmetic)

### Usage
```bash
miesc analyze Vault.vy             # auto-detected from .vy
miesc analyze Vault.vy --chain vyper
```

### Limitations
- No symbolic execution, no formal verification, pattern-based detection only
- Does not depend on the `vyper` compiler being installed — detection is 100% source-text
  based, since a contract's `@version` pragma frequently won't match whatever compiler
  happens to be installed locally (verified: Vyper enforces the pragma at compile time)

---

## Solana (Wired, Roadmap)

**Status:** 🛣️ Wired via `miesc analyze` - Experimental (pattern detection only)

### Languages
- Rust with Anchor framework
- Native Solana programs

### Detected Vulnerabilities
- Missing signer checks
- Missing owner checks
- Arithmetic overflow/underflow
- Account data matching issues
- Insecure PDA derivation
- Unchecked account data
- Type cosplay attacks
- Closing account vulnerabilities

### Usage
```bash
miesc analyze program.rs --chain solana
miesc analyze program.rs             # auto-detected from .rs
```

### Limitations
- No symbolic execution
- No formal verification
- Pattern-based detection only
- May have false positives/negatives

---

## NEAR Protocol (Not wired)

**Status:** 💀 Not wired — `near_adapter.py` exists but no CLI command routes to it.
`miesc analyze --chain near` does not exist (`analyze` only accepts
`ethereum|move|starknet|solana`). Only reachable today by importing `NearAnalyzer` directly
in Python; the vulnerability classes below are what the adapter's pattern matchers implement,
not what you get by running a `miesc` command.

### Languages
- Rust with near-sdk

### Detected Vulnerabilities
- Reentrancy via callbacks
- Improper access control
- Panic in callbacks
- Storage key collision
- Serde vulnerabilities
- Missing predecessor check
- Unchecked promise results

### Usage
Not invocable via CLI today. Direct Python only:
```python
from miesc.adapters.near_adapter import NearAnalyzer
findings = NearAnalyzer().detect_vulnerabilities(NearAnalyzer().parse(Path("contract.rs")))
```

---

## Move (Sui/Aptos) (Wired, Roadmap)

**Status:** 🛣️ Wired via `miesc analyze` - Experimental (pattern detection only). Note: the
CLI has a single `move` chain, not separate `sui`/`aptos` values.

### Languages
- Move language

### Detected Vulnerabilities
- Object ownership issues (Sui)
- Capability leaks
- Flash loan vulnerabilities
- Unchecked arithmetic
- Reentrancy patterns
- Missing access control
- Timestamp dependencies

### Usage
```bash
miesc analyze module.move            # auto-detected from .move
miesc analyze module.move --chain move
```

---

## Stellar/Soroban (Not wired)

**Status:** 💀 Not wired — `stellar_adapter.py` exists but no CLI command routes to it.
`miesc analyze --chain stellar` does not exist. Only reachable by importing
`StellarAnalyzer` directly in Python.

### Languages
- Rust with Soroban SDK

### Detected Vulnerabilities
- Missing authorization checks
- Panic/unwrap in contracts
- Cross-contract call risks
- TTL (Time-To-Live) issues
- Token transfer vulnerabilities
- Unsafe storage patterns

### Usage
Not invocable via CLI today. Direct Python only:
```python
from miesc.adapters.stellar_adapter import StellarAnalyzer
findings = StellarAnalyzer().detect_vulnerabilities(StellarAnalyzer().parse(Path("contract.rs")))
```

---

## Algorand (Not wired)

**Status:** 💀 Not wired — `algorand_adapter.py` exists but no CLI command routes to it.
`miesc analyze --chain algorand` does not exist. Only reachable by importing
`AlgorandAnalyzer` directly in Python.

### Languages
- TEAL (assembly)
- PyTeal (Python DSL)

### Detected Vulnerabilities
- Rekey attacks
- Close-to attacks
- Inner transaction safety
- Group transaction validation
- Unchecked transaction fields
- Asset clawback risks
- Logic signature vulnerabilities

### Usage
Not invocable via CLI today. Direct Python only:
```python
from miesc.adapters.algorand_adapter import AlgorandAnalyzer
findings = AlgorandAnalyzer().detect_vulnerabilities(AlgorandAnalyzer().parse(Path("approval.teal")))
```

---

## Cardano (Not wired)

**Status:** 💀 Not wired — `cardano_adapter.py` exists but no CLI command routes to it.
`miesc analyze --chain cardano` does not exist. Only reachable by importing
`CardanoAnalyzer` directly in Python.

### Languages
- Plutus (Haskell)
- Aiken

### Detected Vulnerabilities
- Double satisfaction attacks
- Datum hijacking
- Unauthorized minting
- Missing signer checks
- UTXO contention issues
- Redeemer validation gaps
- Time-lock bypasses

### Usage
Not invocable via CLI today. Direct Python only:
```python
from miesc.adapters.cardano_adapter import CardanoAnalyzer
findings = CardanoAnalyzer().detect_vulnerabilities(CardanoAnalyzer().parse(Path("validator.hs")))
```

---

## Starknet/Cairo (Wired, Roadmap)

**Status:** 🛣️ Wired via `miesc analyze` - Experimental (pattern detection only)

### Languages
- Cairo

### Detected Vulnerabilities
- Felt overflow
- L1↔L2 message handling issues
- Storage slot collisions
- Unchecked L1 calls
- Caller spoofing
- Proxy upgrade issues
- Reentrancy
- Access control
- Arithmetic issues
- Unchecked u256 operations
- Stale Pragma oracle reads
- Missing init guard on upgrade
- Unchecked syscall results
- Signature replay

### Usage
```bash
miesc analyze Vault.cairo             # auto-detected from .cairo
miesc analyze Vault.cairo --chain starknet
```

### Limitations
- No symbolic execution
- No formal verification
- Pattern-based detection only
- May have false positives/negatives

---

## Recommendations

### For Production Audits
Use **EVM analysis** for a full security assessment:
- Full 9-layer defense coverage
- 50 integrated tools / 35 analysis modules
- Backed detection numbers (SmartBugs full corpus: 95.8% recall; see the README benchmarks)
- Professional report generation

### For Research/Exploration
The 4 CLI-wired pattern-based analyzers (Vyper, Solana, Move, Starknet/Cairo, via
`miesc analyze`) are useful for:
- Initial vulnerability scanning
- Pattern identification
- Security research
- Pre-audit exploration

The other 4 (NEAR, Stellar, Algorand, Cardano) require importing the adapter class directly
in Python — there is no `miesc` command that reaches them today.

**Do not rely on roadmap (non-EVM) analyzers for production security decisions.**

---

## Roadmap

| Phase | Chains | Target |
|-------|--------|--------|
| Current (v6.0.0) | EVM | Production (9 layers, 50 tools) |
| Current (v6.0.0) | Vyper, Solana, Move, Starknet/Cairo | Wired via `miesc analyze`, experimental |
| Not started | NEAR, Stellar, Algorand, Cardano | Adapter code exists, no CLI wiring yet |
| Future | All chains | Production-grade multi-chain |

---

## Contributing

We welcome contributions to improve multi-chain support:

1. **Add detection patterns** - Extend vulnerability patterns for any chain
2. **Tool integration** - Help integrate chain-specific security tools
3. **Testing** - Provide test cases from real vulnerabilities
4. **Documentation** - Improve chain-specific documentation

See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.
