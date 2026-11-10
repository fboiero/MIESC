# Multi-Chain Support

MIESC provides production security analysis for **EVM chains**. Support for other platforms
is on the **roadmap**: experimental adapter code exists but is not production-validated.

## Support Levels

| Level | Description |
|-------|-------------|
| ✅ **Production** | Full 9-layer analysis with 50 tools across 35 analysis modules. Recommended for audits. |
| 🧪 **Experimental** | A real external analyzer is integrated (not just patterns), but recall/precision are not yet benchmark-validated. Useful for review; not a production guarantee. |
| 🛣️ **Roadmap** | Experimental adapter code (pattern-based). Planned, NOT production-validated — not for security decisions yet. |

## EVM Chains (Production)

**Status:** ✅ Production Ready

Supported networks: Ethereum, Polygon, BSC, Arbitrum, Optimism, Avalanche, and all EVM-compatible chains.

### Languages
- Solidity (0.4.x - 0.8.x)
- Vyper

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

## Cairo / Starknet (Experimental)

**Status:** 🧪 Experimental — Caracal integrated (not a pattern-only roadmap entry)

MIESC runs **Caracal** (Trail of Bits' Sierra-level static analyzer for Starknet,
AGPL-3.0) as a first-class adapter, and correlates its findings with a built-in
pattern analyzer. Caracal is pinned to a Cairo-2.20 fork so it analyzes current
Cairo; see [`docs/guides/CAIRO.md`](./guides/CAIRO.md) for setup and usage.

### Languages
- Cairo 1.x / 2.x (Starknet), up to Cairo **2.20** (the pinned Caracal front-end)

### Tools
- **Caracal** (external, semantic): compiles Cairo → Sierra and runs ~20 detectors.
- **Built-in pattern analyzer** (`cairo`): low-confidence heuristic, used as a
  correlation pair — when both agree on a class, confidence is raised.

### Detected vulnerabilities (Caracal detector families)
- Reentrancy (reentrancy, read-only, benign, events)
- `tx-origin` / caller-based authorization
- Controlled class hash: library-call, deploy, replace-class; unprotected upgrade
- L1↔L2 messaging: unchecked `#[l1_handler]` sender, controlled L1 message
- `felt252` unsafe arithmetic
- Unchecked ERC-20 transfer / unused return
- Array misuse (use-after-pop-front), unused events/arguments

### Usage
```bash
miesc scan contract.cairo            # a loose .cairo file
miesc scan path/to/scarb_project     # a Scarb project (directory with Scarb.toml)
miesc doctor                         # shows Caracal/Scarb status + versions
```

### Install
```bash
cargo install --git https://github.com/adrienlacombe/caracal --profile release  # needs rustc >= 1.94
```
`scripts/bootstrap_researcher_tools.sh` installs it automatically (gated on the
Rust toolchain). Scarb is only needed for Scarb *projects* and any 2.x works
(Caracal's bundled compiler does the compiling; local Scarb only supplies metadata).

### Limitations
- **No recall/precision numbers yet** — a labelled Cairo benchmark is future work
  (grant milestone M2). Do not cite detection rates for Cairo.
- Caracal is a maintained fork of an upstream that is no longer active; it is
  capped at the pinned Cairo version (2.20).
- No symbolic execution or formal verification for Cairo.
- The pattern analyzer is a low-confidence heuristic (use `--min-confidence 0.5`
  for high-signal only).
- Some detectors do not apply: `dead-code` is inert on Cairo 2.x (the compiler
  strips unreachable code before Sierra) and `unenforced-view` is Cairo-1 only.
- **Honest errors:** when Caracal fails to compile/run, the result is reported as
  an error — never a silent "0 findings / clean".

---

## Solana (Roadmap)

**Status:** 🛣️ Roadmap - Experimental (pattern detection only)

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
miesc scan program.rs --chain solana
```

### Limitations
- No symbolic execution
- No formal verification
- Pattern-based detection only
- May have false positives/negatives

---

## NEAR Protocol (Roadmap)

**Status:** 🛣️ Roadmap - Experimental (pattern detection only)

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
```bash
miesc scan contract.rs --chain near
```

---

## Move (Sui/Aptos) (Roadmap)

**Status:** 🛣️ Roadmap - Experimental (pattern detection only)

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
miesc scan module.move --chain sui
miesc scan module.move --chain aptos
```

---

## Stellar/Soroban (Roadmap)

**Status:** 🛣️ Roadmap - Experimental (pattern detection only)

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
```bash
miesc scan contract.rs --chain stellar
```

---

## Algorand (Roadmap)

**Status:** 🛣️ Roadmap - Experimental (pattern detection only)

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
```bash
miesc scan approval.teal --chain algorand
miesc scan contract.py --chain algorand  # PyTeal
```

---

## Cardano (Roadmap)

**Status:** 🛣️ Roadmap - Experimental (pattern detection only)

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
```bash
miesc scan validator.hs --chain cardano   # Plutus
miesc scan validator.ak --chain cardano   # Aiken
```

---

## Recommendations

### For Production Audits
Use **EVM analysis** for a full security assessment:
- Full 9-layer defense coverage
- 50 integrated tools / 35 analysis modules
- Backed detection numbers (SmartBugs full corpus: 95.8% recall; see the README benchmarks)
- Professional report generation

### For Research/Exploration
Non-EVM analyzers are useful for:
- Initial vulnerability scanning
- Pattern identification
- Security research
- Pre-audit exploration

**Do not rely on roadmap (non-EVM) analyzers for production security decisions.**

---

## Roadmap

| Phase | Chains | Target |
|-------|--------|--------|
| Current (v6.0.0) | EVM | Production (9 layers, 50 tools) |
| Next | Solana, NEAR | Experimental adapters → validated analysis |
| Later | Move, Stellar | Formal-verification research |
| Future | All chains | Production-grade multi-chain |

---

## Contributing

We welcome contributions to improve multi-chain support:

1. **Add detection patterns** - Extend vulnerability patterns for any chain
2. **Tool integration** - Help integrate chain-specific security tools
3. **Testing** - Provide test cases from real vulnerabilities
4. **Documentation** - Improve chain-specific documentation

See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.
