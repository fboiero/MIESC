# Multi-Chain Support

MIESC supports security analysis across multiple blockchain platforms. This document describes the current status and capabilities for each chain.

## Support Levels

| Level | Description |
|-------|-------------|
| ✅ **Production** | Full 9-layer analysis with 31+ tools. Recommended for audits. |
| 🧪 **Alpha** | Pattern-based detection. Under active development. Use for research/exploration. |
| 🔬 **Experimental** | Basic parsing only. Not recommended for security decisions. |

## EVM Chains (Production)

**Status:** ✅ Production Ready

Supported networks: Ethereum, Polygon, BSC, Arbitrum, Optimism, Avalanche, and all EVM-compatible chains.

### Languages
- Solidity (0.4.x - 0.8.x)
- Vyper

### Capabilities
- **31 integrated tools** across 9 defense layers
- Full symbolic execution (Mythril, Manticore, Halmos)
- Formal verification (Certora, SMTChecker)
- Fuzzing (Echidna, Medusa, Foundry)
- AI/ML analysis (SmartLLM, GPTScan, Pattern Recognition)
- DeFi-specific patterns (20+ attack categories)
- RAG-enhanced analysis with 32+ SWC entries

### Usage
```bash
miesc scan contract.sol                    # Quick scan
miesc audit full contract.sol              # Full 9-layer audit
miesc audit batch ./contracts -p thorough  # Batch audit
```

---

## Solana (Alpha)

**Status:** 🧪 Alpha - Pattern Detection Only

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

## NEAR Protocol (Alpha)

**Status:** 🧪 Alpha - Pattern Detection Only

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

## Move (Sui/Aptos) (Alpha)

**Status:** 🧪 Alpha - Pattern Detection Only

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

## Stellar/Soroban (Alpha)

**Status:** 🧪 Alpha - Pattern Detection Only

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

## Algorand (Alpha)

**Status:** 🧪 Alpha - Pattern Detection Only

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

## Cardano (Alpha)

**Status:** 🧪 Alpha - Pattern Detection Only

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
Use **EVM analysis** for comprehensive security assessment:
- Full 9-layer defense coverage
- 31 specialized tools
- Proven detection capabilities (100% precision on benchmarks)
- Professional report generation

### For Research/Exploration
Non-EVM analyzers are useful for:
- Initial vulnerability scanning
- Pattern identification
- Security research
- Pre-audit exploration

**Do not rely solely on alpha analyzers for production security decisions.**

---

## Roadmap

| Phase | Chains | Target |
|-------|--------|--------|
| v4.5 (Current) | All 7 chains | Pattern detection |
| v5.0 | Solana, NEAR | Enhanced analysis, tool integration |
| v5.5 | Move, Stellar | Formal verification research |
| v6.0 | All chains | Production-grade multi-chain |

---

## Contributing

We welcome contributions to improve multi-chain support:

1. **Add detection patterns** - Extend vulnerability patterns for any chain
2. **Tool integration** - Help integrate chain-specific security tools
3. **Testing** - Provide test cases from real vulnerabilities
4. **Documentation** - Improve chain-specific documentation

See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.
