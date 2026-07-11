# Multi-Chain Support

MIESC provides production security analysis for **EVM chains**. Support for other platforms
is on the **roadmap**: experimental adapter code exists but is not production-validated.

## Support Levels

| Level | Description |
|-------|-------------|
| ✅ **Production** | Full 9-layer analysis with 50 tools across 35 analysis modules. Recommended for audits. |
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
| Current (v5.4.x) | EVM | Production (9 layers, 50 tools) |
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
