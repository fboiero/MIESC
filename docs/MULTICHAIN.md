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

## Polkadot (Experimental)

**Status:** 🧪 Experimental — PolkaVM / `pallet-revive`, via Slither / Aderyn / Solhint plus built-in `polkavm_diff` (class-B heuristics) and `polkavm_resolc` (class-A, runs the compiler)

Polkadot has three distinct smart-contract models; MIESC covers them as follows:

- **EVM parachains (Moonbeam, Astar EVM)** — standard EVM via Frontier / `pallet-evm`.
  **Already covered** by MIESC's production EVM analysis; nothing new is needed.
- **PolkaVM / `pallet-revive`** — Solidity compiled with `resolc` to PolkaVM (RISC-V), run on
  Asset Hub. **This experimental support.** Run it with `--target polkavm`.
- **ink!** (Rust → WASM on `pallet-contracts`) — the language was discontinued (Jan 2026);
  tracked as secondary future work.

### What `--target polkavm` does

Routes a Solidity contract to the Solidity **source-level** tools (Slither, Aderyn, Solhint) plus
the two built-in PolkaVM adapters — **`polkavm_diff`** (class-B heuristics) and **`polkavm_resolc`**
(class-A, runs `resolc`) — and **skips** EVM bytecode / symbolic / fuzzing tools — the compiled
target is RISC-V, not EVM, so EVM-bytecode tools do not apply. Without the flag, the EVM path is
unchanged.

### PolkaVM "difference-with-EVM" checks

`polkavm_diff` flags code that compiles and is correct on the EVM but is insecure or behaves
differently on PolkaVM (silent runtime differences, per the revive compiler book):

- Unlimited-gas external call — no 63/64 gas rule on PolkaVM → DoS vector
- Unbounded memory — fixed 128kb buffer → runtime trap (OutOfBound)
- `CREATE2` / `creationCode` — address derived from code hash, EVM precomputation breaks
- `block.prevrandao` / `difficulty` — a constant on PolkaVM → predictable randomness
- via-ir constructor init-order — base constructors run before derived state-var initializers
- `selfdestruct` — compiles under `resolc` (verified); flagged because its runtime behaviour on `pallet-revive` may differ from the EVM (runtime semantics not independently confirmed)

### PolkaVM compile-compatibility checks (class A)

`polkavm_resolc` runs `resolc` and reports opcodes the compiler **rejects** at its LLVM-IR phase
(measured: `EXTCODECOPY`, `BLOBHASH`; `PC` is rejected earlier by `solc`, so it is an honest error,
not a finding) as `polkavm-unsupported-opcode` findings (High, confidence 0.99) — authoritative
deployability blockers, since the compiler itself is the oracle. A clean compile (exit 0) yields no
finding; any non-rejection compile failure is an honest error, never a false "clean" (and the `npx`
wrapper rejects relative imports, so multi-file contracts are not reliably supported). The adapter is
skipped where `resolc` is unresolvable (PATH-only availability probe: `resolc`, else `node` + `npx` +
`solc`; it never downloads during the probe).

### Usage

```bash
miesc scan contract.sol --target polkavm
miesc scan contracts/ --target polkavm --recursive
```

### Limitations

- **No PolkaVM (RISC-V) bytecode analysis.** Class-B is source-level heuristics; class-A uses the
  compiler's own rejection (compile-time), not analysis of the produced `.polkavm` blob.
- `pallet-revive` is itself experimental upstream (breaking changes).
- No recall/precision benchmark yet — not for production security decisions.
- See [`docs/guides/POLKADOT.md`](./guides/POLKADOT.md) for setup and details.

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

### Detected Vulnerabilities (hardened pattern set)
The source-level pattern detector emits only genuine-vulnerability patterns, each
with a disproving control used as a suppressor (so correct Anchor code stays
quiet):
- **Unchecked arithmetic** on a financial value — unless `checked_/saturating_/
  wrapping_` is on the line.
- **Manual lamport mutation** (`try_borrow_mut_lamports`) without a visible
  authorization — the classic missing-signer withdraw shape.
- **Arbitrary CPI** — `invoke`/`invoke_signed` when the program never types a
  target as `Program<'info, _>` nor checks a key with `require_keys_eq!`.
- **Non-canonical PDA** — `create_program_address` instead of `find_program_address`.
- **Unchecked account** — `UncheckedAccount`/`AccountInfo` with no
  `owner`/`address`/`has_one`/`seeds`/`constraint`.

Plus semantic checks (missing signer on a mutable-accounts handler, account-data
matching, arithmetic safety, CPI reentrancy).

### Usage
```bash
miesc analyze program.rs --chain solana
```

### Limitations
- No symbolic execution or formal verification.
- Pattern-based (no full Anchor parse): macro-generated code, validations split
  across many lines, and cross-file flows can cause misses — it favors precision.
- **Experimental: no recall/precision benchmark.** Hardened against false
  positives (measured: a clean 41-line Anchor program went from 13 findings, 10
  of them High, to 0), but a labeled corpus is still needed to cite rates.

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
| Current (v6.8.0) | EVM | Production (9 layers, 50 tools) |
| Next | Solana, NEAR | Experimental adapters → validated analysis |
| Later | Move, Stellar | Formal-verification research |
| Future | All chains | Production-grade multi-chain |

> The research direction behind this roadmap — whether detection intelligence transfers
> *across execution models*, with an invariant theory that predicts the boundary and
> independent per-chain corpora to measure it — is set out in
> [Does Security Intelligence Transfer Across Execution Models? — A 2027 Research Program](research/UNIFIED_CROSSCHAIN_INTELLIGENCE_RESEARCH_20261113.md).

---

## Contributing

We welcome contributions to improve multi-chain support:

1. **Add detection patterns** - Extend vulnerability patterns for any chain
2. **Tool integration** - Help integrate chain-specific security tools
3. **Testing** - Provide test cases from real vulnerabilities
4. **Documentation** - Improve chain-specific documentation

See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines.
