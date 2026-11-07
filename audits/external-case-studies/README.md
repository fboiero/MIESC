# External audit case studies

This directory records **MIESC dogfooding runs against external, third-party smart-contract
protocols**. Each case study shows the full workflow MIESC is built for: run the automated
static-analysis scan, then apply a disciplined **manual triage** that separates real issues
from the (many) false positives a scanner produces. These are kept as an evidence trail of
MIESC's real-world behaviour, not as formal audit opinions.

> **TL;DR:** Across seven mature-enough targets (Lombard LBTC, Doppler, Valantis STEX, YieldNest,
> Arcadia lending-v2, Revert v4lend, Malda), **every High-severity finding the scanner produced was
> a false positive** once read against the real code. On the newest (Malda) a real, judged High
> *did* exist — but it lived in a trust-boundary invariant the static scanner cannot express, the
> sharpest illustration yet of why the **triage layer, not the raw scan, is the product.**

---

## Scope & ethics (please read)

These case studies were produced under strict, self-imposed constraints:

- **Public information only.** Only **public source code from public GitHub repositories** was
  accessed. Every target is an open-source project whose code is published by its own team.
- **Static analysis only.** The work is limited to reading source code and running static
  analysis (Slither) on a local checkout. **No live systems, deployed contracts, RPC endpoints,
  front-ends, APIs, databases or private infrastructure were accessed.** No credentials were used.
- **No exploitation.** **No on-chain transactions, no deployed-contract interaction, and no
  proof-of-concept exploit was executed against any live system.** Where exploitability is
  discussed, it is reasoned from the source code and dependencies, and labelled as such.
- **No bug-bounty submissions.** **Nothing in this directory was submitted to any bug-bounty
  program** (Immunefi, Cantina, etc.). Un-triaged scanner output is noise; submitting it would
  spam programs that require a mandatory PoC and charge non-refundable fees. Any good-faith
  disclosure to a project is the maintainer's own, separate action.
- **Good faith & reproducibility.** Each run is pinned to a specific public commit. Findings are
  reported honestly, including when the verdict is "false positive" or "not exploitable". The
  intent is to demonstrate MIESC and, where a genuine code-quality nit exists, to be helpful to
  the project — never to pressure or embarrass anyone.

Nothing here should be read as a claim that a target is insecure. If anything, a clean triage
(all scanner Highs being false positives) reflects well on a project's engineering.

---

## Methodology (reproducible)

Each case study followed the same pipeline:

1. **Clone** the public repo at a pinned commit; fetch git-submodule dependencies over HTTPS.
2. **Compile** with Foundry (`forge build --build-info`), honouring the project's own
   `foundry.toml` (solc version, EVM version, `via_ir`, optimizer).
3. **Scan** with Slither, reusing the Foundry build (`slither . --foundry-ignore-compile --json`).
4. **Normalize** the Slither output into MIESC's results schema, filtered to the project's **own
   source** (`src/`), excluding dependencies (`lib/`), mocks and interfaces.
5. **Report** with `miesc report -t premium` (and the Spanish `profesional-es` template), rendered
   to PDF.
6. **Triage** every High finding by reading the real code (and, when a finding depends on a
   library, that dependency too), classifying each as false positive, code-quality nit, or real
   issue, with the reasoning recorded.

Each sub-directory contains: the triage write-up (`triage-memo.md`), a focused triage PDF
(`triage-focused.pdf`), and the normalized scan results (`results.json`). Full multi-hundred-page
premium PDFs are regenerable from `results.json` and are not committed here to keep the repo light.

---

## Case studies

| Target | Commit | Scan (own `src/`) | Triage verdict |
|--------|--------|-------------------|----------------|
| **Lombard LBTC** (`lombard-finance/evm-smart-contracts`) | `7fe83e5` | 30 security-relevant (3 High) | All 3 High = false positives; one real **non-exploitable** code-quality bug (`AssetRouter._changeNativeToken` no-op `delete`) |
| **Doppler** (`whetstoneresearch/doppler`) | `5754c7e` | 275 (0 Crit / 14 High / 106 Med / 88 Low / 67 Info) | **0/14 High exploitable** — access-gated sends, V2-LP-safe transfers, V4-lock + `nonReentrant`/CEI reentrancy |
| **Valantis STEX** (`ValantisLabs/valantis-stex`) | `27b5c74` | 246 (0 Crit / 3 High / 34 Med / 57 Low / 152 Info) | **0/3 High exploitable** — Sovereign-Pool callback is `onlyALM` + depositor-pinned; native-wrap + owner/`nonReentrant` settle |
| **YieldNest** (`yieldnest/yieldnest-protocol`) | `034cd65` | 225 (0 Crit / 5 High / 38 Med / 98 Low / 84 Info) | **0/5 High exploitable** — role-gated ETH sends to canonical/internal recipients; the one reentrancy is CEI-ordered + structurally unreachable |
| **Arcadia lending-v2** (`arcadia-finance/lending-v2`) | `dc2ccb9` | 85 (0 Crit / 2 High / 35 Med / 48 Low / 0 Info) | **0/2 High exploitable** — `arbitrary-send-erc20` on `onlyTranche` / `onlyLiquidator` functions; the team already suppressed both with inline lint comments |
| **Revert v4lend** (`revert-finance/v4lend`) | `f6d0fb41` | 441 (0 Crit / 36 High / 144 Med / 163 Low / 98 Info) | **0/36 High exploitable** — reentrancy under the vault's `transformedTokenId` mutex / trusted-asset direct path, OZ `ReentrancyGuard` automators and owner-registered hook callees; ETH sends to the position's NFT owner or trusted Uniswap routers; `incorrect-shift`/`-exp` fired only in Uniswap v4-core deps |
| **Malda** (`malda-protocol/malda-lending`) | `ab4fa9b2` | 195 (0 Crit / 2 High / 25 Med / 80 Low / 88 Info) | **0/2 scanner Highs exploitable** — `arbitrary-send-eth` is an ETH-rescue to a constructor-set address, `reentrancy-balance` is the caller's own Mendi→Malda migration via trusted markets. The contest's one judged **High (H-1)** — an unchecked cross-chain `receiver` in `EverclearBridge` — sat in the same rebalancer subsystem but **outside Slither's lens** (a trust-boundary invariant, not an `arbitrary-send-*` pattern) |

### lombard-lbtc-2026-10
Lombard LBTC (Bitcoin-backed liquid token). The three scanner Highs (private-constant "shadowing",
MINTER_ROLE-gated `arbitrary-send`) were false positives. The one genuinely real finding —
`AssetRouter._changeNativeToken` runs `delete $.routes[key]` on a mapping-only struct (a Solidity
no-op, so old routes persist) — was traced and found **not attacker-exploitable** (deposit re-keys
on the current native token; redeem is gated by a `CALLER_ROLE` the change revokes). It is a
correctness/operational hardening nit, documented in `finding-mapping-deletion.md`.

### doppler-2026-10
Doppler (Uniswap V4 token-launchpad). All 14 scanner Highs were false positives: `arbitrary-send`
variants are access-gated (`onlyAirlock`, canonical-pool callbacks, payer hard-set to `msg.sender`)
or send to the trusted immutable PoolManager; `reentrancy-eth` findings sit inside V4's `unlock`
lock with a trusted callee, and the fee-claim paths are `nonReentrant` + CEI-ordered;
`unchecked-transfer` is on Uniswap V2 LP tokens that revert on failure. See `triage-memo.md`.

### valantis-stex-2026-10
Valantis STEX (Stake Exchange AMM for liquid-staked HYPE). All 3 scanner Highs were false
positives, confirmed against the `valantis-core` dependency: the deposit callback's arbitrary
`from` is defended because `SovereignPool.depositLiquidity` is `onlyALM` and the STEXAMM pins the
callback `user` to the original depositor; the "arbitrary ETH send" is a native→WHYPE wrap; the
reentrancy is `onlyOwner` + `nonReentrant` with trusted callees. See `triage-memo.md`.

### yieldnest-2026-10
YieldNest (EigenLayer restaking — ynETH native-ETH LST + ynEigen LSD restaking). All 5 scanner
Highs were false positives: four `arbitrary-send-eth` sit on role-gated functions
(`WITHDRAWER_ROLE`, `VALIDATOR_MANAGER_ROLE`, `WITHDRAWAL_MANAGER_ROLE`) whose ETH recipients are
canonical (the ETH2 deposit contract) or protocol-internal (`ynETH`, `redemptionAssetsVault`,
admin-set `feesReceiver`); the one `reentrancy-eth` (`PooledDepositsVault.finalizeDeposits`) is
CEI-ordered (balance zeroed before the call), sends ETH to the trusted vault rather than the
depositor, and `deposit()` is disabled once `ynETH` is set — so it is structurally unreachable.
See `triage-memo.md`.

### arcadia-lending-v2-2026-11
Arcadia Finance lending layer (margin lending on Base — `LendingPool`, `Tranche`, liquidators).
Both scanner Highs were false positives: `LendingPool.depositInLendingPool` is `onlyTranche` and
`LendingPool.auctionRepay` is `onlyLiquidator`, so the "arbitrary" `transferFrom(from, …)` always
takes `from` from a trusted internal caller (a registered Tranche, or the Liquidator passing the
real bidder). Notably the Arcadia team had **already acknowledged both** with inline
`// forge-lint: disable-next-item(arbitrary-send-erc20,…)` suppressions. The only class worth a
team double-check is the liquidation-flow `reentrancy-no-eth` (trusted callees, documented
ordering). See `triage-memo.md`. Toolchain note: this target pins solc `0.8.34`, newer than the
pinned forge's bundled list — installed via solc-select and passed to forge with `--use`.

### revert-v4lend-2026-11
Revert v4lend (a Uniswap-v4-native lending & LP-automation protocol — single-asset ERC4626 vault,
v4-LP-NFT collateral, an on-swap `RevertHook`, standalone automators and transformers; the commit
carried a Cantina audit competition that **closed 03 Nov 2026**). All 36 scanner Highs were false
positives. The `reentrancy-eth`/`-balance` bulk (28) resolves per contract: `V4Vault` has no generic
guard but uses a `transformedTokenId` storage mutex plus a direct path whose only external calls are
the trusted configured ERC20 asset and Uniswap's `PositionManager`; the automators inherit
OpenZeppelin `ReentrancyGuard`; the hook action contracts call only owner-registered ERC4626 vaults.
`arbitrary-send-eth` (3) always targets the position's current NFT owner, the admin-set protocol-fee
recipient, or trusted Uniswap routers; `uninitialized-state` (4) are storage mappings with verified
cross-contract writers; `weak-prng` (1) is a rent fee-carry remainder. The high-signal
`incorrect-shift`/`incorrect-exp` detectors fired **only inside Uniswap v4-core dependencies**
(`BitMath`, `TickBitmap`, `FullMath.mulDiv`) — out of scope. Reconciled against the project's own
Cantina Scan #1/#2 tables and `audit-handoff.md`; MIESC surfaced nothing those scans had not already
found and fixed/accepted. See `triage-memo.md`. **Scoping lesson recorded:** an initial run reported
536/40-High until the owned-filter was tightened to "path **begins** with `src/`" (dependency files
under `lib/.../src/…` were being mis-promoted to first-party) — a scanner that doesn't scope
precisely manufactures its own false Highs.

### malda-lending-2026-11
Malda (a Compound-V2-style cross-chain *unified-liquidity* lending protocol — `mToken` markets, an
`Operator` comptroller, a `Rebalancer` that moves liquidity across chains through bridge adapters,
and a `Migrator` for Compound-fork positions; the ZK coprocessor is Rust and out of scope). Scoped
to the exact 26 first-party `src/` files Sherlock put in-scope. Both scanner Highs were false
positives: `arbitrary-send-eth` is `Rebalancer.saveEth` sweeping the contract's own ETH to a
constructor-set rescue address with no setter (`GUARDIAN_BRIDGE`-gated); `reentrancy-balance` is
`Migrator.migrateAllPositions` operating on the caller's own Mendi→Malda migration through trusted,
fixed markets. The notable result is a **limitation, honestly stated**: the contest's one judged
**High (H-1)** — `EverclearBridge.sendMsg` forwards a rebalancer-supplied `bytes32 receiver` into an
external `newIntent(...)` with no check that it is a valid market, letting the privileged rebalancer
redirect bridged funds — lived in the same subsystem the scanner flagged yet was **invisible to
Slither**, because it is a trust-boundary / business-logic invariant, not a native-ETH send
(`arbitrary-send-eth`) or a tainted `transfer` (`arbitrary-send-erc20`). All 16 judged Mediums are
likewise semantic (rounding, oracle, bridge-flow, DoS); the static scan found none of them. This is
the clearest demonstration in this directory of **where the static lens ends and semantic review
must begin.** See `triage-memo.md`.

---

*Generated with MIESC. Targets, commits and dependencies are cited inline. Questions or
corrections: open an issue.*
