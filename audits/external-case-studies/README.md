# External audit case studies

This directory records **MIESC dogfooding runs against external, third-party smart-contract
protocols**. Each case study shows the full workflow MIESC is built for: run the automated
static-analysis scan, then apply a disciplined **manual triage** that separates real issues
from the (many) false positives a scanner produces. These are kept as an evidence trail of
MIESC's real-world behaviour, not as formal audit opinions.

> **TL;DR:** Across ten mature-enough targets (Lombard LBTC, Doppler, Valantis STEX, YieldNest,
> Arcadia lending-v2, Revert v4lend, Malda, Royco Dawn, Reserve Governor, Revert StableSwap Hooks),
> **every High-severity finding the scanner produced was a false positive** once read against the real
> code. The spread of targets sharpens *why* the triage layer matters: on Malda a real judged High
> lived in a trust-boundary invariant the scanner cannot express; on Royco Dawn the one real High-class
> bug (an ERC-777 reentrancy) sits behind a Slither flag, but the scanner cannot tell it from seven
> benign look-alikes; Reserve Governor is the mirror image — on pure governance code the scanner is
> **silent (0 High)**, correctly; and on Revert StableSwap Hooks the scanner flagged the *exact function*
> of the one judged High (a native-ETH `removeLiquidity` reentrancy) yet **ranked it Medium**, because
> the ETH exits via `poolManager.take` rather than a recognised value-send — the sharpest case of
> *locating* a bug without *adjudicating* it. Loud or silent, located or missed, the lesson holds: the
> **triage layer, not the raw scan, is the product.**

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
| **Royco Dawn** (`roycoprotocol/royco-dawn`) | `d5f9360c` | 382 (0 Crit / 1 High / 41 Med / 53 Low / 287 Info) | **0/1 scanner High exploitable** — `arbitrary-send-erc20` on `requestDeposit` is double-gated (AccessManager `restricted` + ERC-7540 operator model) and sends to the fixed kernel. Cantina closed **262 submissions → 0 valid, 0 High**. The real ERC-777 reentrancy (`stRedeem`) *does* sit behind one of eight `reentrancy-no-eth` Mediums the scanner raised — it **locates but cannot adjudicate** the one real vector (needs the ERC-777 precondition + NAV invariant) |
| **Reserve Governor** (`reserve-protocol/reserve-governor`) | `dc27a684` | 66 (0 Crit / **0 High** / 9 Med / 19 Low / 38 Info) | **0 scanner Highs at all** — on governance code the lens is silent, matching Cantina's judged **0 valid Highs / 1,465 submissions** (Medium-tier payout). The 9 Mediums are benign noise; the real risk (optimistic/standard proposal ID collisions, selector-whitelist, timelock bypass, CEI ordering — `cancelLock` M-01 & M-02 fixed pre-commit) is governance logic with no detector class. The only `arbitrary-send-eth` Highs are in OZ's `Governor`/`Timelock` base, correctly scoped out |
| **Revert StableSwap Hooks** (`revert-finance/stableswap-hooks`) | `cf0c30e5` | 76 (0 Crit / 6 High / 17 Med / 20 Low / 33 Info) | **0/6 scanner Highs exploitable** — two `arbitrary-send-*` on caller-own/caller-chosen funds behind the `onlyPoolManager` unlock callback, `encode-packed-collision` on a hash-pinned creation code, two `incorrect-exp`/`-shift` on Solady's formally-verified `cbrt`, one `reentrancy-eth` on add-liquidity whose only reentrant send runs post-commit. Reconciled vs the project's own `CANTINA.md` (**1 High + 11 Mediums**): Slither flagged the *exact function* of the one judged High (#29, native-ETH `removeLiquidity` reentrancy) but **ranked it Medium** — the ETH exits via `poolManager.take`, invisible to `reentrancy-eth`; the 11 economic findings have no detector class |

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

### royco-dawn-2026-11
Royco Dawn (a *perpetual risk-tranching* protocol — senior/junior ERC-7540 async-vault tranches over
a `RoycoKernel`/`RoycoAccountant`/YDM stack, where the junior is first-loss capital and the senior is
drawdown-protected). Scoped to the whole first-party `src/` the Cantina competition named. The single
scanner High — `arbitrary-send-erc20` on `RoycoVaultTranche.requestDeposit` — is a false positive: the
`transferFrom(_owner, …)` is double-gated by the OZ AccessManager (`restricted`) **and** the ERC-7540
operator model (`onlyCallerOrOperator`), and sends to the tranche's own fixed `kernel()`, never an
arbitrary recipient. That lands in the first of the competition's two reward classes
("non-whitelisted / unspecified recipients"), which **262 submissions closed with 0 valid, 0 High**.
The instructive part is the one real High-class issue the protocol's own deep reviews (Hexens, Certora
FV) point to — an **ERC-777-hook reentrancy** that corrupts tranche NAV if the senior underlying is an
ERC-777 whose transfer callback re-enters `_preOpSyncTrancheAccounting`. Unlike Malda's blind spot,
Slither here *did* flag the exact function (`stRedeem`) as `reentrancy-no-eth` (Medium) — but among
**eight** look-alike deposit/redeem `reentrancy-no-eth` Mediums, all benign for a standard ERC-20. The
scanner produces the candidate set; it cannot rank or confirm within it, because the one real vector
rests on a token-standard precondition and a NAV-solvency invariant it does not model. The NAV
division-by-zero, fee-threshold-unmintability and fee-compounding findings have **no static flag at
all**. The lesson: **static locates, semantic review adjudicates.** See `triage-memo.md`.

### reserve-governor-2026-11
Reserve Governor (a hybrid optimistic/standard on-chain governance system over OpenZeppelin
Governor + TimelockController — an ERC4626 `StakingVault` with vote-locking and multi-token rewards,
a fast/veto proposal path, an `OptimisticSelectorRegistry` whitelisting `(target, selector)` pairs,
and a `TimelockControllerOptimistic` with an optimistic bypass). This is the **mirror image** of the
vault/lending targets: scoped to the first-party `contracts/`, MIESC's default scan produced
**0 Critical and 0 High** — the static lens is *silent* on governance logic — and that matches the
competition's judged outcome exactly: the public Cantina leaderboard shows **0 valid Highs across
1,465 submissions** (the pot settled at the Medium tier). The 9 owned Mediums are benign detector
noise (`incorrect-equality`, an ERC4626 `_withdraw` `reentrancy-no-eth` benign by callee trust, and
ignored `EnumerableSet`/`deposit` return values). Every real issue the competition and the project's
own committed pre-contest review surfaced is **governance / trust-boundary logic** with no detector
class — optimistic/standard proposal ID collisions, veto-threshold boundaries, selector-registry
whitelisting, timelock-bypass correctness, throttle rounding, and a `cancelLock` CEI-ordering theft
(review M-01) plus a reward-accounting nit (M-02), **both already fixed before the contest commit**
(verified). Scoping note: the only `arbitrary-send-eth` Highs in the whole run are OZ's own
`Timelock`/`Governor` execution paths (`_execute`, `_executeOperations`, `relay`) — the timelock's
by-design arbitrary send, correctly excluded as a dependency; a scanner that counted `node_modules/`
as first-party would manufacture three phantom "governance" Highs. Dependencies were staged via
`npm pack` (download-only) plus the project's pnpm OZ patch, without running the repo's install
scripts. See `triage-memo.md`.

### revert-stableswap-hooks-2026-11
Revert StableSwap Hooks (a Uniswap v4 hook bringing Curve-style StableSwap AMM behaviour — a
constant-sum/product blend with amplification `A` — to v4 pools, with v2-style ERC20 LP tokens, rate
oracles, and a `StableSwapZapIn` single-token-deposit periphery). This is the **richest reconciliation
in the directory**, because the project publishes its own findings log (`CANTINA.md`, committed in-repo):
the competition validated **1 High (#29) + 11 Mediums**. All six scanner Highs are false positives: two
`arbitrary-send-*` move the caller's own (or caller-chosen) funds behind the `onlyPoolManager` unlock
callback; `encode-packed-collision` is defused by a `keccak256`-pinned creation code; the two
`incorrect-exp`/`-shift` fire on `cbrt`, lifted verbatim from Solady's formally-verified
`FixedPointMathLib`; and the lone `reentrancy-eth` on `_handleAddLiquidityCallback` is benign (its
flagged `settle{value}` goes to the trusted PoolManager, and the only attacker-reachable ETH refund
runs after all reserves are committed) — not a judged finding, though the team applied the CEI reorder
there anyway (#131). The instructive part is the one judged **High (#29)**, a native-ETH
`removeLiquidity` reentrancy present at the scanned commit: Slither flagged the **exact function**
(`_handleRemoveLiquidityCallback`) as a reentrancy site — but as **`reentrancy-no-eth` (Medium)**, not
the High it is, because the ETH exits via `poolManager.take(currency, sender, amount)` (a plain call,
no `{value}`), so `reentrancy-eth` never fires. The remaining eleven Mediums are pure StableSwap
economics (rounding asymmetry, a missing fee floor, invariant overflow, zap-in sizing, exact-output
rounding) with no detector class. Static **located** the one real High but could not **adjudicate** its
severity, and was blind to the economic majority — the clearest "locate, don't adjudicate" case here.
See `triage-memo.md`.

---

*Generated with MIESC. Targets, commits and dependencies are cited inline. Questions or
corrections: open an issue.*
