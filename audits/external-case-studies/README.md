# External audit case studies

This directory records **MIESC dogfooding runs against external, third-party smart-contract
protocols**. Each case study shows the full workflow MIESC is built for: run the automated
static-analysis scan, then apply a disciplined **manual triage** that separates real issues
from the (many) false positives a scanner produces. These are kept as an evidence trail of
MIESC's real-world behaviour, not as formal audit opinions.

> **TL;DR:** Across three mature-enough targets (Lombard LBTC, Doppler, Valantis STEX), **every
> High-severity finding the scanner produced was a false positive** once read against the real
> code. That is the expected outcome for audited production code — and it is exactly why the
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

---

*Generated with MIESC. Targets, commits and dependencies are cited inline. Questions or
corrections: open an issue.*
