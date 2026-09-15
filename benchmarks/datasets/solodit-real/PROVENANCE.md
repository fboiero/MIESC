# Solodit-Real — Provenance & Ground Truth Methodology

Pilot corpus for MEJORAS2.md items #1/#2: real audited contracts + real,
complete (not curated-subset) audit findings as ground truth, sourced via the
Solodit MCP server (`mcp__solodit__search_findings`/`get_finding`).

## Upstream sources

| Protocol | Contest | Repo | Findings used |
|---|---|---|---|
| NextGen | Code4rena, 2023-10 | https://github.com/code-423n4/2023-10-nextgen | 18 (H-01..H-05, M-01..M-12) |
| Y2K Finance | Code4rena, 2022-09 | https://github.com/code-423n4/2022-09-y2k-finance | 27 (H-01..H-09 minus H-07, M-01..M-16 minus M-09*) |
| Sequence | Code4rena, 2025-10 | https://github.com/code-423n4/2025-10-sequence | 6 (H-01..H-02, M-01..M-04) |
| Napier | Sherlock, 2024-01 | https://github.com/sherlock-audit/2024-01-napier | 17 (H-1..H-4, M-1..M-13) |

\* `rewards/StakingRewards.sol` (and its 3 findings: M-09, M-10 partially, M-15)
was removed from this pilot — the `peculiar` adapter hangs indefinitely on it
(confirmed twice, ignores `--timeout`). Logged as a new finding in
`MEJORAS2.md`, not fixed in this pass.

Contracts are the official **in-scope** files per each contest's own README
scope table (NextGen) or `src/` layout (Y2K Finance) — not the full repo, which
also includes tests, scripts, and vendored dependencies out of scope for the
audit itself.

## Ground truth methodology (`ground_truth.json`)

Unlike SmartBugs-curated (one category inferred from the containing folder,
per contract), this manifest lists **every individual HIGH/MEDIUM finding**
from each contest's full report, with its real file and a category assigned
by hand from the finding's actual title/description/PoC (not automated).
GAS and LOW findings are excluded (not security vulnerabilities in the sense
this benchmark measures). Completeness was verified before curation: both
contests' finding IDs are sequential with zero gaps (e.g. NextGen: H-01..H-05,
M-01..M-12, G-01..G-06 = exactly 23, matching the total `search_findings`
returned) — a strong signal each is the *complete* report, not a curated
highlight reel like the ground truth SmartBugs-curated (and, likely, EVMBench)
uses.

Categories include both the 10 classic `SMARTBUGS_CATEGORIES` (from
`miesc/cli/commands/evaluate.py`) and the 5 new `MODERN_CATEGORIES` added
alongside this corpus (`business_logic`, `oracle`, `rounding`,
`fee_on_transfer`, `erc4626`) — see MEJORAS2.md item #2 for why the classic
taxonomy (SmartBugs-curated is ~2018-2020 research) misses most of what
actually shows up in real 2022+ DeFi audits.

## Known limitation: Slither/Aderyn couldn't fully compile this corpus (partially resolved)

Originally diagnosed (2026-08-14) as MIESC's Slither/Aderyn adapters copying
only the target file into an isolated temp directory, dropping sibling
imports. Re-investigated 2026-08-15 (MEJORAS2.md #4) with a controlled test —
that diagnosis was wrong for Slither (its `force_solc` path already operates
on the real file/directory) and only half-right for Aderyn (it genuinely did
copy only the target file; fixed to walk the transitive relative-import graph
instead — see `AderynAdapter._resolve_relative_imports`). The real,
dominant cause for **this corpus specifically**: `nextgen/`'s files import
sibling interfaces and locally-vendored OpenZeppelin copies
(`Ownable.sol`, `IERC721.sol`, etc.) that were never included here in the
first place — deliberately, per this corpus's own "official in-scope files
only" methodology above. Slither/Aderyn need the full compile-time closure
even though most of those files aren't graded.

`nextgen/AuctionDemo.sol` and `nextgen/MinterContract.sol`'s dependency
closures were fetched from the original repo
(`code-423n4/2023-10-nextgen`, `smart-contracts/`) and added here
(`IMinterContract.sol`, `IERC721.sol`, `Ownable.sol`, `INextGenAdmins.sol`,
`IERC165.sol`, `Context.sol`, `INextGenCore.sol`,
`IDelegationManagementContract.sol`, `MerkleProof.sol` — none of these are
graded findings sources, they exist only so Slither/Aderyn can compile the
two files above) to measure real impact before completing the rest.
**Measured impact: ~0.** Both files' TP counts were unchanged before/after
(everything Slither/Aderyn found once compiling was already caught by
pattern-based tools); `AuctionDemo.sol` lost 1 FP, `MinterContract.sol`
netted zero change. The remaining 6 `nextgen/` files' dependencies were
**not** fetched — the measured return doesn't justify it. Other tools
(pattern-based: fouranalyzer, smartbugs_detector, peculiar, threat_model,
gas_analyzer, etc.) were never affected by any of this and still ran on
every file.

### `y2k-finance/` resolved (2026-08-16, MEJORAS3.md item 1)

Unlike `nextgen/`, this corpus's blind spot wasn't missing relative-import
siblings — it was **package imports** (`@solmate/`, `@chainlink/`,
`@openzeppelin/contracts/token/ERC1155/...`). All 4 `y2k-finance/` files
using them failed to compile under Slither/Aderyn (`ParserError: Source ...
not found`), leaving 40% of this corpus's Layer 1 blind. Root-caused to
three separate adapter bugs (not a corpus problem, fixed in
`SlitherAdapter`/`AderynAdapter` for every user, not just this benchmark):

1. `@solmate/...` and `@chainlink/...` (npm-style `@`-prefixed aliases) were
   canonicalized to a single guessed dependency key (`"solmate"`,
   `"@chainlink/contracts"`) that didn't match what these files actually
   wrote, so the remapping never lined up with the real import prefix.
2. Slither's `force_solc` auto-detection forced raw `solc` (no remapping
   support at all) for any standalone file, `--compile-force-framework solc`
   was appended whenever a pragma-derived `solc_version` was set — which is
   virtually always — silently defeating the dependency-workspace/foundry.toml
   path even when it successfully installed the right dependency.
3. Neither adapter deferred to a project's own already-vendored `lib/` when
   one existed; both always spun up an isolated temp workspace and tried a
   fresh, floating-version `forge install`, ignoring pinned versions.

Fixing (1)-(3) alone doesn't fully solve *this* corpus, though: it's a real
2022-era contract (fixed `pragma solidity 0.8.15`), and floating-latest
OpenZeppelin/Chainlink have since drifted incompatibly (OpenZeppelin v5
moved `ReentrancyGuard.sol` and requires solc `^0.8.24` in
`ERC1155Supply.sol`; `smartcontractkit/chainlink`'s default branch dropped
its `contracts/` directory entirely, and even installing an old pinned tag
of that monorepo reliably hangs on nested-submodule checkout). So, same
policy as `nextgen/` above: the corpus's own dependency closure was vendored
here, pinned to versions contemporaneous with the original audit —
OpenZeppelin `v4.8.3`, `transmissions11/solmate` (unpinned; solmate is small
and hasn't broken compatibility), and the 3 Chainlink aggregator interfaces
from `smartcontractkit/chainlink-evm@v0.3.3` (the same files, just from the
repo Chainlink split them into — the old monorepo path is what hangs).
`y2k-finance/foundry.toml` + `y2k-finance/lib/` here mirror the real
project's own `remappings.txt`
(`code-423n4/2022-09-y2k-finance/remappings.txt`). The exact 13-file
transitive closure (not a full library clone) was determined by actually
running `forge build` against this pinned set and taking its real output
manifest — not guessed by hand.

**Measured impact:** all 5 `y2k-finance/` files now compile and produce
findings under both Slither and Aderyn (previously: 0/5 — every file has at
least one package import, including the otherwise-standalone
`PegOracle.sol`). `evaluate corpus benchmarks/datasets/solodit-real --layers
1` now runs Layer 1 on the full 10-contract corpus with no compile failures.

## Fresh blind-validation additions (2026-08-17): Sequence, Napier

Sequence and Napier were added later, for a different purpose than the pilot
above: they were never seen or referenced while building MIESC's detectors, so
they answer "can MIESC actually find findings from a real report it has never
looked at" instead of just measuring recall against a fixed corpus. Sequence
(wallet/signature protocol) was picked first; Napier (yield-tranching/AMM
DeFi protocol) was picked second, deliberately, because DeFi-flavored
contracts are closer to where MIESC's detector set is meant to specialize.

Both were verified the same way: pin a single real commit by reading actual
file content (not trusting `blob/main` links), confirm the repo is public and
the buggy code is present, categorize each finding by hand from its real
title/description, and — critically — manually trace every nominal true
positive back to the actual detector logic that fired via direct
`run_layer(7, ...)` calls, instead of trusting a same-file/same-category
match. See each protocol's `measured_result` field in `ground_truth.json`'s
`_meta.protocols` for the full trace. Both came back honestly negative: every
nominal TP on both protocols turned out to be a generic pattern (a STRIDE
template, a bare `.approve()` regex, a "mint function without access control"
heuristic) that happened to share a file and category with the real bug, not
an actual detection of it. Real recall on genuinely unseen findings is closer
to 0/6 (Sequence) and 0/17 (Napier) than the nominal precision/recall numbers
suggest.

## Licensing

Contracts retain their original project licenses (see each contest repo).
No additional license is asserted by MIESC over this third-party code; it is
included solely for benchmark reproducibility, same policy as
`../smartbugs-curated/PROVENANCE.md`.

## Reproducing / extending

```bash
python -m miesc.cli.main evaluate corpus benchmarks/datasets/solodit-real \
    --layers 1,6,7 -o result.json
```

To add another protocol: pick one with a verifiably complete report
(sequential finding IDs, no gaps — check via
`mcp__solodit__search_findings(protocol=..., firms=[...])`), copy its
official in-scope files, and append entries to `ground_truth.json` with real
file/category per finding (see MEJORAS2.md item #1 for the full recipe).
