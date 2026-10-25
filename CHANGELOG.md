# Changelog

All notable changes to MIESC will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [6.7.0] - 2026-10-25 — Vyper analyzer, directory & on-chain audit, revert-invariant Phase 2 execution

Minor release. Adds a Vyper pattern analyzer and `.vy` routing, `miesc audit deep <dir>` and
`miesc audit address <0x…>` (verified source from Etherscan V2), and completes revert-invariant
Phase 2: the deterministic gap miner's three categories now reach the execution rungs
(`test_generated` harnesses, Foundry-executed `counterexample`s, and findings for confirmed
access-control / pause / freshness gaps), all opt-in and behind the same FP filter. Two post-merge
security fixes to the new opt-in paths land here, before any of this code ships in a release.

### Added

- **Vyper analyzer and `.vy` routing (`miesc/adapters/vyper_adapter.py`, tool `vyper`, layer 1).**
  A pattern-based analyzer for Vyper sources: explicit `unsafe_*` arithmetic (Low),
  `raw_call(..., is_delegate_call=True)` to a caller-influenced target (`self` excepted),
  `create_forwarder_to`/`create_minimal_proxy_to` without an `initialize` in the same function
  (`create_from_blueprint` is not reported), `tx.origin` authorization, privileged operations
  without a caller guard, missing reentrancy protection on external calls that break
  checks-effects-interactions, and the 0.2.15/0.2.16/0.3.0 broken `@nonreentrant` lock —
  **Critical only on an exact version pin**, Low on a range that merely includes one. Reads
  `# pragma nonreentrancy on` (0.4) and `@nonreentrant("lock")` (0.3). Routing: `miesc analyze`
  picks the analyzer for `.vy`; `run_tool`/`run_layer`, the REST API and the ML path only run the
  tools whose adapter applies to the file (`applies_to`), so the Vyper analyzer adds no row to a
  Solidity audit and Solidity tools add none to a Vyper one. Measured on snekmate, Curve,
  stableswap-ng and Yearn (148 files): 451 `unsafe_arithmetic` Low, 2 reentrancy High in test
  mocks, 1 `tx.origin`, 0 access-control; the paper baseline is unchanged by construction.
  Slither's own Vyper support stays out of reach through `SlitherAdapter.can_analyze`
  (documented limit). Contributed by @alva-p (#228).

- **`miesc audit deep` on a directory, and `miesc audit address`.** `audit deep ./src` (or any
  project directory) used to stop at `IsADirectoryError`; it now runs the unchanged single-file
  pipeline on every `.sol` file (skipping `lib/`, `node_modules/`, `test/`, `script/` and build
  output), with `--timeout` as the budget for the whole directory. Each file's run also reports
  what it imports, so the merged findings and exploit chains are deduplicated (Y2K Finance
  233 -> 122, NextGen 166 -> 121, USDC 265 -> 118) and the summary is counted from them.
  Pattern-detector findings now name the analyzed file instead of a `contract.sol` placeholder.
  The report adds `protocol.contracts` (file and bases of each contract, across files) and
  `protocol.calls`, from a regex graph (`miesc/ml/protocol_graph.py`): which function of another
  contract each contract calls, through a cast (`Vault(x).withdraw()`) or anything declared with
  that type (state variable, parameter, local, struct field), with `IVault` resolved to `Vault`.
  On Y2K (11 files) and NextGen (17 files) every listed call is a real one. Findings are not
  linked across contracts yet: on both protocols a caller-to-finding link only matched generic
  patterns, never the real cross-contract bug (NextGen H-01 has no per-file finding inside
  `NextGenCore` to link to). Slither and Aderyn now look for the project's `foundry.toml` up to
  10 directories up instead of 5 (Aave keeps sources 6 below its root).
  `audit address <0x…> [--chain]` fetches the verified Solidity source through Etherscan V2 with
  the user's own key (`--api-key` or `ETHERSCAN_API_KEY`), writes it to a temporary directory
  (paths escaping it are rejected; the deployer's absolute paths lose their common prefix;
  `@scope/` packages go under `lib/` with their remapping, plus the contract's own remappings, in
  a `foundry.toml`; a contract deployed from a `lib/` dependency moves to the root, since the
  tools leave out findings under `lib/`) so Slither and Aderyn compile against the deployed
  dependency versions instead of installing the latest ones, then runs `audit deep` on it.
  Checked live on UNI (1 file, solc 0.5.16), the USDC `FiatTokenV2_2` implementation (19 own
  files + OpenZeppelin, solc 0.6.12) and the Aave V3 `PoolInstance` (36 files, solc 0.8.27): no
  compilation error, nothing installed. It is the only command that makes a network call. Stdlib
  `urllib`, no new dependency; tests mock every HTTP call. Contributed by @alva-p.

- **Revert-invariant Phase 2 (first slice): within-family access-control gap hypotheses.** The
  revert-invariant miner now compares external/public, state-changing functions that share a
  privileged verb family (`set`, `withdraw`, `upgrade`, `pause`, …) and, when some members are
  access-controlled and a sibling is not, records a `GuardGapHypothesis`
  (`observed_gap="inconsistent"`). Guards are resolved **through applied modifiers**, so a
  function guarded by `onlyOwner` counts as guarded — without that, every OpenZeppelin-style
  contract would false-positive. Advisory only: it is a hypothesis with negative checks (a guard
  may be on an unparsed/inherited modifier, the function may be intentionally permissionless, the
  property may be enforced upstream), never a `Finding`, and `promotion.state` stays `hypothesis`.
  Surfaced under `gap_hypotheses` in the plan (the deep-audit advisory phase picks it up for free)
  and round-trips through `parse_revert_invariant_plans`. Negative control: 0 hypotheses on
  OpenZeppelin `contracts/` and Solady `src/`. No benchmark claim.

- **Revert-invariant Phase 2 (second slice): within-group `pause_toggle` gap hypotheses.** The
  miner now also compares *user-facing* mutators (`deposit`, `withdraw`, `transfer`, `swap`,
  `claim`, …) as a group and, when some are pause-gated (`whenNotPaused`) and a sibling is not,
  records a `GuardGapHypothesis` (`observed_gap="inconsistent"`, category `pause_toggle`).
  Privileged/admin verbs are kept in a disjoint set and are excluded from the pause group, so an
  admin `setX` without `whenNotPaused` never pulls a user mutator into a false gap. Gating is
  resolved through applied modifiers with a three-valued classifier: an applied modifier that is
  not a locally-parsed guard (an inherited or delegating one such as OpenZeppelin `Pausable`'s
  `whenNotPaused`) marks the function **opaque** and excludes it rather than counting it as
  ungated — without that, every `Pausable` consumer would false-positive. Advisory only, never a
  `Finding`, `promotion.state` stays `hypothesis`. Negative control: 0 hypotheses on OpenZeppelin
  `contracts/` and Solady `src/` (490 files). No benchmark claim.

- **Revert-invariant Phase 2 (third slice): deadline/freshness gap hypotheses.** The miner now
  groups external/public mutators **by signature** — those that accept a `deadline`/`expiry`-like
  parameter — and, when a sibling in that group never enforces the deadline, records a
  `GuardGapHypothesis` (`observed_gap="inconsistent"`, category `freshness_check`). A deadline that
  is enforced by a modifier (DEX routers' `ensure(deadline)`), checked locally
  (`block.timestamp <= deadline`), forwarded into an inner call, or stored resolves to
  guarded/opaque and drops out; only a parameter accepted and never referenced reads as a gap.
  Forwarded/stored deadlines are treated as **opaque** (the property is delegated somewhere the
  parser cannot follow — the same epistemic state as an unresolved modifier), not asserted as a
  gap. Advisory only, never a `Finding`, `promotion.state` stays `hypothesis`. Negative control:
  0 hypotheses on OpenZeppelin `contracts/`, Solady `src/`, and Uniswap v2-periphery (≈20 deadline
  functions, all resolved guarded-by-`ensure` or opaque-by-forwarding — a non-vacuous 0). No
  benchmark claim.

- **Revert-invariant Phase 2: advisory bridge to fuzzing/oracle guidance.** New
  `miesc/llm/revert_invariant_bridge.py` turns each `GuardGapHypothesis` into a provider-neutral
  `SequenceOraclePlan` — a fuzzing/oracle obligation the existing agentic layer already
  understands and that round-trips through `parse_sequence_oracle_plans`. Each bridged plan maps
  the gap category to a property a fuzzer should try to violate (access-control / pause / deadline
  → "the call must revert"), one probe step per affected function, and carries the hypothesis'
  own negative checks in its evidence so the benign explanations travel with the obligation. The
  deep-audit advisory phase surfaces them under `capabilities.revert_invariants.oracle_plans`.
  Advisory→advisory: fixed low confidence, never a `Finding`, no executable Solidity. Silent
  exactly where the miner is silent — 0 bridged plans across OpenZeppelin, Solady and Uniswap
  v2-periphery (513 files). Bridging into `InvariantValidator` (executable assertions,
  counterexample promotion) is deliberately deferred to the reasoning-agent step. No benchmark
  claim. This completes the deterministic within-group gap layer (access-control, pause, freshness)
  plus its first consumer.

- **Revert-invariant Phase 2: `test_generated` probe harnesses.** New
  `miesc/llm/revert_invariant_harness.py` turns each gap hypothesis into a Foundry
  `vm.expectRevert` probe **harness** and advances that artifact one rung up the SDD promotion
  ladder (`hypothesis` → `test_generated`). The harness is incomplete by design: every
  contract-specific step (constructor args, call args, reaching the paused state) is an explicit
  `TODO` recorded in `blockers`, and only the category-generic, un-fakeable fragments are
  generated (an unauthorized `vm.prank` for access control, a `vm.warp` past the deadline for
  freshness). The paused state is deliberately **not** fabricated — guessing a pauser call would
  be a false probe. It is returned as an artifact (surfaced under
  `capabilities.revert_invariants.harnesses`), never as a runnable `foundry_test` fed to the
  validator, so nothing is executed and no counterexample is claimed. Actually running the
  harnesses against `InvariantValidator` and promoting to `counterexample` is deliberately
  deferred (the validator runs positive `invariant_… view` assertions with a no-arg constructor,
  a semantic mismatch for revert probes). Silent where the miner is silent — 0 harnesses across
  OpenZeppelin, Solady and Uniswap v2-periphery (513 files). No benchmark claim.

- **Revert-invariant Phase 2: access-control gap execution (`counterexample` rung).** New
  `miesc/llm/revert_invariant_executor.py` executes **access-control** gap hypotheses with Foundry
  and promotes only on a real counterexample. It is opt-in (`DeepAuditConfig.enable_gap_execution`,
  default off; surfaced under `capabilities.revert_invariants.executions`). For the subset where
  the contract deploys with a no-arg constructor and the affected function's parameters are
  elementary, it builds a self-contained probe (inlined contract + a minimal `Vm`, no `forge-std`)
  and performs the unauthorized call low-level. The test inverts on purpose — an unauthorized call
  that **succeeds** → the probe fails → `counterexample`; one that **reverts** → inconclusive, the
  hypothesis stays `hypothesis` (never downgraded to `rejected`, since a revert for an unrelated
  reason, e.g. a zero-argument `require`, is not proof the guard exists). `freshness_check` and
  `pause_toggle` are never routed here (their rejectable state can't be reached without contract
  knowledge). Forge absent, an ineligible subset, or a non-compiling probe → the gap is returned
  unchanged, never an error. Counterexamples are recorded as promoted-plan metadata, **not**
  emitted into the finding set — that bridge is a later, separately-reviewed step. Silent where the
  miner is silent (0 access-control gaps across OpenZeppelin, Solady, Uniswap v2-periphery). No
  benchmark claim.

- **Revert-invariant Phase 2: access-control counterexamples become findings.** New
  `miesc/llm/revert_invariant_findings.py` promotes an access-control **counterexample** from the
  gap executor into a finding (`type="access_control"`, `severity="High"`, `confidence=0.85`,
  `location` anchored at the real function declaration via a new `_FuncSig.decl_offset`, `evidence`
  carrying the reproduction). Emission is gated on `promotion_state == "counterexample"` exactly —
  a hypothesis or a `test_generated` harness never becomes a finding. This is the one rung that
  crosses into the finding set, and it is consistent with the precision discipline: the rule was
  "never an *unverified* finding", and a counterexample is Foundry-executed evidence. In
  `DeepAuditAgent._phase_synthesis` (opt-in, same `enable_gap_execution` flag) these findings pass
  through the **same** false-positive filter and correlation/dedup as every other finding — they do
  not bypass the controls. Negative control: 0 counterexample findings across OpenZeppelin, Solady
  and Uniswap v2-periphery (513 files). No benchmark claim.

- **Revert-invariant reasoning executor for pause/freshness gaps
  (`miesc/llm/revert_invariant_reasoning.py`).** `pause_toggle` and `freshness_check` gap
  hypotheses can now reach the `counterexample` rung that access control already reaches, without
  opening a false-positive hole. The non-negotiable precision invariant: the facts layer never
  constructs the rejectable state as ground truth — a counterexample requires **both** Foundry
  probes to agree. A *control* probe reaches the proposed state (pause the contract / pass a past
  deadline), then calls the guarded sibling (`GuardGapHypothesis.guarded_example`, a new structured
  field) and asserts it reverts, with a leading baseline call so "it reverts" means "because of the
  state"; a *target* probe reuses the executor's storage-write assertion on the unguarded sibling.
  Promotion happens only when control confirms the state **and** the target call succeeded and wrote
  storage, so a wrong fact (a pauser that does not pause, a misidentified deadline) fails closed to
  `hypothesis`. This first slice implements the deterministic local fallback only (literal cases:
  `pause`/`setPaused` + a `whenNotPaused`-style sibling; an integer deadline/expiry parameter the
  sibling checks); the provider hook signature is in place but no remote path runs yet. Opt-in via
  `DeepAuditConfig.enable_gap_reasoning` (default off, requires `enable_gap_execution`; the remote
  gate reuses `agentic_invariants_allow_remote`, no new flag). Confirmed counterexamples emit
  findings through the existing bridge and the same FP filter, typed to canonical taxonomy
  categories that aggregate correctly (`dos` → denial-of-service for pause gating, `timestamp` →
  time-manipulation for freshness) and never mislabelled as access control. The sandbox
  (`ffi=false`, scrubbed environment, network denial, cheatcode-source refusal) is reused verbatim
  from the executor and never weakened.

- **Revert-invariant reasoning agent: remote provider path.** The pause/freshness reasoning
  executor now resolves probe facts local-first (deterministic literal cases, no tokens) and, when
  the local extractor cannot name the one identity it needs (a non-literally-named pauser, or the
  deadline parameter index), asks a supplied reasoning provider for that **single** identity via
  `auto_reasoning_provider` / `ReasoningTask` (capability `counterexample_validation`, remote gate
  reuses `agentic_invariants_allow_remote`). The provider's answer is validated against the parsed
  contract, and the control+baseline probe remains the final gate — a wrong answer fails CLOSED
  (the guarded sibling will not revert in the proposed state), so the LLM can never manufacture a
  counterexample. Local-only behaviour is unchanged when no provider is passed. No benchmark claim.

- **Revert-invariant gap execution: elementary-constructor contracts.** The access-control
  executor and the pause/freshness reasoning executor previously skipped any contract whose
  constructor took arguments. They now deploy a contract whose constructor parameters are all
  elementary (uint/int/address/bool/bytesN) via a shared `_constructor_args` gate, widening the
  executable subset to the many real contracts that take e.g. an owner address or a cap. The
  constructor is deployed with **non-unset** literals — `address(this)` for every address (the
  probe is the deployer, the identity a no-arg `owner = msg.sender` would give), `1` for every
  integer, `false` for `bool`, zero `bytesN` — not zeros, so the deployed state does not read as
  "never initialised": a dead `require(lockedAt == 0)` path stays dead instead of firing as a false
  High counterexample. `evidence` records the literals used. Residual: a constructor whose
  genuinely armed value is exactly 0 or an address other than the deployer (future
  provider-proposed constructor); non-elementary constructor parameters stay ineligible. No
  benchmark claim.

### Fixed

- **`audit address`: malformed explorer payloads exit cleanly instead of crashing.** The
  `SourceCode` parse and result extraction in `fetch_verified_source` now run inside the guard, so
  a malformed standard-json, a non-list `result` or a non-object `sources` entry raises
  `BlockExplorerError` (clean `exit 1`) rather than an unhandled traceback.

- **`audit deep <dir>`: location-less findings are no longer collapsed across files.** The
  directory dedupe keyed on `(tool, type, file, line)`, which degenerated to one row per
  `(tool, type)` for every finding without a resolvable location (enriched/LLM-normalized to an
  empty location) — a recall loss. Such findings are now kept per id, or each when they have none.

- **`audit deep <dir>`: one unreadable file no longer aborts the whole run.** A file that raises
  during analysis (e.g. a non-UTF-8 source) is recorded as `{contract, error}`, counted in
  `metadata.files_failed`, and the remaining files still run, instead of discarding every report
  already gathered. The last file in a tight time budget also gets at least one second.

- **Revert-invariant reasoning executor: the control probe no longer fails open.** A post-merge
  review of the pause/freshness executor built four contracts that produced a `counterexample`
  and a Medium finding without any real gap: a `pause()` that does not pause next to a one-shot
  (`require(!claimed)`) or cooldown-gated guarded sibling, a `pause()` with an unrelated side
  effect the sibling depends on, and a freshness sibling whose "check" is `require(deadline > 0)`
  against the probe's zero literal. The cause was a single control test running baseline → state →
  sibling, so any second-call revert impersonated the guard. The control is now two Foundry tests
  from fresh state (`test_control_baseline`, `test_control_state`), the past deadline is nonzero,
  and the sibling must revert **with the guard's own revert data** (the `require` message or
  custom error read from the locally-defined modifier / local check; plain revert only when that
  payload is not readable). Results carry a `control` record (both statuses, whether the payload
  was matched). The four cases are regression fixtures; the PR's own positive and negative fixtures
  keep their outcome. `capabilities.revert_invariants.executions` now also lists the reasoning
  results when `enable_gap_reasoning` is on, so a `dos`/`timestamp` finding always has its
  execution record in the metadata.

- **Revert-invariant executor: a non-reverting guard is no longer a counterexample.** The probe
  now wraps the unauthorized call in `vm.record()`/`vm.accesses(target)` and fails only when the
  call both succeeded **and** wrote the target's storage. An early-return guard
  (`if (msg.sender != owner) return;`) or a setter that no-ops on the zero argument used to be
  promoted with the evidence "the access-control guard is absent"; both now stay `hypothesis`,
  and the evidence reads "did not revert and wrote the contract's storage". Result ids are now
  unique per privileged verb family (`<plan>-access_control-<first function>`, aligned with the
  harness ids) instead of colliding when one plan carries gaps in two families. The forge JSON
  mapping, the generated `foundry.toml`, the scrubbed environment and the probe text are now
  covered by mocked-forge tests that run in CI (the real-forge tests remain skipped where `forge`
  is absent).

### Security

- **`audit address`: the verified-source payload can no longer steer the build out of the sandbox.**
  `write_contract_to_dir` used to keep a `foundry.toml` that arrived in a contract's verified
  source, and the static analyzers honour it, so a payload `foundry.toml` with an `out`/`cache_path`
  pointing outside the temp directory made `forge build`/`forge clean` write and delete files on a
  path the contract author chose — confirmed by a planted file outside the sandbox being deleted
  during an `audit address` run. The writer now writes **only `.sol` sources** from the payload
  (an allow-list) and always generates the build config itself, with `out`/`cache_path` pinned
  inside the temp directory — closing the whole class, not just `foundry.toml`/`hardhat.config`
  (crytic-compile also auto-detects `brownie-config.yaml`, `waffle.json`, dapp/embark). The payload
  supplies sources only. Not present in any release (post-dates 6.6.0).

- **Revert-invariant executor hardened (`miesc/llm/revert_invariant_executor.py`).** The
  opt-in access-control gap executor runs the *audited* contract under Foundry, and Foundry grants
  cheatcode access to every contract a test deploys. A post-merge review of the executor showed
  that, with the default generated `foundry.toml`, a malicious contract could read the auditor's
  environment (`vm.envOr`) and send it out over `vm.rpc`/`createFork`, and that a permissive global
  `~/.foundry/foundry.toml` let it run shell commands (`vm.ffi`) and write files. The executor now
  pins `ffi = false` and `fs_permissions = []` in the generated project (verified to override the
  global file), runs `forge` with an allow-listed environment and `FOUNDRY_PROFILE=default`
  (verified: the same contract exfiltrates `unset`), denies outbound network where the host offers
  an unprivileged sandbox (`sandbox-exec` on macOS, `unshare -rn` on Linux) and records
  `isolation.network` as `denied`/`unrestricted` in every executed result (a warning is logged when
  unrestricted), and refuses to execute a source that names the cheatcode address or the
  `"hevm cheat code"` seed. `enable_gap_execution` stays off by default and is documented as
  "only on code you are willing to run".

## [6.6.0] - 2026-10-24 — Phase-1 plan miners, DeFi and Yul detectors, hardened adapters

Minor release. Four deterministic, LLM-free *plan miners* land as Phase 1 of their SDDs
(revert-invariant guards, privileged-governance authority graph, resource/liveness progress
surfaces, lending-solvency market model) together with their first consumer, an opt-in
advisory phase in the deep-audit agent that emits plans, never findings (#209, #213, #214,
#215, #219, #221). Two detector families join layer 6/7: four DeFi detectors from @alva-p
(rounding chains, fee-on-transfer, EIP-4626 signatures, unrefunded excess payment; #211) and a
Yul/inline-assembly memory-safety detector rebuilt on the real Solidity memory rules (#207).
The adapters got @alva-p's robustness pass (#197: sibling imports, dependency-only scoping, a
call-graph regex that no longer stalls, validated LLM output), `miesc export` reads the
`audit full` JSON again (#218), and the `defi` profile reaches the DeFi adapter (#220).
Paper-profile numbers on `main` after this release (SmartBugs-curated, 143 contracts, layers
1/6/7, LLM-free): recall 143/143, precision 33.7 % (281 FP), F1 50.4 % — identical, contract
for contract, to the 6.5.0 baseline (`benchmarks/results/smartbugs_eval_layers_1_6_7_20261024_post_pr211_213.json`);
the published papers report 137/143, 22.2 %, 36.0 % at v5.4.1. Nothing frozen changed.

### Added

- **Revert-invariant mining** (Phase 1 of
  `docs/SDD_REVERT_INVARIANT_MINING_20260810.md`). A deterministic, local miner
  (`miesc/llm/revert_invariant_mining.py`) that treats a contract's existing defenses as
  signal: it inventories every guard (`require` / `assert` / custom-error `revert` /
  `if (...) revert|throw`), anchors each to its source line and enclosing function, and
  normalizes it into a defensive category (access control, signature verification, replay
  prevention, freshness, pause toggle, allow/ban list, slippage, accounting cap, bounds, or
  unclassified). Output is the provider-neutral `RevertInvariantOraclePlan` contract (with
  `parse_revert_invariant_plans`), mirroring the existing oracle-plan contracts. It is
  advisory — a guard inventory, never a `Finding` and never a "missing require" accusation;
  later SDD phases (gap hypotheses, oracle/execution plans, the LLM agent) build on it.
- **Yul/inline-assembly memory-safety detector** (Phase 1 of
  `docs/SDD_YUL_ASSEMBLY_MEMORY_SAFETY_HARDENING_20260811.md`). A deterministic, local
  detector (`miesc/detectors/yul_assembly_safety_detector.py`) that models a bounded set of
  inline-assembly effects and flags three high-precision, advisory hazards:
  `yul-memory-safe-violation` (a `memory-safe` block that *structurally* corrupts the memory
  model — frees the pointer at `0x40` to a literal below `0x80`, or leaves the zero slot
  `0x60` non-zero — and does not restore it or return/revert before falling through),
  `yul-unbounded-returndatacopy` (a full `returndatacopy` into a fixed offset with no
  allocation and no terminating `return`/`revert` over the copied region) and
  `yul-arbitrary-sstore` (a slot from `calldataload` or from a parameter of an
  external/public function). A regex cannot know the runtime free pointer, so the model
  honors the Solidity memory-safety rules: temporary use at or above `mload(0x40)` without
  updating the pointer, scratch writes, clobber-then-restore and clobber-then-return are all
  safe and are not flagged. Raw `assembly` is never a finding; `yul-*` names never collapse
  Slither's informational `assembly` warning. Negative control (the claim that matters, not
  the near-empty SmartBugs assembly set): on OpenZeppelin `contracts/` and Solady `src/` —
  the libraries with the most correct assembly — it emits 0 memory-safety and 0
  returndatacopy findings; the only `arbitrary-sstore` hits are public functions that write a
  caller-supplied slot. No benchmark claim.
- **Four DeFi detectors in layer 7** (`miesc/detectors/defi_detectors.py`, contributed by
  @alva-p, #211, split 2 of 7 of #144): `rounding` (a `div*` method chained straight into a
  `mul*` method in fixed-point libraries, the form Slither's divide-before-multiply does not
  see), `fee_on_transfer` (a `transferFrom` into the contract whose function then credits the
  *requested* amount with no `balanceOf(address(this))` measurement anywhere in the file; Low,
  medium confidence, comments masked), `erc4626` (a contract exposing the deposit/withdraw/
  totalAssets trio whose signatures break the EIP-4626 arity; gate per contract, standard
  overloads allowed) and `business_logic` (a `payable` function that accepts `msg.value >=`
  a computed price and never refunds the excess; NextGen M-12). Measured on SmartBugs-curated,
  `benchmarks/real_projects/`, OpenZeppelin `contracts/` and Solady `src/`: no finding outside
  the fee-on-transfer cases that do exactly what the rule describes; the paper-profile numbers
  do not move (the four types are outside the SmartBugs taxonomy). The detectors scan with a
  linear header regex, not `CallGraphBuilder`.
- **Advisory-plan phase in the deep-audit agent** — the first consumer of the deterministic,
  LLM-free plan miners. `DeepAuditAgent`, when `enable_advisory_plans` is set (opt-in, default
  off), runs the revert-invariant, privileged-governance, resource/liveness-griefing and
  lending-solvency miners over the source and surfaces their plans under
  `report["phases"]["advisory_plans"]` (plus an `advisory_plan_count` in metadata). The phase
  needs no reasoning provider and emits plans, never `Finding`s — so it adds zero precision risk
  and never alters the finding set. A miner that raises is recorded with its error and does not
  break the audit. Until now these miners (`mine_revert_invariants`,
  `mine_privileged_governance_lifecycle`, `mine_resource_liveness_griefing`,
  `mine_lending_solvency_liquidation`) were exported but never called.
- **Lending solvency & liquidation — market model** (Phase 1 of
  `docs/sdd/SDD_LENDING_SOLVENCY_LIQUIDATION_HARDENING_20260811.md`). A deterministic, local miner
  (`miesc/llm/lending_solvency_liquidation.py`) that builds a protocol-solvency model for lending
  contracts: accounting fields (collateral, debt, shares, indexes, reserves, bad_debt), market
  parameters (collateral factor, liquidation threshold, close factor, bonus), solvency-critical
  functions (supply/borrow/repay/accrue/liquidate/…), price dependencies, and configuration actors.
  A precision gate emits a plan only when the contract looks like a lending protocol (≥1
  solvency-critical function and ≥1 accounting field). Output is the provider-neutral
  `LendingSolvencyLiquidationPlan` contract (with `parse_lending_solvency_plans`). It is advisory —
  a market-model inventory, never a `Finding` (distinct from the DeFi detectors / solvency
  invariant templates); later SDD phases build on it.
- **Privileged governance lifecycle — authority graph** (Phase 1 of
  `docs/sdd/SDD_PRIVILEGED_GOVERNANCE_LIFECYCLE_HARDENING_20260811.md`). A deterministic, local
  miner (`miesc/llm/privileged_governance_lifecycle.py`) that models a contract's privileged
  authority rather than re-matching `onlyOwner`: it inventories privileged actors (owner,
  admin, guardian, governor, proposer, executor, pauser, upgrader, keeper, …), AccessControl
  roles with their grant/revoke functions, and the edges between them and the functions they
  guard/grant/revoke, anchored to source. Output is the provider-neutral
  `PrivilegedGovernanceLifecyclePlan` contract (with `parse_privileged_governance_plans`). It is
  advisory — an authority inventory, never a `Finding` and never a "missing timelock"
  accusation (distinct from the governance findings in `advanced_detectors`); later SDD phases
  (lifecycle hypotheses, governance oracles, execution plans) build on this graph.
- **Resource/liveness griefing — progress surface** (Phase 1 of
  `docs/sdd/SDD_RESOURCE_LIVENESS_GRIEFING_HARDENING_20260811.md`). A deterministic, local miner
  (`miesc/llm/resource_liveness_griefing.py`) that models *progress* rather than re-matching
  `for (...)` loops: for each externally growable resource (dynamic array, mapping, withdrawal/
  proposal queue, pending-payment map, keeper task) it records the functions that grow it and the
  progress-critical functions (withdraw/claim/settle/execute/liquidate/…) that traverse it,
  anchored to source. Output is the provider-neutral `ResourceLivenessGriefingPlan` contract (with
  `parse_resource_liveness_plans`). It is advisory — a progress-surface inventory, never a
  `Finding` and never an "unbounded loop" accusation (distinct from the DoS detectors); later SDD
  phases (liveness hypotheses, progress oracles, execution plans) build on it.

### Changed

- The index-preserving Solidity text helpers (`_strip_comments`, `_line_of`, `_match_brace`) that
  the deterministic plan miners had each copied verbatim now live in one tested module,
  `miesc/llm/_solidity_text.py`. Internal refactor with no behavior change; `_FUNCTION_RE` stays
  per-module because the revert-invariant miner needs a superset (it also matches
  `modifier`/`constructor`) that the others must not.
- DeFi findings now carry a `type` equal to their category (`flash_loan`, `mev_exposure`,
  `rounding`, `fee_on_transfer`, `erc4626`, `business_logic`, …) instead of relying on the
  title keyword fallback. The SARIF `ruleId` becomes one per category and the `miesc baseline`
  fingerprint of these findings changes, so a baseline generated before this release reports
  them as new once.
- The `defi` audit profile runs layer 7 and the DeFi adapter (`miesc audit profile defi`); it
  listed a tool name that no longer exists (`price_oracle_checker`) and never reached
  `defi_detectors.py`, so the DeFi detectors were only reachable through `audit full`.

### Fixed

- **Adapter robustness and LLM output validation** (contributed by @alva-p, #197, split 1 of 7
  of #144). Slither and Aderyn resolve relative sibling imports and the `@openzeppelin` /
  `@solmate` / `@chainlink` package prefixes on standalone files, and scope their findings to
  the contract under audit by dropping only dependency files (`lib/`, `node_modules/`, package
  prefixes; `miesc/adapters/_dependency_scope.py`) while keeping findings inherited from
  sibling contracts and findings without a source mapping; an Aderyn sibling outside the
  project root falls back to a flat copy instead of failing. The call-graph function regex
  (`CallGraphBuilder.FUNCTION_PATTERN`) no longer backtracks catastrophically: it stalled for
  more than 60 s on Uniswap v3 `SwapRouter`, OpenZeppelin `TimelockController` and Solady
  `ERC4337`, and now takes milliseconds while also recognising `onlyRole(keccak256(...))`
  modifiers. SmartLLM enforces valid structured output (one validated retry) and accepts the
  installed coder models; LLMBugScanner falls back to an installed coding model instead of a
  configuration error, shares the LLM cache mixin and records `models_used` in its metadata.
- The lending-solvency miner's gate ("a deposit/supply/withdraw/redeem function and a
  collateral/debt/shares/reserve word anywhere in the source") accepted every vault, staking
  pool, pair and token: `supply` matched `totalSupply`, and the words were matched as
  substrings of the whole text, string literals included. Measured before the fix: the
  ERC-4626 vaults of OpenZeppelin (6) and Solady, Lido's stETH and two SmartBugs tokens all
  came out as "lending markets" (2/143 on SmartBugs, both false). The gate now requires a
  debt-side function (borrow / repay / liquidate / seize / absorb) and a `collateral` or
  `debt` identifier; accounting keywords are matched inside identifiers only, with comments
  and string contents masked; the plan anchors at the first accounting identifier (a
  declaration) instead of the first loose word or line 1. After the fix: Aave v3 (`Pool`,
  `BorrowLogic`) and Compound v3 (`CometCore`) still pass with every parameter extracted;
  SmartBugs, OpenZeppelin, Solady, Lido, Uniswap v3 and Chainlink: 0. The parser's
  `market_model` typing is fixed too (5 mypy errors).
- The resource/liveness progress-surface miner counted two things as a traversal that are
  not one: a bodiless declaration (an interface's `function execute(...) external;`) whose
  "body" became the whole next contract in the file, loops included, and the word `for`
  inside a string literal (`"Incorrect balances for bonded amount"`). On SmartBugs-curated
  10 of its 14 surfaces came from those two artifacts (parity_wallet ×8, spank_chain ×2).
  Two shared helpers in `miesc/llm/_solidity_text.py` fix it for every miner: `_body_brace`
  (returns no body when a `;` precedes the next `{`) and `_mask_strings` (blanks literal
  contents, offsets preserved); a traversal now also requires the resource to be referenced
  inside the loop's header or block, not merely somewhere in the same function. The
  revert-invariant miner's span table had the same bodiless-declaration pattern and uses the
  same helper. Corpus after the fix: 5 surfaces in 3 contracts (rubixi, etheraffle ×2,
  send_loop ×2), all real loops; real-project sweep unchanged (Aave's one real surface).
- `miesc export` read only the `results` list, so every format (SARIF, CSV, JSONL,
  Markdown, HTML, GitHub annotations) exported zero findings from the JSON that
  `audit full` writes through the ML orchestrator (`raw_findings` / `ml_enhanced`,
  no `results` key); observed on a real run with 64 findings. The exporters now
  share the result-file normalisation `report` already used
  (`miesc.cli.utils.results_from_result_file`): `ml_enhanced.findings` first (the
  complete, severity-adjusted list), then `top_findings`, then `raw_findings`
  (capped to 20 entries by the orchestrator), regrouped per tool; `contract_path`
  is honoured as the contract name.

## [6.5.0] - 2026-10-23 — Configurable LLM providers and access-control precision

Minor release. One registry now decides which LLM backends exist and how to reach them:
Claude, GPT, DeepSeek, Kimi (Moonshot), a local Ollama, or any OpenAI-compatible endpoint you
declare in the config; `scan --model`, `audit deep --llm-provider`, the `--verify-fp` advisory
pass, `MIESC_LLM_PROVIDER`, `miesc doctor` and the EVMBench harness all read it (#204, #203,
#208). On the detection side the access-control rules need an unguarded privileged operation
(#202). Paper-profile numbers on `main` after this release (SmartBugs-curated, 143 contracts,
layers 1/6/7, LLM-free): recall 143/143, precision 33.7 % (281 FP), F1 50.4 %; the published
papers report 137/143, 22.2 %, 36.0 % at v5.4.1. Nothing frozen changed; `make bench`
reproduces the new figures into a dated artifact and `make reproduce` keeps checking the old.


### Added

- **Configurable LLM providers.** `miesc/core/llm_providers.py` is the single registry of
  backends: built-in `anthropic`, `openai`, `deepseek`, `kimi` (Moonshot, OpenAI-compatible)
  and `ollama`, plus any OpenAI-compatible endpoint declared under `llm.providers` in the
  config (`kind`, `base_url`, `api_key_env`, `default_model`, `models`). `scan --model` takes
  `provider[:model]` (`kimi`, `kimi:kimi-k2-thinking`, `ollama:qwen2.5-coder:32b`,
  `deepseek:pro`) next to the historical aliases and rejects unknown providers before any
  analysis; `audit deep --llm-provider` and `MIESC_LLM_PROVIDER` accept any registered name;
  `miesc doctor` lists every provider, whether its key variable is set and whether the
  default model is reachable, without printing keys. The frontier adapter and the
  orchestrator build their clients from the registry (base URL, key, timeout), which removes
  the DeepSeek special case that used to overwrite `OPENAI_API_KEY` in the process
  environment. Guide: `docs/guides/LLM_PROVIDERS.md`. The ensemble provider list and the
  older OpenAI-only agents are not on the registry yet.
- `benchmarks/evmbench_eval.py --model` resolves through the registry too (any provider as
  `provider[:model]`, Kimi included); `deepseek` and `ollama` keep their harness meaning
  (`deepseek-chat`, `qwen2.5-coder:32b`) so earlier runs stay comparable. Evidence note:
  `docs/internal/DETECT_MULTIPROVIDER_EVMBENCH_2026-10.md`.
- The `--verify-fp` advisory LLM pass (`--verify-model`) reads the same registry: any
  provider as `provider[:model]`, a cheaper default tier per vendor, `MIESC_VERIFY_<NAME>_MODEL`
  to override it; an unknown provider disables the pass rather than guessing an endpoint.

### Changed

- **Access-control false positives.** New `miesc/detectors/access_guards.py` (caller guard:
  any `only*` modifier, a `msg.sender` condition or a role mapping used as a boolean;
  self-service withdrawal: value to the caller or to a recipient whose own entry is read, or
  a `msg.value` refund, never the contract balance). The layer-6 access-control rules,
  Peculiar's rule and the intelligence gap-fillers use them; legacy-constructor rules need a
  public unguarded function assigning `msg.sender` to an owner-like variable in a contract
  without a real constructor, and the intelligence regex no longer runs across contracts;
  array writes count only when the array shrinks or the caller supplies length or index;
  "Ownership Not Renounced" (advanced detector) is a note, out of the scoring taxonomy.
  SmartBugs-curated (LLM-free): recall 143/143, precision 31.9 % → 33.7 %
  (305 → 281 FP), F1 50.4 %; `access_control` 66 → 42 FP. The 36 contracts
  left with a spurious `access_control` carry Slither's `arbitrary-send-eth` or a real
  `tx.origin` / `selfdestruct` under another label.

### Fixed

- Aderyn runs with `--skip-update-check` (aderyn 0.1.x panics when its GitHub version check
  is rate-limited) and gets the running interpreter's `solc-select` shim first on its PATH,
  so a fresh `HOME` no longer pushes it onto Homebrew's single latest solc.

## [6.4.0] - 2026-10-23 — Data-flow detectors and honest scoring (C3 continued)

Paper-profile numbers on `main` after this release (SmartBugs-curated, 143 contracts,
layers 1/6/7, LLM-free): recall 143/143, precision 31.9 % (305 FP), F1 48.4 %. The
published papers report 137/143, 22.2 %, 36.0 % at v5.4.1; `make bench` reproduces
the new figures into a dated artifact and `make reproduce` keeps checking the frozen ones.

### Changed

- **Arithmetic false positives (#198).** The evaluation scorer no longer maps informational
  detectors (Slither `solc-version`, pragma and style rules) to a vulnerability category
  through their descriptions; the layer-6 overflow rule needs a state or financial context
  or a contract-level variable written with an external input; the ML fallback's
  `integer_overflow` needs a balance-like state write. SmartBugs-curated (LLM-free):
  recall 143/143 kept, precision 25.7 % → 28.9 % (414 → 352 FP), F1 44.8 %.
- **Time and randomness false positives (#199).** New `miesc/detectors/chain_attribute_flow.py`:
  a minimal intra-procedural data flow for `block.timestamp`/`now`/`block.number`/
  `blockhash`/`block.difficulty`/`block.coinbase`. The `smartbugs_ml` fallback, 4naly3er's
  `use_of_block_timestamp` and the intelligence timestamp gap-filler only fire when the
  value reaches a comparison in a condition/return or an entropy sink (hash, modulo,
  strong source); storing or logging the timestamp is not a finding. The ML fallback also
  matches `now` as a word (the substring test hit `known`). Scorer: Slither `timestamp`
  maps to `time_manipulation` (a stray `block.timestamp` alias made it randomness), the
  adapter's own `category` is honoured, `deprecated-standards` is out of taxonomy, and
  path-like tokens are stripped before the keyword fallback (the corpus path leaked the
  label). SmartBugs-curated (LLM-free): recall 143/143, precision 28.9 % → 31.9 %
  (352 → 305 FP), F1 48.4 %; `bad_randomness` 46 → 14 FP, `time_manipulation`
  43 → 30 FP.
- **Professional report (#198)** now shows, per finding, which tools agree and the calibrated
  confidence, plus a "Coverage and Limitations" section (tools skipped, in fallback mode,
  failed; LLM on/off) and an "Appendix B: Provenance" from the result's provenance block.
- `miesc scan --model ollama` now defaults to `qwen2.5-coder:14b` for a fast opt-in
  local LLM pass (was `qwen2.5-coder:32b`) (#195). The benchmarked 32B local model remains
  available via `--model qwen32b`; `audit full`, the ensemble path, and the config
  default are unchanged, so the documented benchmark figures are unaffected.

### Fixed

- `miesc report` crashed on the `audit full` JSON (`raw_findings` is a dict there) (#198).
- The `smartbugs_ml` prediction cache (system temp dir, 24 h) is keyed on the rule code,
  so a rule change no longer serves the previous rules' findings to a benchmark run (#199).

### Dependencies

- Python minor-version group bumped (21 packages, #163); `github/codeql-action` 4.39.0
  (#162); `ossf/scorecard-action` 2.5.0 (#161).

## [6.3.0] - 2026-10-21 — Precision wave (C3) and LLM-path follow-ups

Minor release. Wave C3 changes what the intelligence layer reports: two broad gap-fillers
(`dos_push_unbounded`, `reentrancy_crossfunction`) are gone, three rule bugs are fixed and the
evaluation scorer no longer reads remediation text as a diagnosis. On SmartBugs-curated
(LLM-free paper profile) recall stays 143/143 and precision rises from 22.4 % to 25.7 %
(495 → 414 false positives). Also: the ArithmeticDetector recognises cast operands (BECToken
batchOverflow), Slither and Aderyn no longer share `/tmp` report files, Ollama can be asked
for native JSON (opt-in), the arena benchmark matcher credits by SWC id and detector type,
and the README states what each setup actually delivers.

### Added

- **Opt-in native JSON output for Ollama** (`MIESC_OLLAMA_FORMAT_JSON=1`, or
  `format_json=True` on the shared mixin): the shared Ollama caller and the frontier
  adapter's chat call send `"format": "json"`, so the model returns a JSON document
  instead of prose the extractor must repair. Measured on `VulnerableBank.sol` with
  `qwen2.5-coder:32b`: the same reentrancy finding, parsed by the `direct` strategy
  instead of `json_repair`, in 52 s instead of 198 s. Cache-free `audit full` on the same
  contract (fresh `HOME`, Ollama live, `--llm-timeout 120`): with the flag every LLM
  adapter's response parsed by the `direct` strategy (GPTScan, GPTLens, iAudit, LlamaAudit,
  LLM-SmartAudit, SmartLLM, LLMBugScanner; PropertyGPT still fenced) against a mix of
  `fenced`/`anchored` repairs without it, no timeouts either way, wall time 304 s vs 294 s.
  Still off by default: the next step is the same comparison on the SmartBugs LLM
  follow-up profile before flipping it.
- README: a "what you actually get, by setup" table (static-only, local open-weight,
  three frontier APIs, ensemble) with recall, precision, F1 and cost per audit from the
  Paper 1 claims matrix.

### Changed

- **Wave C3, precision.** `_normalize_category` in `miesc evaluate` no longer coerces
  out-of-taxonomy findings (`hardcoded_gas`, DeFi `mev_exposure`) into SmartBugs categories by
  reading their remediation text, and an empty type no longer matches every alias. The
  intelligence layer's `dos_push_unbounded` and `reentrancy_crossfunction` gap-fillers are
  removed (0 exclusive true positives); `incorrect_constructor_name`, `unchecked_call_pattern`
  and `front_running` rule bugs fixed. SmartBugs-curated LLM-free: 143/143 recall, precision
  22.4 % → 25.7 % (artifact `smartbugs_eval_layers_1_6_7_20261021_intel_fix`) (#189).
- **ArithmeticDetector** recognises cast operands (`uint256(cnt) * _value`, the BECToken
  batchOverflow) and skips SafeMath library bodies; detector-level arithmetic recall on the
  three arena contracts 33 % → 100 %, SmartBugs-curated unchanged (#188).
- **Arena benchmark matcher** credits findings by SWC id and detector type instead of keyword
  substrings; arena access_control 1/3 → 3/3, overall 0.82 → 0.89 without over-crediting (#191).

### Fixed

- **Slither and Aderyn no longer share `/tmp/slither_output.json` / `/tmp/aderyn_output.json`.**
  Each run writes its report to a per-run temp file and removes it, so two MIESC
  processes on one machine (a benchmark and a scan, parallel CI jobs) cannot read each
  other's output and attribute one contract's findings to another; a caller-supplied
  `output_path` is still honoured and kept.

## [6.2.0] - 2026-10-21 — Product Excellence waves C1–C4

Minor release: the finding-quality wave changes what a scan reports (lint and
informational rules are capped at Low/Info, fixes are keyed by detector rule, every
finding carries its file and function), so baselines built on 6.1.x may shift. Every
result JSON now carries a `provenance` block, and the local-LLM path parses what the
models actually emit. SmartBugs-curated (LLM-free paper profile): recall 143/143,
precision 22.4 % (paper: 137/143, 22.2 %).

### Added

- **One tolerant JSON extractor for every LLM adapter** (`miesc/llm/json_extraction.py`).
  SmartGuard, GPTScan, GPTLens, iAudit, LlamaAudit, LLM-SmartAudit, SmartLLM,
  LLMBugScanner, PropertyGPT and FrontierLLM now parse model output through the same
  strategies (code fences, `<think>` blocks, key-anchored string-aware balanced scans,
  repair of trailing commas / single quotes / raw newlines, the `json-repair` library
  for unescaped quotes inside Solidity snippets and truncated output, NDJSON). The
  extractor never raises and records which strategy worked or why none did; SmartGuard
  and FrontierLLM keep that outcome in their result metadata. Real Ollama responses
  captured with `MIESC_LLM_DUMP_DIR` live in `tests/fixtures/llm_responses/` and must
  keep parsing.
  `json-repair` is now a core dependency (pure Python) so the local `--model ollama`
  path works on a minimal install.
- **`--llm-timeout` on `scan` and `audit full`**: a wall-clock budget applied only to
  adapters that declare `requires_llm`; static tools keep `--timeout`. Every tool record
  carries `timeout_budget_s`.
- **"Slowest tools" table** at the end of `audit full` (all three paths), from per-tool
  timings the ML orchestrator now keeps (`tool_timings`, `tool_budgets`).
- **Every result JSON carries a `provenance` block** so a run can be cited and
  re-run: MIESC version and git SHA (when running from a checkout), Python, OS/arch,
  the version string of every tool that executed as its binary reports it (probed
  once per run through the executable the adapter resolved; `unknown` when a tool has
  no version flag, never a failed run), the `solc` build the Slither adapter selected
  per contract, the versions of the result-moving Python packages (`slither-analyzer`,
  `scikit-learn`, `solc-select`, …), the config file path and SHA-256,
  `MIESC_SEED`/`MIESC_LLM_PROVIDER`/`MIESC_LLM_MODEL` when set, an `llm_free` flag
  and the exact command line. Written by `miesc scan`, `miesc audit quick|full`,
  `miesc evaluate corpus|ablation` (next to the unchanged `experiment_card`) and
  `miesc fix`, which now also writes a run report (`<output>.json`, or `--report PATH`)
  that cites the scan it consumed. `miesc evaluate compare` prints both runs'
  provenance side by side with differing rows highlighted. Adapters may declare
  `ToolAdapter.version_command()`; Slither, Aderyn, Solhint and Mythril do.
  (`miesc/core/provenance.py`; REPRODUCE.md now points at the block instead of a
  hand-maintained tool-version table.)
- **Documentation drift guards** (`tests/test_docs_drift.py`): CI now fails when the
  README MCP tool list differs from the server's `@mcp.tool()` set, when the
  installation guides or `CITATION.cff` state a version other than `miesc.__version__`,
  when a quoted `python -m <module>` command names a module that does not exist, or
  when a relative Markdown link in the user-facing docs is dead.
- **Product Excellence Plan** (`docs/roadmap/PRODUCT_EXCELLENCE_PLAN_2026-10.md`): the
  researcher-journey scorecard and ranked improvement waves; `docs/ROADMAP.md` points to it.

### Changed

- **`smartbugs_detector` precision.** Tightened the `short_addresses` and `front_running`
  patterns: on SmartBugs-curated (LLM-free layers 1,6,7) recall stays 143/143 and
  precision rises from 20.5 % to 22.4 % (paper: 22.2 %); artifact
  `benchmarks/results/smartbugs_eval_layers_1_6_7_20261020_fp_tightened.*` (#172).

### Fixed

- **Local-LLM responses with unescaped quotes inside Solidity snippets** no longer yield
  zero findings on the `scan --model ollama` path: the parser falls back to a tolerant
  JSON repair before giving up (#174).

## [6.1.1] - 2026-10-20

### Fixed

- **Aderyn 0.1.x parse panics are reported as a skip, not an error.** aderyn aborts
  with a Rust panic (exit 101) on legacy Solidity it does not model (`throw` in
  pre-0.4.22 sources; 36 of the 143 SmartBugs-curated contracts). The adapter now
  returns `status: skipped` with `reason: unsupported_source` and a warning that
  names the upstream limitation, so layer summaries explain the missing result.
- **Tool availability is probed once per run, not once per contract.** `run_tool`
  caches each adapter's `is_available()` for the process;
  `AdapterLoader.reset_availability()` clears it and the evaluator calls it per run.
  SmartGuard's
  `ollama list` probe has a 5 s timeout, which added ~12 min to a 143-contract
  SmartBugs run when Ollama was unreachable.
- **Evaluate results carry `version`, `timestamp` and `tools_used` at the top level
  again** (as the 5.4.1 paper artifacts do), next to the `experiment_card`;
  `miesc evaluate compare` reads the version from either place instead of printing
  `MIESC ?`.
- **`miesc[mcp]` installs a working server again.** The extra now pins the MCP
  Python SDK to the 1.x line (`mcp[cli]>=1.2.0,<2`); the 2.x SDK renamed `FastMCP`
  and `miesc-mcp` crashed with a misleading "MCP SDK not installed" message. The
  server now tells apart a missing SDK from an incompatible one.
- **`miesc report -f pdf` no longer reports success without a PDF.** When neither
  WeasyPrint nor pandoc is available the HTML fallback is still written, but the
  command exits 1 and says how to install `miesc[pdf]`.
- **`scripts/verify_installation.py`** no longer fails a minimal `pip install miesc`
  on Django (an extra); it checks the real core dependencies, lists optional extras
  as warnings and reports available tools consistently with `miesc doctor`.
- **Makefile** targets `install`, `install-dev`, `bench`, `ablation`, `reproduce`,
  `dataset-verify` pointed at files removed in the `src/ → miesc/` unification; they
  now wrap the canonical scripts (`benchmarks/verify_paper_claims.py`,
  `miesc evaluate corpus --layers 1,6,7`, `paper1_ablation_summary.py`).

### Added

- **Regression tests for the installation fixes**: PDF fallback exit code
  (`tests/test_report_pdf_fallback.py`), MCP SDK missing vs. incompatible
  (`tests/test_mcp_import_guard.py`), `verify_installation.py` core list kept in
  sync with `pyproject.toml` (`tests/test_verify_installation.py`), Aderyn panic
  handling (`tests/test_aderyn_unsupported_source.py`).
- **`miesc evaluate corpus|ablation --no-llm`**: first-class LLM-free evaluation
  profile. Adapters now declare `requires_llm` in their metadata (SmartGuard, GPTScan,
  GPTLens, iAudit, LlamaAudit, LLMSmartAudit, SmartLLM, LLMBugScanner, PropertyGPT,
  FrontierLLM); the flag skips them without probing and records `llm_free: true` and
  the skipped tools in the `experiment_card`. `make bench` and REPRODUCE.md use it
  instead of the `OLLAMA_HOST=http://127.0.0.1:1` workaround.
- **`make bench BENCH_TAG=<label>`** suffixes the dated result files so two runs on the
  same day do not overwrite each other.
- **`miesc[ml]` extra** (scikit-learn, numpy) for the built-in ML detectors that are
  part of the Paper 1 reproducible profile; also included in `miesc[full]`.
- **`REPRODUCE.md`**: a from-scratch guide to re-run the Paper 1 SmartBugs profile
  and compare it with the published artifact, with the tolerance to expect.
- Documentation refresh: README and `docs/INSTALLATION*.md` no longer reference the
  removed `src/` package, list the 22 real MCP tools, document `solc-select` as a
  prerequisite and the `qwen2.5-coder` defaults.

- **Calibrated finding confidence.** Every finding now carries a `confidence`
  (0-1) and `confidence_level` (high/medium/low), blending detector reliability
  (reused from the correlation engine's tool weights), cross-tool agreement, and
  the false-positive signal. `scan` and `audit full` gain `--min-confidence FLOAT`
  to drop low-confidence noise, and the SARIF export fills the `rank` slot from the
  calibrated confidence for triage in GitHub Code Scanning.
- **Confidence-aware CI gate.** `--fail-on-confidence FLOAT` on `scan` and
  `audit full` trips the `--ci`/`--fail-on` gate only on findings whose confidence
  meets the threshold. The report still shows every finding — only the exit code
  changes — so a noisy first run does not block the build on low-confidence issues.
- **`min-confidence` GitHub Action input**, threaded into the `scan` and
  `audit-full` runs so the confidence filter is available in CI, not just locally.
- **`miesc score`** — a composite security score (0-100) and letter grade (A-F)
  that weights findings by severity × calibrated confidence, plus a shareable badge
  (`--badge svg|json|markdown`; the SVG is self-contained). Scores a contract path
  or an existing scan/audit report; `--fail-under N` gates CI on the score.
- **Security-score regression gate.** `miesc score --against <baseline> --fail-on-regression`
  (with `--tolerance`) fails CI when the score drops versus a prior results or score
  JSON — a relative gate alongside the absolute `--fail-under`, the security analogue
  of a coverage-regression gate.
- **Counterexample → Foundry PoC.** Formal verification now turns each prover
  counterexample into an executable-shaped reproduction. The witness is parsed into
  structured `name = value` bindings (raw text preserved), and
  `miesc verify <contract> --poc <dir>` writes one Foundry test scaffold per
  counterexample — laying the inputs into typed, compile-valid Solidity locals with
  the type inferred from the prover's variable naming (`p_amount_uint256` →
  `uint256 amount`). Values that are not literals (e.g. `2**256 - 1`) fall back to a
  safe default with the raw value kept in a comment, so the scaffold always compiles.
  `--poc-check` optionally runs `forge build` on each scaffold to confirm it compiles
  (strictly best-effort; skipped when forge is unavailable, so CI is never affected).

## [6.1.0] - 2026-10-16 — RIBCi–CYTED 2026 camera-ready

### Added
- `benchmarks/verify_paper_claims.py`: recomputes every Paper 1 & 2 figure from
  its backing JSON, anchors each to the camera-ready `.tex`, and checks the Data
  Availability artifacts exist (exits non-zero on mismatch).
- Camera-ready benchmark scripts and artifacts: EVMBench same-run multi-protocol
  scorer, null-control matcher, Paper 1 ablation summary, Paper 2 pre-patch
  Slither baseline, SmartBugs FP-filter effect, and the EVMBench same-run results
  under `benchmarks/results/evmbench/same_run_claude_20261016/`.
- `benchmarks/README.md` script index and `paper/ribci-cyted-2026/ERRATA.md`
  (paper↔repo discrepancies E-1/E-2/E-3).

### Changed
- Claims matrices regenerated deterministically (`SOURCE_DATE_EPOCH=2026-10-16`)
  with the new artifacts; evidence JSONs unchanged so figures are unchanged.
- Reproducibility docs rewritten in English; README "Academic Validation" uses
  only JSON-sourced figures (drops the unsourced "Slither alone 43.2%" comparison
  and the "eliminate the original finding" phrasing) and links the camera-ready
  PDFs; `CITATION.cff` preferred-citation is the two RIBCi–CYTED 2026 papers
  (thesis secondary); `references.bib` reproduces the camera-ready bibliography.
- Development logs moved to `docs/internal/`.

## [6.0.0] - 2026-07-12

MIESC v6.0 turns the analyzer into something a team can adopt in CI without a
first-run finding flood, act on inside the pull request, consume from an editor,
and extend through a versioned plugin contract. It is a MAJOR release because it
introduces new public surfaces (baseline engine, plugin API contract, code-action
output) intended to be stable going forward.

### Added

- **T1.1 - Finding baseline & suppression engine.** New `miesc/core/baseline.py`,
  `miesc baseline generate|diff` commands, and `--baseline` / `--fail-on-new`
  flags on `scan` and `audit`. Content-hash fingerprints stay stable when
  unrelated edits shift line numbers, so teams can adopt MIESC in CI on an
  existing codebase and fail only on newly introduced findings.
- **T1.2 - SARIF-native inline PR annotations.** Findings are emitted as GitHub
  workflow annotations (`::error`/`::warning file=,line=`) that render inline on
  the PR diff. Composes with the baseline engine so only new findings are
  annotated.
- **T1.3 - Webhook + Slack notifier sink for CI.** Analysis results can be pushed
  to a webhook or Slack channel, closing the loop from detection to team
  notification in a pipeline.
- **T2.1 - Structured code-action / textEdit output.** `fix --format code-actions`
  emits LSP-shaped JSON (one object per fix with `finding_id`, `title`, `file`,
  and an `edits` array of `{range, newText}`) — an editor-agnostic quick-fix
  contract the platform/IDE layer can consume.
- **T3.1 - Unified formal-verification report + SARIF.** `verify --sarif`
  aggregates certora, halmos, and the Solidity SMTChecker into one deterministic
  JSON report and matching SARIF file, linking counterexamples back to the source
  findings they confirm or refute.
- **T3.3 - Versioned Plugin API contract + conformance suite.** A stable,
  versioned plugin API so third-party detectors can target a documented contract,
  validated by a conformance test suite.
- **T3.4 - Reference example plugins + marketplace seeding.** Reference plugins
  demonstrating the versioned API, plus initial marketplace index seeding.

### Changed

- Coverage gate raised and locked at `--cov-fail-under=80` (current line coverage
  81.12%).
- Migrated mutation tooling to the mutmut 3.x toolchain (py3.14 compatible);
  recorded a 75% mutation score on the v6 core modules.
- The validation suite is now deterministic regardless of machine state
  (ollama/gptlens model detection mocked, leaked singletons fixed), so a green
  gate is reproducible rather than incidental.

### Fixed

- Repointed the Makefile `test`, `test-coverage`, `lint`, `format`, and
  `security-sast`/`security-secrets` targets from the dead `src/` directory to
  `miesc/` after the src→miesc package unification (the `src/` tree is now only
  stale `.pyc` bytecode). This restores real coverage measurement and linting.
- Removed a stale `miesc/*` blanket coverage omit that zeroed measurement.
- Bounded `documentation_analyzer` scans to the project root instead of system
  tmp.
- Corrected a benchmark orchestrator import
  (`SecurityOrchestrator` -> `MIESCOrchestrator`).

## [5.4.3] - 2026-05-16

### Documentation

- Added the 5.4.2 release status note with published artifact links, GHCR
  digest, standard Docker image scope, and smoke-test commands.

### Fixed

- Made local analysis caches respect `MIESC_HOME` or explicit cache directories
  so tests and isolated runs no longer write to `~/.miesc` unexpectedly.
- Applied the Black formatting required by CI for the orchestrator cache setup.

### Changed

- Tightened the public package boundary, OpenAPI contract checks, REST/MCP
  contract validation, CI/Docker alignment, and local analysis helper behavior
  after the published `v5.4.2` release.
- Updated paper publication instructions and added a post-release validation
  checkpoint documenting why `v5.4.2` must not be retagged or republished.

### Validation

- GitHub Actions for the post-release checkpoint passed lint/format, security
  scan, type check, unit tests, documentation build/link check, integration
  tests, benchmarks, Docker build/test, and Trivy scan.
- Local `make release` rebuilt the wheel and sdist and passed `twine check` plus
  release artifact content validation.

## [5.4.2] - 2026-05-09

### Fixed

- Aligned release documentation, CLI banners, OpenAPI metadata, Docker examples,
  release verification instructions, and package fallbacks with the final
  release surface.
- Kept the release tag target consistent with the final commit intended for
  GitHub Release, PyPI, and Docker publication.

### Updated

- Includes the SmartBugs benchmark refresh published after v5.4.1.

## [5.4.1] - 2026-05-09

### Improved — Intelligence Engine Precision + Recall

- **Access control recall: 67% → 100%** — 6 new patterns (constructor_mismatch,
  delegatecall_unprotected, mapping_write_arbitrary, withdraw_no_balance_update,
  confused_comparison, incorrect_constructor multiline)
- **FP filtering: context-aware filters** — 3 new precision guards:
  - `non_timelock_timestamp`: suppresses time_manipulation for pure timelock require()
  - `randomness_context`: only fires bad_randomness when block vars used for entropy
  - `has_unchecked_arithmetic`: only fires arithmetic_pre08 with actual financial operations
- **Multiline pattern support** — `re.DOTALL` patterns for cross-line constructs
  (constructor bodies, delegatecall in function scope)
- **Estimated precision improvement**: ~25-30% (from 19.1% baseline)

### Fixed

- **Flaky Mythril test**: `test_analyze_with_findings` mocked to prevent timeout
- **SafeMath guard**: removed overly restrictive check that blocked insertion on
  pre-0.8 contracts without existing SafeMath (was the only failing test)
- **Docker CI**: re-run triggered for disk space failure

### Updated

- Version references across Docker, Streamlit, grants (all → 5.4.x)
- Grant drafts (Starknet, EF ESP, NGI Zero) with v5.4.0 numbers
- Paper bundles rebuilt with Mussetta coauthor

## [5.4.0] - 2026-04-29

### Added — Research Evaluation Framework

- **`miesc evaluate` command group** — scientific benchmark harness for researchers:
  - `miesc evaluate corpus <dir>` — ground-truth evaluation with precision/recall/F1/timing
  - `miesc evaluate ablation <dir>` — per-layer contribution study (standalone + combined)
  - `miesc evaluate compare <a> <b>` — statistical comparison between runs
  - `miesc evaluate info <dir>` — dataset statistics (categories, Solidity versions)
- **Experiment config files** — `--config experiment.yaml` loads all parameters for
  reproducible evaluation (layers, timeout, categories, env vars, seed)
- **JSONL export** — `miesc export -f jsonl` for ML pipelines (one finding per line)
- **Per-layer timing** — audit output includes `timing.per_layer` dict with seconds per layer
- **Experiment cards** — every evaluation auto-generates reproducibility metadata
  (version, platform, seed, model, timestamp, exact command)
- **Category normalization** — 80+ aliases + keyword fallback matching for
  cross-tool finding classification
- **Research Guide** — `docs/guides/RESEARCH.md` covering evaluation, ablation,
  plugin development, and reproducibility
- **CI template for research** — `.github/workflows/example-research-eval.yml`
  ready to copy for automated benchmark evaluation

### Improved — Paper 2 (Remediation Pipeline)

- Expanded to 7 pages IEEE format (from 5)
- Added Solidity code listings (before/after reentrancy patch)
- Added Foundry exploit test listing (generated by test-gen)
- New section: Threats to Validity (internal, external, construct)
- Expanded formal verification (CHC engine methodology, limitations)
- Expanded Discussion: compilation rate analysis, cost/scalability

## [5.3.1] - 2026-04-22

### Improved — Benchmark Results

- **SmartBugs recall 80% → 95.8%** — intelligence engine patterns (zero-recall
  categories, arithmetic SafeMath detection for pre-0.8) push static+intelligence
  to 137/143 contracts (reproducible Paper 1 profile). With a local Ollama
  follow-up: 97.9% (140/143), reported as a secondary claim.

### Fixed — Packaging Hotfix + UX Improvements

- **Templates bundled in PyPI wheel** — `miesc report` was failing on pip
  installs because `docs/templates/reports/` was not included in the package.
  Created `miesc/data/` with `get_data_path()` resolver (package-first,
  repo-root fallback for dev).
- **`--llm-enhance` wired to Ollama** — flag existed but was a no-op.
  Now calls `LLMReportInterpreter.interpret_critical_findings()` on the
  top 5 critical/high findings via Ollama.
- **`miesc fix` hit rate 33% → 100%** — fixed function inference for
  "unknown" names, deduplicated findings, added ReentrancyGuard import,
  skip detection for already-fixed functions.
- **Report tool count** — executive report showed "0 integrated tools".
  Now extracts from `findings[].tool` and `results[].tool`.
- **Warnings silenced** — `prometheus_client`/`FastAPI` import warnings
  downgraded from WARNING to DEBUG for new users.
- **Pre-flight syntax check** — `solc --stop-after parsing` warns about
  broken contracts before tools run.
- **Config YAML wired** — `get_tool_timeout()` and `get_max_workers()`
  read from `config/miesc.yaml` into scan/audit pipeline.
- **PDF fallback warning** — explicit install instructions when
  weasyprint/pandoc missing (was silent rename to .html).
- **Watch command** — 30s timeout cap, intelligence engine failures
  logged, removed mythril from balanced profile.
- **Docker CI** — scoped BuildX cache per job to prevent eviction on
  long multi-arch builds.
- **Premium report layer coverage** — Layer 1 shows "✅ Complete"
  instead of "Not Run" for scan output.
- **Multi-chain output normalized** — `miesc analyze` for Cairo/Move/
  Solana produces scan-compatible JSON. Added `--ci` flag.

### Tests — 6031 passed, 88% coverage (+53 from v5.3.0)

- 29 new tests: watch command (7), audit→report e2e (6),
  llmbugscanner adapter (16)

## [5.3.0] - 2026-04-21

### Added — From Detection to Remediation Pipeline

- **`miesc fix`** — auto-generates patched Solidity files from findings.
  Adds `nonReentrant`/`onlyOwner` modifiers, wraps `.call{}` in
  `require(success)`, inserts `SafeMath`. Verified E2E.
- **`miesc compliance`** — maps findings to 12 standards (ISO 27001,
  NIST CSF, OWASP, CWE, SWC, MITRE, MiCA Art.11, DORA Art.9).
- **`miesc scan --diff <ref>`** — PR-level scanning for CI.
- **7 bridge exploit patterns** — Wormhole, Ronin, BNB, Nomad ($1.7B+).

### Tests — 5978 passed, 87% coverage

## [5.2.0] - 2026-04-21

### Added — Intelligence Engine (15 capabilities, `src/core/intelligence.py`)

Post-detection engine: cross-tool Bayesian confidence, semantic dedup,
15 zero-recall patterns, 6 FP suppression rules, LLM↔static cross-val,
severity calibration, 14 recommendations, 10 fix-code templates, 10 exploit
scenarios, report enrichment, SARIF enrichment, `--verbose` flag, directory
scan, watch integration. ~30% noise reduction measured. DPGA-compatible.

### Added — Multi-chain +35 vuln types (total 77)

Stellar/Soroban +7, Solana/Anchor +7, Move/Sui/Aptos +7.
EVM intelligence patterns 8→15.

### Added — Plugin examples + gas analyzer (26 tests)

### Added — Roadmap (`docs/ROADMAP_v5.2_v5.3.md`)

### Fixed — 8 production bugs (stale-cache, rich deps, LLM validator, etc.)

### Tests — 5913 passed, 87% coverage (+581 from v5.1.4)

See v5.1.5–v5.1.9 entries below for per-release details.

## [5.1.9] - 2026-04-21

### Fixed — Critical: Slither stale-output silently missed reentrancy

- **Slither adapter returned 0 findings on contracts with known
  reentrancy vulnerabilities.** Root cause: `/tmp/slither_output.json`
  from a previous `analyze()` call on a DIFFERENT contract was read
  instead of the current run's output. A `ReentrancyVulnerable` contract
  (SWC-107, `tests/fixtures/reentrancy.sol`) that Slither correctly
  detects as HIGH reentrancy-eth was silently reported as "No issues
  found" by MIESC.

  Fix: delete the output file BEFORE running `subprocess.run`, so there
  is never a stale file to fall back to. Applied to both Slither and
  Aderyn (both use fixed `/tmp/{tool}_output.json` paths).

  The v5.1.7 existence-check fix (commit `cdf81c7`) prevented stale
  reads when the CONTRACT PATH was missing, but did NOT prevent stale
  reads when the OUTPUT FILE was left over from a prior successful run.
  This fix closes that remaining hole.

  **Users should upgrade immediately**: `pip install --upgrade miesc`

### Improved — UX for new users

- **Scan failure guidance**: when all tools error (common first-run
  scenario when slither/aderyn not installed), the CLI now shows:
  ```
  All analysis tools failed. Check tool availability:
    slither: ...
  Run 'miesc doctor' to check which tools are installed.
  Quick fix: pip install slither-analyzer
  ```
  Previously: `No issues found!` (misleading when tools failed).

- **README badges**: added monthly downloads badge (pepy.tech) and
  Python versions badge. Both render live on the GitHub landing page.

- **GitHub topics**: set 20 topics for discoverability (smart-contracts,
  security, ethereum, starknet, cairo, llm, formal-verification, ...).

- **GitHub description** updated to: "35 analysis modules, 9 defense
  layers, one command. Pre-audit triage for Ethereum, Starknet, and
  beyond."

### Infrastructure

- **Docker workflow fix**: `build-multiarch` and `build-full` jobs now
  fire on tag pushes (`refs/tags/v*`), not just main-branch pushes.
  v5.1.8 tag's multiarch build was silently skipped because the `if`
  condition required `refs/heads/main`.

- **Dependabot PRs**: merged 6 chore bumps (actions/checkout v6,
  actions/setup-node v6, actions/setup-python v6, actions/github-script
  v9, docker/setup-qemu-action v4, python-minor group, attrs, importlib-
  metadata). 3 remaining (eth-utils major, npm conflicts, websockets
  major).

## [5.1.8] - 2026-04-13

### Fixed — Critical regression in v5.1.7

- **`pip install miesc` produced a broken CLI.** The 5.1.7 install missed
  `rich` (which was in the `[cli]` optional extra), so any command that
  printed via `console.print(...)` crashed with
  `AttributeError: 'NoneType' object has no attribute 'print'`. Affected
  commands include `analyze`, `report`, `audit`, `verify`, and several
  others — totalling **137 console.print sites across miesc/cli/commands/**.

  Fix has two parts:
  1. **`rich>=13.0.0` is now a hard dependency** in `pyproject.toml`
     (moved out of the `[cli]` optional extra).
  2. **Defensive `_PlainConsole` fallback** in `miesc/cli/utils.py`:
     even if `rich` is missing for any reason, `console.print(...)` calls
     fall back to plain `print()` with markup stripped.

  Discovered during the v5.1.7 post-release smoke test (fresh
  `pip install miesc==5.1.7` in a clean venv → ran the README's Quick
  Start commands → `miesc analyze` crashed). v5.1.7 is left on PyPI for
  reproducibility but **users should upgrade to 5.1.8 immediately**.

## [5.1.7] - 2026-04-13

### Added — v5.1.7 Gates (closing the v5.1.6 benchmark report's three open items)

- **Gate 2: Taxonomy normalization** (`src/core/finding_taxonomy.py`).
  New `CanonicalCategory` enum (16 categories) + 70+ direct mappings
  from tool-specific detector names (Slither's `arbitrary-send-eth`,
  Aderyn's `unprotected-upgrade`, Mythril's `integer-overflow`, etc.)
  to canonical categories. DeepAuditAgent's Phase-3 branches now route
  via canonical category instead of substring matching, so follow-up
  analysis fires on real-world tool output. Rekt benchmark:
  `defi_confirmed` 0 → 19.

- **Gate 1: Victim-side corpus + balanced FP dataset**.
  Pulled the missing five SmartBugs-curated categories
  (`access_control`, `bad_randomness`, `denial_of_service`, `reentrancy`,
  `unchecked_low_level_calls`), bringing the in-repo corpus to the full
  143 contracts. Reworked `scripts/bootstrap_fp_dataset.py` to use the
  canonical taxonomy. Result: FP dataset grew 122 → 934 samples
  (3 → 67 TPs), `AuditorTrainedFPClassifier` now produces non-degenerate
  metrics.

- **Gate 3: LLM-path benchmark with multi-LLM consensus**
  (`benchmarks/deep_audit_rekt_llm.py`). Forces two distinct Ollama
  models for the `code_analysis` vs `verification` use cases so the
  consensus mechanism actually fires. Phase-3 consensus gate widened
  from `severity == "critical"` to `("critical", "high")`. Full run on
  11 Rekt exploits: **80 HIGH+CRITICAL findings → 4 needs_manual_review**
  (5% triage queue density, 26 agree_rejected, 12 single_opinion).
  BonqDAO oracle exploit produced 4/4 disagreements — exactly the case
  multi-LLM consensus is designed to surface for human review.

### Added — Test infrastructure (+321 tests vs. v5.1.6)

- **`tests/test_security_regressions.py`** (22 tests):
  command injection resistance, path traversal, prompt injection
  sanitization, pickle safety, ReDoS resistance, LLM output validation,
  secret redaction.
- **`tests/test_scalability.py`** (12 tests):
  large-contract scanning bounds, SpecRunner timeout enforcement,
  RAG O(1) lookup, taxonomy throughput, concurrent agent safety.
- **`tests/test_functionality_regressions.py`** (12 tests):
  FP classifier persistence, multi-chain dispatcher, CanonicalCategory
  contract, phase ordering, VulnerabilityExample fields, specs↔verify
  shape.
- **`tests/test_deep_audit_regressions.py`** (16 tests):
  one regression per bug fixed (DeFi API, Phase-3 report block, consensus
  gate, canonical routing, _start_time timeout).
- **`tests/test_bootstrap_fp.py`** (22 tests): FP labeling heuristic.
- **`tests/test_verify_command.py`** (11 tests): CLI contract.
- **`tests/test_load_adapters.py`** (8 tests): shim regression.
- **`tests/test_llm_location_coercion.py`** (18 tests): location field
  coercion regression.
- **`tests/test_finding_taxonomy.py`** (32 tests): taxonomy module.
- **`tests/test_adapter_contracts.py`** (162 parametrized tests):
  contract-level checks across the full ADAPTER_MAP — import clean,
  is_available never raises, analyze on missing file returns error.

### Fixed — Real bugs surfaced by the new test infrastructure

- **LLM output validator rejected non-dict locations** (`src/security/
  llm_output_validator.py`). SmartLLM was returning 0 findings on
  every Rekt contract because Pydantic strictly required
  `Optional[CodeLocation]` and the LLMs return `"function:line"`,
  bare integers, plain function names, etc. Added
  `@field_validator("location", mode="before")` that coerces common
  shapes into a `CodeLocation` dict.

- **`load_adapters` shim missing** (`miesc/cli/utils.py`). DeepAuditAgent
  imported it on every `analyze()` call, the import failed, the warning
  spammed logs, AND Phase-3 dynamic tool triggering silently degraded.
  Added a 48-LOC shim that walks `ADAPTER_MAP`, imports each module,
  instantiates the class, and caches the result. 50 adapters load
  successfully in our local environment.

- **Slither / Aderyn / Mythril stale-cache bug**
  (`src/adapters/{slither,aderyn,mythril}_adapter.py`). When given a
  nonexistent contract path, these adapters' subprocess calls failed —
  but the post-processing then read `/tmp/{tool}_output.json`, a stale
  file from a previous successful run on a DIFFERENT contract. Result:
  findings for the wrong contract were returned. Discovered by
  `tests/test_adapter_contracts.py` and fixed with explicit existence
  checks at the top of each `analyze()`.

- **`SecureFormatter` env-var redaction gap**
  (`src/security/secure_logging.py`). Only matched 48-character
  `sk-` keys and `api_key=`-style assignments. Missed the
  `OPENAI_API_KEY=sk-...` env-var pattern (most common shape in real
  logs). Added redaction for `_KEY=`, `_TOKEN=`, `_SECRET=` env-var
  suffixes and shorter `sk-` keys.

- **Peculiar adapter fallback warning spam**
  (`src/adapters/peculiar_adapter.py`). Logged `WARNING: No GNN model
  found...` on every `is_available()` check (called by every audit).
  Now logged once per process at info level.

### Improved — Code quality

- Lint cleanup: 42 → 12 ruff issues (71% reduction). Remaining 12
  are stylistic-only (`B905` zip-without-strict, `E402` intentional
  sys.path manipulation, `I001` import order in conditional block).
- Docker workflow now triggers on `v*.*.*` tag pushes and emits
  semver Docker tags (`{{version}}`, `{{major}}.{{minor}}`) — future
  releases auto-publish to GHCR.

### Documentation

- `docs/PRE_RELEASE_AUDIT_v5.1.7.md` — comprehensive audit covering
  code quality, security, OSS compliance, and project alignment.
  Includes prioritized action plan and bug-fix summary.
- `benchmarks/results/v5.1.7_gates_report.md` — full per-contract
  breakdown of the LLM consensus run on the Rekt corpus.
- `paper/miesc-paper.tex` updated to reflect v5.1.6+v5.1.7 capabilities
  (Cairo 1.1.0 with 13 vuln types, multi-LLM consensus mechanism,
  formal-verification bridge, attack_steps + detection_heuristic in
  the RAG knowledge base).

### Tests

5,306 passed, 5 skipped, 0 regressions across the ~25-commit
pre-release sweep (was 4,985 in v5.1.6, +321 tests).

## [5.1.6] - 2026-04-12

### Added — Bloque 3 (DeepAuditAgent deep investigation)

- **Finding-driven tool triggering** now actually invokes the follow-up analyzers
  instead of only setting labels:
  - Oracle / price findings → `_targeted_defi_scan()` runs `DeFiPatternDetector`
    scoped to the vulnerable function and attaches concrete pattern matches.
  - Access-control findings → `_targeted_property_for_function()` generates a
    Certora CVL rule targeting the function (pipes directly into `miesc verify`).
- **Multi-LLM consensus** on CRITICAL findings (replaces the single second-opinion
  path). Queries the primary code-analysis model AND the verification-use-case
  model; reconciles into `agree_confirmed` / `agree_rejected` / `disagreement`
  / `single_opinion` and applies bounded confidence adjustments (+0.20 on
  agreement, -0.30 on joint rejection, -0.10 + `needs_manual_review=True` on
  disagreement). Legacy `_get_llm_second_opinion()` is preserved as a shim.
- Phase 3 result exposes new aggregate fields: `needs_manual_review_count`,
  `properties_generated`, `defi_confirmed_count`.

### Added — Bloque 4 (RAG knowledge base depth)

- `VulnerabilityExample` dataclass extended with `attack_steps: List[str]` and
  `detection_heuristic: Optional[str]`.
- Enriched the 6 most common SWC patterns (SWC-107, -105, -106, -104, -115, -101)
  and the two most impactful 2023 exploit case studies (Euler, Curve/Vyper) with
  concrete step-by-step attack procedures and grep-level detection heuristics.
- `VulnerabilityRAG.enhance_finding()` now surfaces `attack_steps` and
  `detection_heuristic` in the LLM context block when the match provides them.

### Fixes — Post-v5.1.5 polish

- **Halmos verification fixed end-to-end**: CLI now walks up to `foundry.toml`
  before invoking halmos. `SpecRunner.run_halmos()` returns `status="no_tests"`
  when halmos finds no symbolic tests (previously misreported as `failed`).
  Parser now strips ANSI color codes from counterexamples.
- **GPTScan RAG placeholder bug**: `%RAG_CONTEXT%` stayed literal in the final
  prompt because the RAG injection replaced a different string. Renamed to
  `%RAG_CONTEXT_PLACEHOLDER%` with an explicit single-site replacement.
- Added few-shot real-exploit references (Cream/Euler/BNB in GPTScan,
  Curve/Euler/Wormhole in SmartLLM, Parity/Nomad/Audius in LLMSmartAudit).

### Tests

- `tests/test_deep_audit_agent.py`: +13 tests across 4 new classes
  (TestTargetedDefiScan, TestTargetedPropertyGeneration, TestLLMConsensus,
  TestPhase3FindingDrivenIntegration).
- `tests/test_vulnerability_rag.py`: +16 tests covering the new dataclass
  fields, attack_steps / detection_heuristic presence on top patterns, and
  real_exploit coverage across all 60 registry entries.
- `tests/test_gptscan_prompt.py` (new): 6 tests on prompt integrity + RAG
  placeholder behavior.
- `tests/test_spec_runner.py`: +2 tests (ANSI stripping, `no_tests` status).
- Full suite: 4985 passed, 5 skipped, 0 regressions.

## [5.1.5] - 2026-04-12

### Added

- **Auditor-trained False Positive classifier**
  (`src/ml/fp_ml_classifier.py`, `AuditorTrainedFPClassifier`)
  - scikit-learn `GradientBoostingClassifier` trained on JSONL-labeled
    findings — lets teams improve precision over time with their own
    validated data.
  - Graceful heuristic fallback when sklearn isn't installed or the
    model isn't trained yet.
  - Features: severity, tool one-hot, vuln-type hash, confidence, code
    context length, known-library detection, Solidity 0.8+ detection.
  - `create_sample_dataset()` produces a 20-row synthetic dataset for
    quick demos / tests.

- **Formal verification RUNNER**
  (`src/formal/spec_runner.py`, `SpecRunner`)
  - Executes the specs generated by `miesc specs` against real provers:
    Certora Prover (`certoraRun`), Halmos, and SMTChecker (`solc`).
  - Normalizes outputs into `VerificationResult` (pass/fail/timeout/error +
    counterexamples + elapsed seconds).
  - `run_all_available()` convenience runner that skips missing tools.

- **New CLI command: `miesc verify`**
  - `miesc verify contract.sol --tool smtchecker`
  - `miesc verify contract.sol --spec rules.spec --tool certora`
  - Closes the loop: **finding → spec → actually run the prover**.

- **Expanded Cairo/Starknet patterns** (13 vuln types, up from 8)
  New patterns informed by real 2024-2026 exploits:
  - `PRAGMA_ORACLE_STALE` — zkLend (Feb 2025, $9.6M)
  - `UNCHECKED_U256` — Cairo 1.0 u256 unchecked arithmetic
  - `UPGRADE_NO_INIT_GUARD` — Braavos account reinitialization (2023)
  - `UNCHECKED_SYSCALL_RESULT` — dropped `SyscallResult` from
    `call_contract_syscall` / `library_call_syscall`
  - `SIGNATURE_REPLAY` — account abstraction without nonce/chain_id binding

- **Streamlit Cloud deployment guide**
  (`docs/guides/STREAMLIT_CLOUD_DEPLOYMENT.md`)
  - Step-by-step `share.streamlit.io` deploy, secrets setup, troubleshooting.
  - `webapp/app.py` version now reads dynamically from `miesc.__version__`
    (no more manual bumps on the dashboard).

### Changed

- `CairoAnalyzer.version` bumped to `1.1.0` (13 vuln types).
- `src/formal/__init__.py` now exports `SpecRunner`, `VerificationResult`,
  `run_all_available` alongside the existing spec-generation API.

### Tests

40+ new tests:
- `tests/test_fp_ml_classifier.py` — 23 tests for feature extraction,
  heuristic fallback, and sklearn training/persistence.
- `tests/test_spec_runner.py` — 14 tests for prover availability, output
  parsers, graceful degradation, and a real-solc SMTChecker integration test.
- `tests/test_cairo_analyzer.py` — 6 new tests for the 2024-2026 exploit
  patterns (zkLend / Braavos / syscall / replay).

## [5.1.4] - 2026-04-12

### Added
- **Multi-chain support via `miesc analyze` command**
  - Auto-detects chain from file extension
  - Supports: Ethereum/EVM (.sol, .vy), Starknet (.cairo), Move (.move), Solana (.rs)
- **New Cairo/Starknet analyzer** (`src/adapters/cairo_adapter.py`)
  - 8 vulnerability types: felt overflow, L1/L2 message validation,
    caller spoofing, storage collisions, proxy upgrade, reentrancy,
    access control, arithmetic
  - Detects issues in VulnerableVault.cairo demo contract
- Example Cairo contract: `examples/contracts/cairo/VulnerableVault.cairo`

### Usage
```bash
miesc analyze Token.sol           # Auto-detects EVM
miesc analyze Vault.cairo         # Auto-detects Starknet
miesc analyze MyModule.move       # Move (Sui/Aptos)
miesc analyze program.rs --chain solana
```

### Tests
13 new tests for Cairo analyzer. Total 4925 tests, 80.13% coverage.

## [5.1.3] - 2026-04-12

### Added
- **Formal verification spec auto-generator** (`src/formal/spec_generator.py`)
  - Generates Certora CVL rules from MIESC findings
  - Generates Scribble annotations
  - Generates SMTChecker assertions
- **New CLI command: `miesc specs`**
  - `miesc specs results.json -f cvl -o my.spec`
  - `miesc specs results.json -f scribble`
  - `miesc specs results.json -f smtchecker`
- Maps 7 vulnerability types to spec templates:
  reentrancy, access-control, overflow, underflow, unchecked-call,
  timestamp, weak-randomness

### Use case
Bridge between automated detection (MIESC) and formal verification
(Certora Prover, Scribble, solc SMTChecker) — previously a gap.

Workflow:
  1. `miesc scan contract.sol -o results.json`
  2. `miesc specs results.json -f cvl -o my.spec`
  3. `certoraRun contract.sol --verify MyContract:my.spec`

### Tests
18 new tests for spec generation. Total 4912 tests, 82.38% coverage.

## [5.1.2] - 2026-04-12

### Added
- **Tunable FP filter via `--fp-strictness` flag** (off/low/medium/high)
  - `off`: report everything (threshold=1.1)
  - `low`: permissive (0.70)
  - `medium`: balanced, default (0.60)
  - `high`: aggressive for CI (0.40)
  - EtherStore.sol: off=14, low=14, medium=11, high=9 findings
- **`--llm-enhance` flag** for opt-in AI insights (adds ~40s)
- **Head-to-head competitor comparison** (`benchmarks/competitor_comparison.py`)
  - Compares MIESC vs Slither, Aderyn, Solhint, Echidna on 5 contracts
- **Honest comparison doc** (`docs/COMPARISON.md`) with pros/cons
- **New strictness presets API** in `FalsePositiveFilter`

### Changed
- **60x speedup on scan**: 529s → 8.5s on 5-contract benchmark
  - LLM enhancement now opt-in across 11 adapters (was auto-running)
  - Parallelized QUICK_TOOLS with ThreadPoolExecutor
  - Removed Mythril from QUICK_TOOLS (too slow, opt-in via `audit full`)
- **Cross-tool dedup improved**: 40+ new aliases in `TYPE_ALIASES`
  - Slither `suicidal` + Aderyn `selfdestruct-identifier` → 1 finding
  - Slither `weak-prng` + Aderyn `weak-randomness` → 1 finding
  - Slither `controlled-delegatecall` + Aderyn `delegate-call-unchecked-address` → 1 finding
- **Quieter CLI output**: 8 init logs moved from INFO → DEBUG
- **Ollama HTTP API** instead of CLI subprocess (cleaner LLM output)
- **Slither path discovery**: added `/opt/homebrew/bin` for macOS Homebrew users

### Fixed
- Slither adapter: honor `--solc` path directly (works around bad-interpreter issue in solc-select wrapper)
- ANSI escape codes garbled `llm_insights` field in JSON output
- GPTScan model priority list (was returning `:7b` when `:32b` was available)

### Performance
- `miesc scan contract.sol`: **1.4s** (was 1:22 / 82s in v5.1.1)
- Multi-contract benchmark (5 vulnerable contracts): **7.3s** (was 529s)
- Still 2.15x more findings than Slither alone (97 vs 45), at 6x the time cost

### OSS Quality
- Root directory cleanup: **48 → 31 visible items**
- Moved governance files (`CODE_OF_CONDUCT`, `CONTRIBUTING`, etc.) to `.github/`
- Moved policy files (`PRIVACY`, `RESPONSIBLE_USE`) to `docs/policies/`
- Removed 19 `.coverage*` snapshot files from git
- Added comprehensive Troubleshooting section to README

## [5.1.1] - 2026-02-12

### Added
- **RAG Knowledge Base Expansion**: 59 vulnerability patterns (up from 39)
  - New categories: MEV (4), Bridge (3), ZK (2), NFT (2), DeFi (2)
  - Real exploits: Curve/Vyper ($70M), Euler ($197M), Wormhole ($320M)
- **RAG Performance Optimizations**:
  - O(1) document lookup via dictionary index (was O(n) linear search)
  - Query caching with 5-min TTL, 256-entry LRU cache
  - `batch_search()` for multiple queries in single ChromaDB call
  - `batch_get_context_for_findings()` groups findings by type (50-75% faster)
- **Context Window Optimization**:
  - `_truncate_code_smart()` prioritizes security-critical functions
  - `_extract_rag_query()` for semantic queries instead of raw code
  - Dynamic context allocation based on contract size
  - Prompt template reduced from ~2500 to ~500 chars
- **RAG-Enhanced False Positive Filter**:
  - Validates findings against 59-pattern knowledge base
  - Detects fix patterns present in code (nonReentrant, SafeMath, etc.)
  - Identifies severity mismatches between reported and expected
- **Documentation**:
  - `docs/guides/RAG_API.md` - Comprehensive RAG API documentation
  - `scripts/benchmark_rag.py` - Performance benchmark script

### Changed
- SmartLLM verificator now pre-fetches all RAG context at once
- FalsePositiveFilter now accepts `use_rag` parameter (default True)

---

## [5.1.0] - 2026-02-11

### Changed
- **CLI Refactoring**: main.py reduced from 6,710 to 126 lines (98.1% reduction)
- Extracted 8 command modules to `miesc/cli/commands/`:
  - `audit.py` - 7 subcommands (quick, full, layer, smart, profile, single, batch)
  - `report.py` - Report generation with 7 templates and LLM interpretation
  - `benchmark.py` - Security posture tracking over time
  - `scan.py` - Quick vulnerability scan
  - `detect.py` - Framework auto-detection (Foundry/Hardhat/Truffle/Brownie)
  - `doctor.py` - System health check
  - `export.py` - Export to SARIF/Markdown/CSV/HTML
  - `watch.py` - Real-time file watching with auto-scan
- All commands now registered via `cli.add_command()` pattern
- Removed unused imports from main.py

### Added
- `miesc/cli/commands/` package with 15 command modules
- Modular CLI architecture for easier maintenance and testing

---

## [5.0.3] - 2026-02-02

### Fixed
- Docker build: package stubs for editable install in multi-stage build
- CI/CD: override entrypoint for Docker image test
- CI/CD: disable coverage threshold in integration tests (only 2 test files)
- Removed unused `setuptools_scm` from build-requires

### Changed
- Black formatting applied to scripts, examples and webapp (13 files)
- Cleaned up 177 Finder duplicate files

---

## [5.0.2] - 2026-02-01

### Fixed
- CLI help text updated to reflect 50 tools / 9 defense layers
- REST API VERSION now imports from package (no more hardcoded value)
- 849 ruff linting errors resolved (0 remaining)
- 242 files reformatted with black
- 27 bare-except clauses replaced with specific exception types
- 31 raise-without-from-inside-except fixed with proper exception chaining

### Changed
- Docker base image optimized: Mythril/Manticore moved to Dockerfile.full only
- Docker build parallelized: aderyn + foundry builder stages run concurrently
- Docker layer reordering: code changes no longer invalidate pip cache
- BuildKit cache mounts for pip and cargo across all Docker images
- Duplicate Foundry install removed from runtime stage
- Medusa removed from builder (was always failing)
- Pre-commit hooks updated to latest versions (ruff v0.14.14, black 26.1.0, etc.)
- Pre-commit Python version updated from 3.9 to 3.12
- Test warnings reduced from 242 to 198

---

## [5.0.1] - 2026-02-01

### Fixed
- Version sync across Docker files, README, docker-compose.yml
- REST API VERSION constant updated from stale 4.3.2 to package version
- CI/CD: Linting, formatting, and security checks now block PRs (removed continue-on-error)
- Layer 5 AI adapters use centralized OLLAMA_HOST config instead of hardcoded localhost

### Added
- MCP server test suite (test_mcp_server.py, 13 tests)
- v5.0.0 adapter test suite (test_v500_adapters.py, 51 tests)
- ML model requirements documentation (docs/models/README.md)
- MCP dependency in Docker image
- Graceful degradation logging for ML adapters (peculiar, dagnn, smartbugs_ml)

### Changed
- Coverage threshold raised from 50% to 55%
- CI Python version updated from 3.11 to 3.12
- REST API ADAPTER_MAP expanded to 50 entries (was 32)

---

## [5.0.0] - 2026-01-31

### Added
- **9 Defense Layers with 35 Analysis Modules**: Expanded from 7 layers/32 tools to 9 layers/50 tools
- **17 new adapters**: fouranalyzer, oyente, pakala, scribble, solcmc, gptlens, llamaaudit, iaudit, peculiar, upgradability_checker, bridge_monitor, l2_validator, circom_analyzer, audit_consensus, exploit_synthesizer, vuln_verifier, remediation_validator
- **MCP Server**: stdio-based FastMCP server for Claude Desktop integration with 18 tools
- **Cross-Validation v3**: Bayesian scoring with intra/inter-layer confidence and Layer 9 meta-analysis
- **`miesc-mcp` entry point**: Run MCP server via `miesc-mcp` CLI command

### Changed
- Architecture expanded from 7 to 9 defense layers
- False positive filter v2.3 with FP rates for all new adapters
- Tool weights updated for 50 tools in config/miesc.yaml

---

## [4.5.3] - 2026-01-30

### Fixed
- **Batch audit PoC names**: PoC exploit templates now use the correct per-contract name instead of "Unknown" when generating reports from batch audits (`audit batch`).

---

## [4.5.2] - 2026-01-29

### Added
- **PoC exploit generation in PDF reports**: Professional/premium reports now auto-generate Foundry test templates for Critical/High findings, including exploit code, prerequisites, and expected outcomes.

### Fixed
- **ML-enhanced findings in reports**: Reports now use ML-adjusted severities instead of raw findings, ensuring deployment recommendations reflect the full ML pipeline (FP filtering, severity adjustments).

---

## [4.5.1] - 2026-01-29

### Fixed
- **Deployment recommendation override**: LLM can no longer override a stricter deployment recommendation (NO-GO) with a more permissive one (GO/CONDITIONAL). This prevents critical findings from being incorrectly marked as safe for deployment.

### Links
- **PyPI**: https://pypi.org/project/miesc/4.5.1/
- **Docker**: `docker pull ghcr.io/fboiero/miesc:4.5.1`

---

## [4.5.0] - 2026-01-29

### Added

#### Comprehensive Integration Tests
- **Full test suite**: 2700+ tests with 71% coverage
- **Integration test files**: Pipeline, reports, multichain, and benchmark integration tests
- **CLI testing**: End-to-end audit command testing with Click's CliRunner

#### Enhanced Report Generation
- **Smart audit format support**: Reports now correctly parse `tools_run`, `tools_success`, `tools_failed` arrays
- **Effort vs Impact Matrix**: Prioritization matrix with finding counts per cell (DO FIRST, Quick Win, Priority, Schedule, etc.)
- **Tool execution details**: Tools Utilized, Layer Coverage Analysis, and Appendix sections now populate correctly
- **Report documentation**: Comprehensive `docs/guides/REPORTS.md` guide

#### Optional Dependencies
- **Graceful degradation**: `openai` and `python-dotenv` are now optional imports
- **Cleaner installs**: Base installation works without LLM dependencies

### Fixed
- **PDF generation**: Fixed Jinja2 template rendering by adding to core dependencies
- **Smart audit reports**: Contract name, findings, and tool data now correctly extracted
- **Test mock**: Fixed `audit smart` test to use correct `analyze` method

### Links
- **PyPI**: https://pypi.org/project/miesc/4.5.0/
- **Docker**: `docker pull ghcr.io/fboiero/miesc:4.5.0`

---

## [4.4.0] - 2026-01-25

### Changed
- **Repository reorganization**: Restructured project layout for better maintainability
- **CI/CD improvements**: Enhanced GitHub Actions workflows

### Links
- **GitHub Release**: https://github.com/fboiero/MIESC/releases/tag/v4.4.0

---

## [4.3.7] - 2025-01-20

### Added

#### Premium Audit Reports
- **Premium report template** (`-t profesional`): Trail of Bits / OpenZeppelin style professional audit reports
- **CVSS-like scoring**: Automatic vulnerability scoring with attack vectors (AV, AC, PR, UI, C/I/A)
- **Risk matrix**: Visual Impact vs Likelihood matrix with finding distribution
- **Deployment recommendation**: GO / NO-GO / CONDITIONAL with justification
- **Attack scenarios**: AI-generated step-by-step attack scenarios for critical findings
- **Code remediation**: AI-generated fix suggestions with git-style diffs
- **Remediation roadmap**: Prioritized timeline for addressing vulnerabilities

#### Docker LLM Distribution
- **Dual-model support**: docker-compose now downloads both `deepseek-coder:6.7b` and `mistral:latest`
- **Production config**: New `docker-compose.prod-llm.yml` with health checks, resource limits, and GPU support
- **Setup wizard**: Interactive `scripts/docker-setup.sh` for easy deployment
- **Health check**: New `deploy/health-check.sh` to verify Ollama and model availability

#### PDF Report Generation
- **WeasyPrint integration**: Native PDF generation with professional styling in Docker
- **Premium CSS**: Professional CSS optimized for PDF output with A4 page setup
- **CLI support**: `miesc report results.json -f pdf -o report.pdf` now works in Docker
- **Auto-fallback**: Falls back to pandoc/wkhtmltopdf if weasyprint unavailable

#### New Files
- `docs/templates/reports/profesional.md` - Premium report template
- `docs/templates/reports/profesional.css` - Professional PDF styling
- `src/reports/risk_calculator.py` - CVSS scoring and risk matrix generator
- `docker-compose.prod-llm.yml` - Production Docker config with LLM
- `scripts/docker-setup.sh` - Interactive setup wizard
- `deploy/health-check.sh` - Service health verification

### Changed
- `miesc report` now supports `--template profesional` option
- `llm_interpreter.py` enhanced with attack scenario and code remediation generation
- `config/miesc.yaml` includes profesional report configuration section

### Links
- **GitHub Release**: https://github.com/fboiero/MIESC/releases/tag/v4.3.7
- **Docker**: `docker pull ghcr.io/fboiero/miesc:4.3.7`

---

## [4.3.5] - 2025-01-19

### Fixed
- **Slither ARM64 compatibility**: Auto-creates minimal Foundry project for standalone `.sol` files when solc-select binaries don't work on ARM64 architecture
- **crytic-compile detection**: Prevents `AssertionError` when forge is installed but no `foundry.toml` exists

### Changed
- Slither adapter now intelligently detects platform and chooses compilation method
- Added `_setup_foundry_project()` and `_cleanup_foundry_project()` for temporary Foundry configuration

### Links
- **GitHub Release**: https://github.com/fboiero/MIESC/releases/tag/v4.3.5
- **Docker**: `docker pull ghcr.io/fboiero/miesc:4.3.5`

---

## [4.3.4] - 2025-01-15

### Added
- **PyPI plugin search**: `miesc plugins search <query>` to discover plugins on PyPI
- **Local plugins directory**: `~/.miesc/plugins/` for development and local plugins
- **Version compatibility validation**: Checks plugin compatibility with MIESC version
- **New CLI options**: `--force` and `--no-check` for `miesc plugins install`
- **Plugin path command**: `miesc plugins path [--create]` to manage local plugins directory

### Changed
- `miesc plugins list` now shows compatibility status column
- `miesc plugins info` displays version requirements and compatibility details

### Fixed
- SyntaxWarning in `detector_api.py` docstrings (escaped regex patterns)

### Links
- **PyPI**: https://pypi.org/project/miesc/4.3.4/
- **GitHub Release**: https://github.com/fboiero/MIESC/releases/tag/v4.3.4
- **Docker**: `docker pull ghcr.io/fboiero/miesc:latest`

---

## [4.3.3] - 2025-01-14

### Added

#### Plugin System
- **Full plugin management CLI**: `miesc plugins list/install/uninstall/enable/disable/create`
- **Plugin scaffolding**: `miesc plugins create my-detector` generates complete plugin project
- **PyPI integration**: Install detector plugins directly from PyPI
- **Plugin configuration**: Enable/disable plugins via `~/.miesc/plugins.yaml`

#### Custom Detectors
- **15 built-in detectors** available out of the box:
  - `flash-loan-attack` - Flash loan attack patterns
  - `reentrancy-patterns` - Reentrancy vulnerabilities
  - `access-control` - Missing access controls
  - `tx-origin` - tx.origin authentication issues
  - `unchecked-return` - Unchecked return values
  - `slippage-protection` - Missing slippage protection
  - `rug-pull-patterns` - Token rug pull patterns
  - `mev-vulnerability` - MEV extraction vulnerabilities
  - `delegatecall-danger` - Dangerous delegatecall patterns
  - `selfdestruct-usage` - Selfdestruct usage detection
  - `weak-randomness` - Weak randomness sources
  - `timestamp-dependence` - Block.timestamp reliance
  - `approval-race` - ERC20 approval race conditions
  - `unbounded-loop` - DoS via unbounded loops
  - `hardcoded-address` - Hardcoded addresses

#### Sample Plugin
- **Example plugin** in `examples/sample-plugin/` demonstrating:
  - Complete plugin structure with `pyproject.toml`
  - Custom detector implementation (`DangerousDelegatecallDetector`)
  - Test suite for the detector
  - Vulnerable test contract (`VulnerableProxy.sol`)

#### Docker ARM64 Support
- **Multi-arch Docker images**: `ghcr.io/fboiero/miesc:latest` now supports both AMD64 and ARM64
- Native support for Apple Silicon (M1/M2/M3/M4) Macs
- Fixed `latest` tag to include ARM64 manifest

### Changed
- Docker workflow builds `latest` tag only from multi-arch job
- Plugin entry points now use string category instead of enum for flexibility

### Documentation
- Added sample plugin documentation in `examples/sample-plugin/README.md`
- Updated plugin system documentation in README.md

### Links
- **PyPI**: https://pypi.org/project/miesc/4.3.3/
- **GitHub Release**: https://github.com/fboiero/MIESC/releases/tag/v4.3.3
- **Docker**: `docker pull ghcr.io/fboiero/miesc:latest`

---

## [4.3.2] - 2025-01-09

### Added

#### PyPI Publication
- **MIESC is now available on PyPI**: `pip install miesc`
- Installation options: `miesc`, `miesc[cli]`, `miesc[web]`, `miesc[full]`
- Package includes all 31 adapters and 9 defense layers

#### New CLI Commands
- **`miesc scan`** - Simplified quick vulnerability scan
  - `miesc scan contract.sol` - Quick 4-tool scan
  - `miesc scan contract.sol --ci` - CI mode (exit 1 on critical/high issues)
  - `miesc scan contract.sol -o report.json` - JSON output

#### Module Execution
- Support for `python -m miesc` execution
- Added `miesc/__main__.py` for module entry point

### Fixed
- **Optional dependency imports** - WebSocket/FastAPI type annotations no longer fail when packages not installed
- Added `from __future__ import annotations` for deferred type evaluation
- Fallback `None` assignments for optional imports (FastAPI, uvicorn, WebSocket)

### Changed
- Web frameworks (FastAPI, Flask, Streamlit, Django) are now optional dependencies
- Minimal core dependencies: click, pydantic, pyyaml, slither-analyzer
- Package structure updated to include `src.*` modules in distribution

### Documentation
- Added `QUICKSTART.md` with CLI usage and 9-layer architecture guide
- Updated README badges (PyPI, version 4.3.2)
- Updated README_ES.md with same badges

### Links
- **PyPI**: https://pypi.org/project/miesc/4.3.2/
- **GitHub Release**: https://github.com/fboiero/MIESC/releases/tag/v4.3.2

---

## [4.2.1] - 2024-12-23

### Added

#### Scientific Benchmark Validation (SmartBugs Curated)
- **Comprehensive multi-tool benchmark** against SmartBugs Curated dataset (143 contracts)
- Benchmark runner script (`benchmarks/run_benchmark.py`) for reproducible validation
- Detailed results in `benchmarks/results/` JSON format

#### Benchmark Results Summary
| Tool | Layer | Recall | F1-Score | Notes |
|------|-------|--------|----------|-------|
| Slither | 1 | 84.3% | 80.0% | +27.3% vs SmartBugs 2020 paper |
| SmartBugsDetector | 2 | 100% | - | Pattern-based, no compilation |
| Mythril | 3 | - | - | 6 findings with SWC codes |

#### Per-Category Detection Rates (Slither)
- Unchecked low-level calls: 100%
- Front running: 100%
- Arithmetic overflow: 93.3%
- Bad randomness: 87.5%
- Access control: 86.7%
- Reentrancy: 73.3%
- Time manipulation: 60.0%
- Denial of service: 50.0%

#### New Adapters
- **SmartGuard Adapter** - ML-based vulnerability prediction
- **LLMBugScanner Adapter** - GPT-4o powered vulnerability detection
- **ZK Circuit Adapter** - Zero-knowledge proof circuit validation
- **CrossChain Adapter** - Bridge and cross-chain security analysis

#### Slither Adapter Improvements
- Legacy Solidity support (0.4.x - 0.5.x) with `--compile-force-framework solc`
- Automatic solc-select integration for version management
- Improved IR generation handling for complex legacy patterns

### Changed
- Updated version to 4.2.1
- Enhanced adapter error handling for legacy contracts
- Improved benchmark reproducibility with JSON result export

### Documentation
- Added benchmark methodology documentation
- Scientific comparison with literature (SmartBugs 2020, Empirical Review 2020)
- Multi-tool strategy recommendations

---

## [4.1.0] - 2024-12-09

### Added

#### New Security Layers (post-thesis extension)
- **Layer 8: DeFi Security Analysis** - First open-source DeFi vulnerability detectors
  - Flash loan attack detection (callback validation, repayment verification)
  - Oracle manipulation detection (spot price vs TWAP)
  - Sandwich attack detection (zero slippage, missing deadlines)
  - MEV exposure analysis (liquidation front-running)
  - Price manipulation detection (reserve ratio vulnerabilities)

- **Layer 9: Dependency Security Analysis** - Supply chain security
  - OpenZeppelin CVE database integration (CVE-2022-35961, etc.)
  - Vulnerable version detection with semantic versioning
  - Dangerous pattern detection (tx.origin, selfdestruct, delegatecall, ecrecover)
  - Third-party library vulnerability scanning (Uniswap, Compound)

#### API Enhancements
- SSE (Server-Sent Events) streaming endpoint `/mcp/stream/audit`
- DeFi-specific analysis endpoint `/mcp/defi/analyze`
- Real-time layer-by-layer progress updates

#### Scientific Validation
- **SmartBugs benchmark integration** (143 contracts, 207 vulnerabilities)
  - 50.22% recall (outperforms individual tools)
  - 87.5% recall on reentrancy vulnerabilities
  - 89.3% recall on unchecked low-level calls
- Automated evaluation script with metrics calculation
- Scientific report generation for thesis

#### Performance Benchmarks
- Scalability benchmarks demonstrating 346 contracts/minute
- 3.53x parallel speedup with 4 workers
- Memory-efficient analysis (< 5 MB per contract)

### Changed
- Updated MCP REST API to version 4.1.0
- Improved Solidity version auto-detection for legacy contracts (0.4.x - 0.8.x)
- Enhanced error handling in tool adapters
- Architecture extended from 7 to 9 layers (Layers 8-9 are post-thesis work)

### Fixed
- Foundry.toml interference with Slither analysis on SmartBugs dataset
- Solc version selection for legacy contracts

---

## [Historical — DPGA submission (2025-12)]

### Added
- **DPGA Application Submitted** (December 5, 2025)
  - Application ID: GID0092948
  - Status: Under Review
  - Contact: Bolaji Ayodeji (DPG Evangelist)
  - Expected review period: 4-8 weeks
- Complete DPG compliance documentation package
- DPGA Application Responses CSV for reference

## [4.0.0] - 2025-01-14

### Added

> _Per-technique metrics in this section (PropertyGPT recall, DA-GNN accuracy, RAG
> precision, DogeFuzz coverage/speed) are figures **reported by the cited source
> papers**, not independently benchmarked by MIESC. MIESC's own corpus results are
> the SmartBugs-curated / EVMBench / real-world-exploit numbers._

- **PropertyGPT** (Layer 4 - Formal Verification): Automated CVL property generation
  - 80% recall on ground-truth Certora properties
  - Increases formal verification adoption from 5% to 40% (+700%)
  - Based on NDSS 2025 paper (arXiv:2405.02580)
- **DA-GNN** (Layer 6 - ML Detection): Graph Neural Network-based vulnerability detection
  - 95.7% accuracy with 4.3% false positive rate
  - Control-flow + data-flow graph representation
  - Based on Computer Networks (ScienceDirect, Feb 2024)
- **SmartLLM RAG + Verificator** (Layer 5 - AI Analysis): Enhanced AI-powered analysis
  - Retrieval-Augmented Generation with ERC-20/721/1155 knowledge base
  - Multi-stage pipeline: Generator → Verificator → Consensus
  - Precision improved from 75% to 88% (+17%), FP rate reduced by 52%
  - Based on arXiv:2502.13167 (Feb 2025)
- **DogeFuzz** (Layer 2 - Dynamic Testing): Coverage-guided fuzzer with hybrid execution
  - AFL-style power scheduling algorithm
  - 85% code coverage, 3x faster than Echidna
  - Parallel execution with 4 workers
  - Based on arXiv:2409.01788 (Sep 2024)
- Certora adapter (formal verification integration)
- Halmos adapter (symbolic testing for Foundry)
- DAG-NN adapter (graph neural network detection)

### Changed
- Increased tool count from 22 to 25 adapters (+13.6%)
- Restructured repository to UNIX/OSS conventions
- Updated README with comprehensive "What's New in v4.0" section
- Improved scientific rigor in documentation

### Research Papers Integrated
- NDSS Symposium 2025: PropertyGPT for automated property generation
- Computer Networks 2024: DA-GNN for graph-based vulnerability detection
- arXiv 2025: SmartLLM with RAG and Verificator enhancements
- arXiv 2024: DogeFuzz coverage-guided fuzzing

## [3.5.0] - 2025-01-13

### Added
- OpenLLaMA local LLM integration for AI-assisted analysis
- Aderyn adapter (Rust-based static analyzer)
- Medusa adapter (coverage-guided fuzzer)
- AI enhancement for Layers 3-4 (symbolic execution, formal verification)
- SmartLLM, GPTScan, LLM-SmartAudit adapters
- SMTChecker adapter (built-in Solidity verification)
- Wake adapter (Python development framework)
- 117 unit and integration tests
- CI/CD workflow with automated tool installation
- Complete adapter documentation

### Changed
- Increased tool count from 15 to 17
- Improved test coverage to 87.5%
- Enhanced DPGA compliance (100% maintained)

## [3.4.0] - 2025-11-08

### Added
- Aderyn and Medusa adapters
- 17 security tool integrations

### Changed
- Test suite expanded to 117 tests

## [2.2.0] - 2024-10-XX

### Added
- 15 security tool integrations
- AI-assisted triage (GPT-4, Llama)
- PolicyAgent v2.2 (12 compliance standards)
- Model Context Protocol (MCP) architecture
- 30 regression tests
- Comprehensive documentation

## [2.1.0] - 2024-09-XX

### Added
- Multi-agent architecture
- Initial MCP integration
- Compliance mapping framework

## [2.0.0] - 2024-08-XX

### Added
- Complete framework rewrite
- 7-layer defense architecture
- Initial tool adapters (10)

## [1.0.0] - 2024-06-XX

### Added
- Initial proof-of-concept
- Basic Slither and Mythril integration

---

[Unreleased]: https://github.com/fboiero/MIESC/compare/v5.4.3...HEAD
[5.4.3]: https://github.com/fboiero/MIESC/compare/v5.4.2...v5.4.3
[5.4.2]: https://github.com/fboiero/MIESC/compare/v5.4.1...v5.4.2
[5.4.1]: https://github.com/fboiero/MIESC/compare/v5.4.0...v5.4.1
[4.3.4]: https://github.com/fboiero/MIESC/compare/v4.3.3...v4.3.4
[4.3.3]: https://github.com/fboiero/MIESC/compare/v4.3.2...v4.3.3
[4.3.2]: https://github.com/fboiero/MIESC/compare/v4.2.1...v4.3.2
[4.2.1]: https://github.com/fboiero/MIESC/compare/v4.1.0...v4.2.1
[4.1.0]: https://github.com/fboiero/MIESC/compare/v4.0.0...v4.1.0
[4.0.0]: https://github.com/fboiero/MIESC/compare/v3.5.0...v4.0.0
[3.5.0]: https://github.com/fboiero/MIESC/compare/v3.4.0...v3.5.0
[3.4.0]: https://github.com/fboiero/MIESC/compare/v2.2.0...v3.4.0
[2.2.0]: https://github.com/fboiero/MIESC/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/fboiero/MIESC/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/fboiero/MIESC/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/fboiero/MIESC/releases/tag/v1.0.0
