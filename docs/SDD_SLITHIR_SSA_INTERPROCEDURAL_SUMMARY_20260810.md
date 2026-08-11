# SDD: SlithIR SSA Interprocedural State and Taint Summaries

Date: 2026-08-10
Owner lane: Codex
Status: proposed, provider-neutral SDD

## 1. Signal

MIESC already wraps Slither as a subprocess, normalizes detector findings, tracks
SlithIR generation failures, keeps a local regex-based taint analyzer, and has
provider-neutral agentic contracts for semantic graph gating, sequence oracles,
snapshot fuzzing, invariant synthesis, exploit validation, and hardening
domains.

The gap is the missing middle artifact between raw Slither detector output and
agentic/fuzz/formal routing: an explicit, deterministic summary of SlithIR SSA
definitions, state reads/writes, external calls, tainted values, guards, and
interprocedural propagation.

That artifact matters because Slither's published design centers on SlithIR,
SSA, dataflow, and taint tracking. MIESC currently consumes Slither findings but
does not preserve the SSA/value-flow facts that would let downstream agents
answer higher-signal questions:

- Did attacker-controlled calldata influence a storage write or call target?
- Was a value read before an external call and written after it?
- Which internal calls propagate taint or state effects into a public entrypoint?
- Which functions are incomplete because SlithIR generation failed?
- Which findings should route to Foundry/Halmos/Echidna instead of staying as
  static hypotheses?

This SDD adds a local-first, provider-neutral summary contract. It does not add a
new external dependency beyond optional Slither Python API access when available.
If Slither is absent or only the CLI JSON is available, the feature degrades to
empty summaries plus existing adapter metadata.

## 2. Spec

Add a provider-neutral `slithir_ssa_summary` artifact that can be produced by a
local extractor and consumed by semantic graph gates, sequence oracles, snapshot
fuzzing, invariant synthesis, exploit validation, triage ranking, and reports.

Inputs:

- Solidity source path or project path.
- Optional Slither Python API object, if available.
- Existing Slither adapter metadata, including `analysis_incomplete` and
  `incomplete_functions`.
- Optional current findings, semantic graph gates, and policy bounds.
- Policy constraints: local-first, max functions, max operations, max evidence
  strings, deterministic ordering.

Output:

```json
{
  "slithir_ssa_summaries": [
    {
      "contract": "Vault",
      "function": "withdraw(uint256)",
      "visibility": "external",
      "entrypoint": true,
      "analysis_complete": true,
      "state_reads": [
        {
          "variable": "balances",
          "ssa_name": "balances_1",
          "source": "balances[msg.sender]",
          "line": 42
        }
      ],
      "state_writes": [
        {
          "variable": "balances",
          "ssa_name": "balances_2",
          "value_source": "0",
          "line": 44
        }
      ],
      "external_calls": [
        {
          "kind": "low_level_call",
          "target": "msg.sender",
          "value_source": "bal_1",
          "guarded_by_success": false,
          "line": 43
        }
      ],
      "taint_flows": [
        {
          "source": "msg.sender",
          "sink": "external_call.target",
          "path": ["msg.sender", "LOW_LEVEL_CALL.target"],
          "sanitized": false,
          "confidence": 0.9
        }
      ],
      "interprocedural_effects": [
        {
          "callee": "_debit(address,uint256)",
          "state_reads": ["balances"],
          "state_writes": ["balances"],
          "taint_sources": ["function_parameter"],
          "summary_confidence": 0.84
        }
      ],
      "risk_waypoints": [
        {
          "kind": "read_call_write",
          "variables": ["balances"],
          "recommended_tools": ["foundry", "halmos", "echidna"],
          "evidence": ["balances read before external call and written after it"]
        }
      ]
    }
  ]
}
```

Non-goals:

- Replacing Slither detectors.
- Shipping a new whole-program static analyzer in this checkpoint.
- Requiring a remote model, vendor API, or non-DPG-compatible provider.
- Claiming benchmark uplift before non-canonical evidence exists.
- Writing canonical benchmark outputs or frozen paper artifacts.

## 3. Design

### 3.1 Extractor

Add a local extractor in a future implementation checkpoint, for example
`miesc/formal/slithir_ssa_summary.py` or `miesc/ml/slithir_ssa_summary.py`.
The extractor should prefer the Slither Python API because it exposes contracts,
functions, nodes, SlithIR operations, SSA variables, reads/writes, calls, and
source mappings directly. The adapter should not shell-parse human printer
output as the primary path.

Fallback modes:

1. `api`: full summary from Slither Python objects.
2. `json_metadata`: no SSA facts, but preserve Slither detector findings and
   incomplete-analysis metadata.
3. `source_heuristic`: bounded compatibility mode that only emits conservative
   signals already available from MIESC's regex taint analyzer.
4. `unavailable`: empty artifact with reason and no vulnerability claims.

### 3.2 Summary Construction

For each contract function:

1. Identify public/external entrypoints and reachable internal callees.
2. Walk SlithIR SSA operations in deterministic source/node/order order.
3. Record state reads, state writes, low-level calls, high-level external calls,
   delegatecalls, staticcalls, transfers, sends, return-value checks, revert
   guards, and modifier/require/assert guards.
4. Build local use-def facts from SSA names.
5. Mark taint sources: calldata, function parameters, `msg.sender`,
   `msg.value`, `msg.data`, `tx.origin`, oracle return data, external call
   return data, and storage reads configurable by domain.
6. Propagate taint through SSA assignments, tuple unpacking, index operations,
   arithmetic, ABI encoding/decoding, and internal-call arguments.
7. Compute compact interprocedural summaries for each callee:
   state read set, state write set, external-call surface, taint source set,
   taint sink set, and guard set.
8. Inline callee effects into entrypoint summaries with a recursion and budget
   cap.

### 3.3 Risk Waypoints

The artifact should produce waypoints, not final findings. Downstream tools can
turn them into agentic tasks, fuzz campaigns, formal properties, or review
prompts.

Initial waypoint kinds:

- `read_call_write`: same state variable read before external call and written
  after the call.
- `tainted_call_target`: user-controlled value reaches a call/delegatecall
  target.
- `tainted_call_value`: user-controlled value reaches transferred ETH amount.
- `tainted_storage_write`: user-controlled value reaches privileged or critical
  storage.
- `unchecked_external_result`: external call success or return data is not
  checked before state transition.
- `cross_function_guard_gap`: public entrypoint reaches internal state mutation
  without an authorization guard in the call path.
- `oracle_taint_to_accounting`: external oracle return data influences shares,
  collateral, debt, liquidation, fee, or price accounting.
- `incomplete_ir_function`: SlithIR failure means detector coverage was partial.

### 3.4 Provider-Neutral Agent Contract

A future agentic contract can add:

- `AgentCapability.SLITHIR_SSA_SUMMARY`.
- `SlithIRSSASummary`, `SSAStateAccess`, `SSAExternalCall`, `SSATaintFlow`,
  `InterproceduralEffect`, and `RiskWaypoint` dataclasses.
- `SlithIRSSASummaryAgent` that asks a provider or local model to review the
  bounded summary, not raw full source.
- Parser and sanitizer helpers with strict text/list/object caps.

The local extractor remains authoritative for facts. A provider may classify or
prioritize waypoints, but it must not invent SSA facts not present in the
artifact.

## 4. False-Positive Controls

- SSA facts are observations; waypoints are hypotheses; confirmed findings stay
  in the existing finding pipeline.
- Each waypoint must include at least one concrete source mapping, variable, or
  operation evidence item.
- Interprocedural summaries must carry a confidence that drops when call targets
  are dynamic, inherited, unresolved, or budget-truncated.
- Taint propagation must distinguish direct, derived, storage-derived, and
  unknown-origin taint.
- Incomplete SlithIR analysis is a coverage warning, not a vulnerability.
- Deterministic ordering is required for reproducible evidence and small diffs.
- Remote providers can be replaced by local heuristics; provider names do not
  appear in the artifact schema.

## 5. Integration Plan

Discovery and schema:

1. Inventory Slither Python API fields for contracts, functions, CFG nodes,
   SlithIR operations, SSA variables, reads, writes, calls, and source mappings.
2. Map MIESC's current `TaintSource`, `TaintSink`, and `SanitizerType` enums to
   SSA summary fields.
3. Define maximum summary sizes for default, CI, and paper profiles.
4. Define stable JSON schema and dataclasses.
5. Define empty/unavailable/incomplete states.

Local extractor:

6. Add extractor module and pure dataclasses.
7. Add fixtures for one-contract and multi-contract internal-call summaries.
8. Add tainted call target/value/storage-write propagation tests.
9. Add read-call-write waypoint tests.
10. Add incomplete SlithIR metadata carry-through tests.

Agentic and routing:

11. Add optional agentic contract wrappers.
12. Feed summaries into semantic graph gates as precise graph edges.
13. Feed read/write/call waypoints into sequence-oracle planning.
14. Feed oracle/accounting waypoints into invariant synthesis.
15. Feed high-confidence waypoints into Foundry/Halmos/Echidna routing.

CLI, config, reports:

16. Add opt-in config `enable_slithir_ssa_summary`.
17. Add CLI JSON emission behind the same opt-in.
18. Add report section that explains waypoint evidence without overclaiming.
19. Add MCP schema exposure if existing MCP surfaces accept analysis artifacts.
20. Add repository hygiene notes for non-canonical evidence paths.

Evaluation:

21. Run focused unit fixtures first.
22. Run a non-canonical SmartBugs slice with dated Codex outputs.
23. Compare triage quality and tool-routing hit rate, not paper TPR claims.
24. Promote only if waypoints reduce false positives or produce confirmed PoCs.
25. Update paper/benchmark claims only after Fernando explicitly approves a new
    baseline.

Parallelization:

- Items 1-5 are read-only and safe for parallel explorers.
- Items 6-10 should stay in one writer group around the extractor and tests.
- Items 11-15 can split only after schema stabilizes.
- Items 16-20 touch shared CLI/config/docs and require claims.
- Items 21-25 must avoid canonical benchmark outputs.

## 6. Validation

For this SDD-only checkpoint:

```bash
git diff --check -- docs/SDD_SLITHIR_SSA_INTERPROCEDURAL_SUMMARY_20260810.md
```

For the first implementation checkpoint:

```bash
python3 -m py_compile miesc/adapters/slither_adapter.py miesc/ml/taint_analysis.py
python3 -m pytest tests/test_slither_incomplete_analysis.py -q
```

Expected implementation assertions:

- Slither unavailable produces a valid empty summary.
- Incomplete SlithIR generation propagates into `analysis_complete: false`.
- SSA read/write/call ordering is deterministic.
- Taint flows never become confirmed vulnerabilities by themselves.
- Interprocedural recursion is capped and marked when truncated.
- Provider/model replacement does not change the JSON contract.

## 7. References

- Slither repository and API: https://github.com/crytic/slither
- SlithIR SSA wiki: https://github.com/crytic/slither/wiki/SlithIR-SSA
- Slither data dependency wiki: https://github.com/crytic/slither/wiki/data-dependency
- Slither paper: https://arxiv.org/abs/1908.09878
- MIESC local Slither adapter: `miesc/adapters/slither_adapter.py`
- MIESC local taint analyzer: `miesc/ml/taint_analysis.py`
- MIESC local SlithIR notes: `docs/tesis/APENDICE_TECNICAS_ANALISIS.md`
