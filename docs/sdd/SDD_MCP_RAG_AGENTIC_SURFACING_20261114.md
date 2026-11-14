# SDD: MCP, RAG and Agentic Surfacing & Hardening

Date: 2026-11-14
Owner lane: Claude (side-session, blissful-einstein-961e3f)
Status: proposed — design + first slice, pending Fernando's approval

## 0. Premise correction (read first)

The task that opened this lane stated *"There is no MCP surface today."* **That is
false, and verified against code at v6.8.0.** MIESC already ships:

- A real **Model Context Protocol server** — `miesc/mcp_server.py` (1059 LOC),
  built on the official `mcp` SDK 1.x (`mcp.server.fastmcp.FastMCP`), ~22
  `@mcp.tool()` tools, stdio transport, shipped as console script
  `miesc-mcp = "miesc.mcp_server:main"` (`pyproject.toml:176`). Hardened via
  PR #134.
- A **second, older "MCP"-named stack** — `miesc/mcp_core/` (custom
  `ContextBus`, `MCPToolRegistry`, a WebSocket server) launched by
  `miesc server mcp`.

So the real work is **not** "build an MCP server". It is: harden and extend the
one that exists, build the **consumer** side that is genuinely missing, resolve
the naming/honesty problems in the second stack, and close concrete **RAG** and
**agentic** gaps. This matches the user's own framing: *the MCP/RAG/agentic
capability is powerful but under-surfaced and under-optimised.*

Every claim below carries a `file:line` anchor so it is checkable.

## 1. Signal

MIESC has a large, capable MCP/RAG/agentic subsystem that is (a) under-documented,
(b) partially duplicated, and (c) in two specific places **dishonestly described**
or **unsafe by default**. A demanding open-source maintainer or academic reviewer
reaches these within minutes. This SDD maps the real state, proposes a hardening
and surfacing plan, and recommends a single first implementable slice.

## 2. Current state (verified map)

### 2.1 Four overlapping server/streaming surfaces

| # | Entry point | Module | What it is | Honest? |
|---|---|---|---|---|
| 1 | `miesc-mcp` | `miesc/mcp_server.py` | **Real MCP** (FastMCP SDK, stdio, JSON-RPC, 22 tools) | ✅ yes |
| 2 | `miesc server mcp` | `miesc/mcp_core/websocket_server.py` | Custom WebSocket event stream, **claims MCP** | ❌ no (see 2.2) |
| 3 | (import) | `miesc/core/websocket_api.py` | FastAPI WebSocket streaming API (`[api]` extra) | ✅ (no MCP claim) |
| 4 | `miesc server rest` | `miesc/api/rest.py` | Django REST API, port 5001 | ✅ |

`miesc/mcp/__init__.py` is a thin re-export shim over `mcp_core` — and it is
**broken**: it does `from miesc.mcp_core.tool_registry import ToolRegistry`
(`miesc/mcp/__init__.py:9`) but the class is named `MCPToolRegistry`
(`tool_registry.py:148`); the `ImportError` is swallowed and all three names
silently become `None`.

### 2.2 The dishonest surface (surface #2)

`miesc/mcp_core/websocket_server.py` docstring (lines 6, 12) claims it
*"Implements the Model Context Protocol (MCP) over WebSocket"* and is
*"Compatible with Claude Desktop and other MCP clients."* Both are **false**:

- Its wire protocol is a bespoke `{"command": "start_audit" | "subscribe" | ...}`
  message set (`_handle_message`, lines 226-267). It is **not** JSON-RPC 2.0 and
  has no `initialize` / `tools/list` / `tools/call`. Claude Desktop cannot speak
  to it.
- Its `_run_audit` is **partly simulated**: `# Simulate tool execution ...
  await asyncio.sleep(0.5)  # Simulate work` (lines 352-353); every layer just
  re-runs `SmartBugsDetectorEngine.analyze()` (line 357) regardless of layer, and
  the layer names (lines 432-443) contradict the canonical `LAYERS`. So
  `miesc server mcp` streams a **mock** audit advertised as a real 9-layer one.

The `ContextBus` half of `mcp_core` is, by contrast, **live and legitimate**:
`context_bus.MCPMessage` / `get_context_bus` are imported by `agents/base_agent.py`
and ~7 agents (policy, aderyn, recommendation, interpretation, coordinator, ai)
for inter-agent messaging. The problem is scoping and naming, not the bus itself.

### 2.3 The real MCP server (surface #1)

`miesc/mcp_server.py` delegates to existing CLI internals (good — no logic
duplication): `_run_tool_internal → miesc.cli.utils.run_tool` (133-139),
`_run_layer_internal → run_layer` (142-146), profiles via `cli.utils` (111).
22 tools across analysis / correlation / reports / system. Three **verified
defects**:

1. **`miesc_analyze_defi` calls a non-existent tool key.** It runs
   `_run_tool_internal("defi_analyzer", ...)` (`mcp_server.py:352`), but
   `ADAPTER_MAP` has key `"defi"` → `DeFiAdapter` (`cli/constants.py:167`); there
   is no `"defi_analyzer"`. `run_tool` returns `status:"skipped",
   reason:"no_adapter"`, so one of the three DeFi tools silently contributes
   nothing. (`mev_detector`, `advanced_detector` are correct keys.)
2. **`miesc_generate_report` reads only `audit_results["results"]`**
   (`mcp_server.py:604,619`). The ML `audit full` result shape has **no
   `results` key** (it is `raw_findings` / `ml_enhanced`), so SARIF/markdown
   reports from an ML-audit dict come out empty. The normaliser
   `cli.utils.results_from_result_file` exists for exactly this and is not used.
3. **stdout contamination risk on stdio transport.** `cli.utils.run_layer` /
   `run_tool` print progress to **stdout** via Rich `info()`/`success()`
   (`cli/utils.py`), while `mcp_server.main()` only redirects *logging* to stderr
   (`mcp_server.py:1050-1054`). On stdio JSON-RPC, stray stdout can corrupt the
   protocol stream. (Must be reproduced with the SDK's own `stdio_client`, not a
   `capsys` unit test — a Python-level redirect test passes while child-process
   fd-1 output still corrupts.)

Also: `_validate_contract_path` accepts only `.sol` / `.circom`
(`mcp_server.py:154`), so the non-EVM adapters the repo *does* have
(Solana/Cairo/Move/PolkaVM) are unreachable via MCP; and the deterministic plan
miners (`mine_*`, `agentic_contracts` plans) are **not exposed** at all —
`miesc_detect_exploit_chains` is a hardcoded 3-pattern string match
(`mcp_server.py:515-531`), not the real miners.

### 2.4 No single core entrypoint (duplication)

Adapter invocation is reimplemented in **five** places: `cli.utils.run_tool`
(CLI + MCP), `MLOrchestrator._run_tool` (`core/ml_orchestrator.py:280`),
`MIESCOrchestrator._run_tool` (`core/orchestrator.py`), `OptimizedOrchestrator._run_tool`,
and `rest.py:316` (unnormalised `no_adapter`/`not_available` statuses). SARIF has
**three** independent generators (`audit._to_sarif`, `rest.to_sarif`,
`core/exporters.SARIFExporter`). This is the structural reason the MCP, REST and
CLI surfaces drift.

### 2.5 RAG

`miesc/llm/embedding_rag.py` — `VulnerabilityDocument` (line 673) has
`swc_id`/`cwe_id` but **no `chain` field** and no invariant-provenance field; the
knowledge base is **93** EVM/Solidity documents (`VulnerabilityDocument(` ×93).
`to_metadata()` (725) has no chain key; `search()`/`multi_step_search()` filter
only by `category`/`severity` via `build_metadata_filter`. The FP path is
chain-coupled too: `ml/fp_filter.py` hardcodes `pragma solidity`, OpenZeppelin and
Chainlink paths. `ml/fp_ml_classifier.AuditorTrainedFPClassifier` exists but **no
trained model is shipped** (no `.pkl`/`.joblib`/`.onnx` under `miesc/`); it falls
back to `_heuristic_fp_probability`. These are precisely the whitepaper's Track-T2
gaps, now confirmed in code.

### 2.6 Agentic loops

The flagship `agents/deep_audit_agent.py` runs a bounded loop
(`while queue and iteration < max_iterations and not timeout`, line 870) and has a
deterministic-miner hook. But its LLM verifier
(`deep_audit_agent.py:1236-1263`) POSTs the **raw contract code** to Ollama
`/api/generate` via `urllib` with:
- **no** `detect_prompt_injection` / `sanitize_code_for_prompt` on the code,
- **no** `safe_parse_llm_json` (hand-rolled `text.index("{")`/`rindex("}")`),
- a **fail-open** default: unparseable output returns `{"confirmed": True}`
  (line 1260).

The module imports **none** of `miesc/security/` (sanitizer, output validator,
reproducibility). And `security/reproducibility.set_global_seeds` /
`ensure_reproducibility` have **zero runtime callers** — determinism is built but
never wired. The toolkit to fix all of this already exists:
`security/prompt_sanitizer.py` (`detect_prompt_injection`, `sanitize_code_for_prompt`,
`sanitize_context`, `build_safe_prompt`), `security/llm_output_validator.py`
(`safe_parse_llm_json`, pydantic `VulnerabilityFinding`/`VerificatorResponse`),
`security/reproducibility.py` (`set_global_seeds`, `ExperimentLogger`).

## 3. Target design

### 3.1 MCP server (surface #1) — the canonical MCP surface

- **Keep** `mcp_server.py` as THE MCP surface. Fix the three defects in 2.3.
- **Expose the deterministic plan miners** (`mine_*` / advisory plans) as a
  read-only `miesc_advisory_plans` tool, mirroring the existing CLI consumer
  pattern (advisory metadata, never `Finding`s → zero precision risk).
- **Widen `_validate_contract_path`** to the extensions the installed adapters
  declare (via adapter `applies_to`), so non-EVM chains are reachable — without
  hardcoding a chain list.
- **MCP resources & prompts** (currently tools-only): expose the SWC/CWE knowledge
  base and tool catalogue as MCP *resources* (`miesc://kb/{swc}`,
  `miesc://tool/{name}`) and ship a small set of audit *prompts*.
- **Transport & auth**: stdio stays the default (Claude Desktop, local, zero-auth
  by design). For remote agents, add MCP's **own** Streamable HTTP transport (the
  SDK provides it) behind a bearer token — **not** the custom WebSocket. Keep it
  an opt-in `[mcp]`-gated subcommand.
- **Boundary hardening**: route every `*_json` tool input through
  `prompt_sanitizer`/validator before it reaches an LLM, and treat all tool
  *inputs* as untrusted.

### 3.2 MCP consumption — the genuinely missing half

MIESC consumes **no** external MCP servers today. Design:

- A thin **MCP client** (`mcp.client.session.ClientSession` + `stdio_client` from
  the pinned 1.x SDK — availability to be confirmed at implementation time) that
  can call a configured allowlist of external MCP servers (e.g. a chain-RPC
  server, a CVE/advisory server, a docs server).
- **Trust model (non-negotiable):** external MCP output is **data, never
  instructions.** Every response passes through `detect_prompt_injection` +
  `sanitize_context` + pydantic validation, is normalised through the same
  `run_tool` status vocabulary, and is surfaced as *advisory evidence* in report
  metadata — never promoted to a `Finding` and never concatenated into a prompt
  unsanitised. Allowlist-only, per-call timeout, no autodiscovery.
- Natural seam: model an external MCP server as a MIESC **adapter** so it inherits
  availability gating, status normalisation and provenance for free.

### 3.3 Agentic loop hardening

- Wire `sanitize_code_for_prompt` + `build_safe_prompt` into
  `deep_audit_agent`'s LLM verifier; replace hand-rolled JSON parsing with
  `safe_parse_llm_json` + the pydantic `VerificatorResponse`.
- **Flip the fail-open to fail-closed**: unparseable/again-injected output →
  `confirmed: False` (or `inconclusive`), never an auto-confirm.
- Call `set_global_seeds` / `ensure_reproducibility` at the agentic entrypoint and
  record the seed + model version in provenance, so agentic runs are reproducible.

### 3.4 RAG — chain/invariant provenance + shipped FP model

- Add an additive `chain` field (default `"evm"`) + optional `invariant`
  provenance to `VulnerabilityDocument`, its `to_metadata()`, and an optional
  `filter_chain` on `search()`/`multi_step_search()`. **Caveat:** touching
  `to_text()` re-embeds all 93 docs and shifts EVM retrieval/FP behaviour; keep
  `chain` in *metadata + filter only* for v1, and verify persisted-index
  invalidation (`_collection_metadata`, ~line 5163) so a `chain` filter against an
  old collection does not silently return nothing.
- Decouple `fp_filter` Solidity assumptions behind a chain-aware guard.
- Decide the FP model story: either ship a trained artefact with a provenance card
  or document plainly that the heuristic fallback is the shipped behaviour (the
  current silent fallback overstates capability).
- Cross-model retrieval (Track-T2 implementation side) is **future**, not this
  SDD — no benchmark claims here.

### 3.5 Relabel `mcp_core` (honesty fix)

Rename/reframe surface #2 as what it is — an **internal agent event bus +
optional local streaming demo** — and **delete the "MCP / Claude Desktop
compatible" claims** and the simulated-audit path (or clearly mark it a demo).
Fix or remove the broken `miesc/mcp/` shim.

## 4. Long-term plan & scope (phased)

- **M0 — Honesty & correctness (this slice):** fix the 3 MCP-server defects;
  correct/relabel the false MCP/Claude-Desktop claims; fix the broken shim.
- **M1 — Surface the real capability:** docs + SVG diagrams of the true MCP/RAG/
  agentic architecture; expose plan miners + non-EVM paths + MCP resources.
- **M2 — Agentic safety:** sanitizer/validator/seeds wired into the agentic loop;
  fail-closed; reproducible runs.
- **M3 — RAG provenance:** `chain`/invariant metadata + filter; FP-model
  provenance; chain-aware FP.
- **M4 — MCP consumption:** external-MCP client with the untrusted-data trust
  model, as an adapter.
- **M5 — Remote transport:** MCP Streamable HTTP + bearer auth.

Scope guardrails: additive only; EVM path untouched; non-EVM stays Experimental;
no benchmark/claims-matrix changes; respect the paper freeze (README + `paper/**`
+ `benchmarks/results/**` are frozen; `docs/research/`, `docs/sdd/`, `miesc/` are
not).

## 5. Recommended first implementable slice (one PR)

**MCP-server correctness & honesty (M0).** Exactly:

1. Fix `miesc_analyze_defi` tool key `"defi_analyzer"` → `"defi"`.
2. Route `miesc_generate_report` input through `results_from_result_file` so ML
   audit dicts render.
3. Guard stdio stdout contamination (redirect fd-1 around tool calls), proven with
   a real `stdio_client` round-trip.
4. Delete the false "MCP / Claude Desktop compatible" claims from
   `mcp_core/websocket_server.py` and fix the broken `miesc/mcp/` shim import.

Why this slice first:
- **One PR, bounded, high trust-gain** — removes two silent-wrong behaviours and
  two dishonest claims a reviewer would flag immediately.
- **Existing test harness**: six `tests/test_mcp*.py` files to extend.
- **No frozen path, no benchmark effect, no precision risk** (no `Finding`
  changes).
- **Docs/SVGs can then describe true behaviour** — a precondition for the
  whitepaper/documentation work.

It beats the RAG `chain`-field slice as *first* because the chain field re-embeds
93 docs and perturbs EVM retrieval/FP (measurement needed first), whereas M0 is
pure correctness with no behavioural risk to the EVM line.

## 6. Tradeoffs & alternatives

- **Consolidate the 4 server surfaces now?** Tempting (it is the root duplication)
  but large and risky; defer behind M0. M0 at least stops the dishonest one from
  masquerading.
- **Custom WebSocket vs MCP Streamable HTTP for remote:** the custom bus is live
  for *inter-agent* messaging; for *external* agents the standard MCP transport is
  the correct, maintainable choice. Keep them separate concerns.
- **External MCP as adapter vs bespoke client:** adapter reuses gating/provenance;
  chosen.

## 7. Risks

- stdio stdout fix must be validated with a real client (capsys passes falsely).
- `chain` field index invalidation can silently zero-out retrieval.
- Relabelling `mcp_core` touches a file imported by the agent layer — change only
  docstrings/CLI help + the simulated path, not the `ContextBus` API.
- README and papers are frozen; any wording fix there needs an explicit
  new-baseline request from Fernando.

## 8. Out of scope

Benchmark re-runs, claims-matrix edits, cross-model retrieval evaluation, a full
server-surface consolidation, and any non-additive change to the EVM pipeline.
