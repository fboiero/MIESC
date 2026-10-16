# SDD: Semantic Graph Gating for Solidity Vulnerability Detection

Date: 2026-07-09
Owner lane: Codex
Status: proposed, first provider-neutral graph gate contract implemented

## 1. Signal

MIESC now has static detectors, symbolic execution, fuzzing, invariant
synthesis, sequence-oracle plans, PoC generation, and provider-neutral agentic
contracts. The remaining gap is explainable context selection.

Recent work points to graph-shaped intermediate representations:

- GNNSE builds semantic graphs for control/data dependencies and uses them to
  decide which contracts deserve symbolic execution.
- ByteEye constructs edge-enhanced bytecode CFGs and learns vulnerability
  signals from graph features.
- CKG-LLM builds contract knowledge graphs from Slither IR and translates
  vulnerability descriptions into graph queries.
- BugSweeper uses function-level graph representations to detect unsafe
  inter-function interactions.
- Heterogeneous semantic graph work combines AST-derived structure, variables,
  and function calls to improve generalization.

MIESC already has call graphs, Slither IR parsing, RAG, and agentic reasoning,
but it lacks a stable artifact that says: these are the graph nodes, relations,
focal anchors, graph queries, and downstream tools that should receive priority.

## 2. Spec

Add a provider-neutral semantic graph gate artifact.

Inputs:

- Solidity source.
- Existing findings.
- Optional Slither IR/call/data-dependency summaries.
- Optional sequence-oracle or invariant outputs in later phases.
- Policy constraints: local-first, max source chars, max nodes.

Output:

```json
{
  "semantic_graph_gates": [
    {
      "id": "withdraw_access_gate",
      "objective": "Focus privileged withdraw path for access control review",
      "target_vulnerability_types": ["access_control"],
      "focal_nodes": ["fn_withdraw"],
      "nodes": [
        {
          "id": "fn_withdraw",
          "kind": "function",
          "label": "withdraw(uint256)",
          "contract": "Vault",
          "function": "withdraw",
          "line": 42,
          "metadata": {}
        }
      ],
      "edges": [
        {
          "source": "fn_withdraw",
          "target": "state_owner",
          "relation": "missing_guard",
          "confidence": 0.81,
          "evidence": ["withdraw writes value without onlyOwner"]
        }
      ],
      "graph_queries": ["find external value movement without role guard"],
      "recommended_tools": ["slither", "mythril", "halmos"],
      "confidence": 0.77,
      "rationale": "external value movement lacks an authorization edge"
    }
  ]
}
```

Non-goals for this checkpoint:

- Training or shipping a GNN model.
- Replacing Slither, Mythril, Halmos, Echidna, or Foundry.
- Claiming precision/recall uplift.
- Touching frozen paper artifacts or canonical benchmark outputs.
- Binding the feature to a specific model or API provider.

## 3. Design

Implemented first checkpoint:

1. Add `AgentCapability.SEMANTIC_GRAPH_GATING`.
2. Add `SemanticGraphNode` and `SemanticGraphEdge`.
3. Add `SemanticGraphGate` as the routing/focal-context artifact.
4. Add `SemanticGraphGateAgent` to build a bounded `ReasoningTask`.
5. Add `parse_semantic_graph_gates()` with strict sanitization.
6. Export the contract through `src.llm` and `miesc.llm`.

This keeps MIESC local-first and replaceable. A local heuristic, local model,
approved remote provider, Slither IR adapter, bytecode graph extractor, or
future GNN scorer can all produce the same JSON shape.

False-positive controls:

- A gate requires an objective and at least one focal node, graph node, or edge.
- Graph gates are analysis-priority hypotheses, not vulnerability findings.
- Scores are bounded to `[0, 1]`.
- Text, list, metadata, source, node, and edge sizes are bounded.
- Graph relations must be explainable through evidence and rationale.

## 4. Validation

Focused validation:

```bash
pytest tests/test_agentic_contracts.py tests/test_miesc_llm_exports.py -q
ruff check src/llm/agentic_contracts.py src/llm/__init__.py miesc/llm/__init__.py tests/test_agentic_contracts.py tests/test_miesc_llm_exports.py
```

Required assertions:

- capability is provider-neutral;
- prompts avoid vendor/model binding;
- malformed graph objects are rejected or sanitized;
- graph gates require meaningful focus;
- public `miesc.llm` exports remain stable;
- hostile scalar fields cannot leak into output.

## 5. Integration Plan

The next 50 activities are split into lanes that can run in parallel when file
ownership is disjoint.

Research and schema:

1. Compare semantic graph fields from GNNSE, ByteEye, CKG-LLM, BugSweeper.
2. Map MIESC Slither IR fields to graph node kinds.
3. Map MIESC call graph fields to graph edge kinds.
4. Map findings to focal node anchors.
5. Define bytecode CFG node compatibility without requiring bytecode first.
6. Define graph-query text conventions.
7. Define target vulnerability labels for graph gates.
8. Define risk scoring semantics.
9. Define non-canonical evidence filenames.
10. Document DPG/local-first execution boundaries.

Contract and local builder:

11. Add semantic graph contracts.
12. Add parser and sanitization tests.
13. Add local heuristic graph gate provider support.
14. Extract function nodes from source.
15. Extract state-variable nodes from source.
16. Extract modifier/role nodes from source.
17. Extract external-call nodes from source.
18. Extract reads/writes/calls/guards edges.
19. Generate deterministic focal node IDs.
20. Add source-range snippets as later optional metadata.

Agentic integration:

21. Feed graph gates into finding judgment tasks.
22. Feed graph gates into sequence-oracle tasks.
23. Feed graph gates into property synthesis tasks.
24. Use graph gates to choose symbolic/fuzz/formal tools.
25. Add opt-in `enable_semantic_graph_gating` config.
26. Add paper profile capability without changing benchmark claims.
27. Add MCP schema exposure.
28. Add CLI JSON output for gates.
29. Add report section for graph-focus rationale.
30. Add traceability from final finding to graph gate.

Tool and adapter integration:

31. Ingest Slither call graph when available.
32. Ingest Slither data-dependency printer output.
33. Ingest existing `src/ml/call_graph.py` output.
34. Ingest `src/ml/slither_ir_parser.py` summaries.
35. Route high-risk gates to Mythril/Halmos.
36. Route graph-gated stateful gates to Echidna/Foundry.
37. Route access-control gates to semantic detectors.
38. Route bytecode-only projects to future ByteEye-like extractor.
39. Preserve deterministic ordering for repeatable evidence.
40. Add resource/time bounds.

Evaluation and promotion:

41. Run focused unit fixtures for access control.
42. Run focused unit fixtures for reentrancy.
43. Run focused unit fixtures for timestamp dependency.
44. Run focused unit fixtures for oracle manipulation.
45. Run non-canonical benign false-positive slice.
46. Run non-canonical SmartBugs graph-gated slice.
47. Record only dated Codex-specific outputs.
48. Compare gate precision before any paper claim.
49. Prepare promotion criteria for Fernando review.
50. Only after explicit approval, update baseline/claims.

Parallelization:

- Activities 1-10 are read-only and safe for explorers.
- Activities 11-20 should stay in one writer group around `src/llm`.
- Activities 21-30 touch agent/CLI/MCP and require claims per file group.
- Activities 31-40 can split by parser/adapter ownership.
- Activities 41-50 must avoid canonical benchmark paths.

## 6. References

- GNNSE: https://www.techscience.com/cmc/v86n2/64772
- ByteEye: https://link.springer.com/article/10.1007/s10515-025-00559-9
- CKG-LLM: https://arxiv.org/html/2512.06846v2
- BugSweeper: https://arxiv.org/html/2512.09385v1
- Heterogeneous semantic graphs: https://www.mdpi.com/2079-9292/13/18/3786
