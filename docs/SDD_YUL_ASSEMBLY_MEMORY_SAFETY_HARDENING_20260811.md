# SDD: Yul/Inline-Assembly Memory and Storage Safety Hardening

Date: 2026-08-11
Owner/Lane: Codex
Status: Proposed SDD, not implemented, no benchmark claim

## Signal

MIESC already records broad Solidity coverage: static analyzers, symbolic/formal tools, fuzzing adapters, semantic graph gates, sequence/snapshot plans, interprocedural summary planning, delegatecall storage aliasing, transient storage, external-call returndata, and local/provider-neutral reasoning contracts. Existing assembly coverage is mostly shallow: tools can flag `assembly` usage, direct `sstore`, `delegatecall`, `calldatacopy`, or low-level call patterns, but MIESC does not yet create a structured model of what an inline assembly block does to memory, calldata, storage, returndata, stack-derived pointers, or Solidity reference variables.

That gap matters because inline assembly deliberately crosses the boundary where Solidity's normal safety and optimizer assumptions are weaker. Solidity's documentation warns that memory-using inline assembly has to respect the Solidity memory model, that `memory-safe` annotations are the developer's responsibility, and that violating those assumptions can lead to undefined behavior that is hard to discover through testing. OWASP SCWE-039 also treats insecure inline assembly as a smart-contract weakness, including incorrect type conversions, unsafe low-level operations, and loss of funds or data. Slither currently exposes an `assembly` detector, but it is an informational warning rather than a semantic analysis of assembly effects.

The technique to add is **Yul/Inline-Assembly Memory and Storage Safety Hardening**: parse inline assembly fragments into bounded effect summaries, classify memory/storage/calldata/returndata hazards, and emit provider-neutral validation obligations that can feed semantic graph gating, SSA/interprocedural summaries, fuzzing, symbolic checks, and PoC scaffolding.

## Spec/Goal

Add a future capability named:

```text
yul_assembly_memory_safety_hardening
```

Expected output key:

```text
yul_assembly_safety_plans
```

Suggested aliases:

```text
assembly_memory_safety
yul_effect_summary
inline_assembly_hardening
```

The capability must produce advisory analysis and validation plans. A raw `assembly` block is not a vulnerability by itself; promotion requires a concrete unsafe effect, source anchor, reachable function context, and either deterministic evidence or a clearly reviewable validation obligation.

Primary objectives:

1. Extract inline assembly/Yul blocks with source anchors and enclosing Solidity function context.
2. Summarize reads/writes to memory, storage, calldata, returndata, free-memory pointer, zero slot, and Solidity reference variables.
3. Classify hazards such as unsafe `memory-safe` annotation, scratch-space overflow, free-memory pointer corruption, zero-slot corruption, unbounded `returndatacopy`, arbitrary `sstore`, unchecked downcast, manual calldata decoding without bounds, custom dispatch ambiguity, and low-level call/delegatecall side effects.
4. Generate validation obligations for fuzzing, symbolic execution, local fixture tests, or human review.
5. Preserve provider-neutral contracts so a deterministic local analyzer, local model, or hosted reasoning provider can be swapped without changing downstream interfaces.

## Design/Contract

Introduce a provider-neutral data contract before implementation:

```python
YulAssemblySafetyPlan = {
    "id": "string",
    "objective": "string",
    "source_anchor": "file:line",
    "enclosing_function": "string",
    "assembly_summary": {
        "dialect": "evm|yul|unknown",
        "is_memory_safe_annotated": "bool",
        "instructions": ["string"],
        "memory_reads": ["string"],
        "memory_writes": ["string"],
        "storage_reads": ["string"],
        "storage_writes": ["string"],
        "calldata_reads": ["string"],
        "returndata_reads": ["string"],
        "external_effects": ["call|delegatecall|staticcall|create|create2|selfdestruct"],
        "solidity_variable_bindings": ["string"],
    },
    "hazards": [
        {
            "category": "unsafe_memory_safe_annotation|scratch_space_overflow|free_memory_pointer_corruption|zero_slot_corruption|arbitrary_storage_write|manual_calldata_decode_without_bounds|unchecked_downcast|unbounded_returndata_copy|custom_dispatch_ambiguity|low_level_call_side_effect",
            "evidence": ["string"],
            "preconditions": ["string"],
            "negative_checks": ["string"],
            "confidence": "low|medium|high",
        }
    ],
    "validation_obligations": [
        {
            "tool": "foundry|echidna|halmos|local_fixture|human_review",
            "property": "string",
            "expected_failure_or_revert": "string",
            "inputs_to_mutate": ["string"],
            "budget_hint": "string",
        }
    ],
    "promotion": {
        "state": "hypothesis|test_generated|counterexample|replayed|rejected",
        "evidence": ["string"],
        "blockers": ["string"],
    },
    "metadata": {
        "capability": "yul_assembly_memory_safety_hardening",
        "schema_version": "1",
    },
}
```

The capability should compose existing MIESC pieces:

- Slither/Aderyn/Solhint can remain first-pass signal sources for `assembly`, `low-level-calls`, and related warnings.
- `SlithIR SSA + Interprocedural State/Taint Summary` can consume storage, calldata, and call-effect summaries.
- `SemanticGraphGate` can prioritize functions where assembly writes privileged state or forwards untrusted calldata.
- `External Call Returndata Hardening` can consume unbounded or unsafe returndata-copy summaries.
- `Delegatecall Storage Aliasing` can consume assembly `delegatecall` and `sstore` effects.
- `InvariantValidator`, Foundry, Echidna, and Halmos can validate generated properties.
- False-positive filtering must downgrade benign, bounded, compiler-supported, or unreachable assembly fragments.

## Prompt Requirements

Prompt and parser design must refer to an **interchangeable security reasoning agent**. No prompt, schema, parser, test, or SDD requirement may require one vendor, product, endpoint, or model family.

The reasoning agent must:

- Anchor every assembly effect to a source block and enclosing Solidity function.
- Separate observed instructions from inferred hazard hypotheses.
- Include negative checks for known-safe idioms and compiler-supported patterns.
- Treat `memory-safe` annotations as claims to validate, not proof.
- Avoid confirmed-finding language until execution, symbolic validation, or human review confirms impact.
- Support deterministic local fallback based on parsed opcodes and bounded heuristics.

## False-Positive Controls

The capability must avoid noisy "assembly is bad" findings:

- A block that only reads immutable values or uses bounded memory scratch space remains advisory unless a hazard is identified.
- `memory-safe` annotated blocks are not trusted blindly, but they are not findings without a violated memory-model rule.
- Direct `sstore` is not automatically exploitable; it requires reachability, attacker influence, or sensitive slot impact.
- Manual calldata decoding is not a finding if length checks dominate every load.
- Returndata copying is not a finding when bounded by the free-memory pointer and restored memory invariants.
- Assembly inside trusted libraries should retain library/version provenance and safe idiom notes.
- Provider output must be parser-bounded before any integration.

Promotion rules:

- `hypothesis`: assembly effect and hazard category only.
- `test_generated`: a check exists but has not produced a failing execution.
- `counterexample`: fuzzing or symbolic execution violates the property.
- `replayed`: deterministic local or fork replay demonstrates impact.
- `rejected`: negative checks prove the fragment is bounded, unreachable, or benign.

## Non-Goals

- No rewrite of the Solidity parser.
- No new EVM decompiler.
- No canonical benchmark update from this SDD alone.
- No blanket ban on inline assembly.
- No provider-specific reasoning dependency.
- No confirmed vulnerability when only an informational assembly warning exists.

## Integration Plan

Phase 0 is this SDD. Future work should land in small, testable steps:

1. Add schema contracts and parser tests under the provider-neutral agentic contract layer.
2. Add deterministic extraction of inline assembly blocks with source anchors.
3. Add a minimal Yul opcode/effect tokenizer for memory, storage, calldata, returndata, and call instructions.
4. Add local hazard classifiers for memory-safe annotation misuse, unbounded copies, arbitrary storage writes, and manual calldata decoding.
5. Bridge effect summaries into semantic graph, SSA/interprocedural summary, returndata hardening, and delegatecall aliasing surfaces.
6. Generate validation obligations for Foundry, Echidna, Halmos, local fixtures, and human review.
7. Keep evaluation non-canonical until a controlled baseline run is explicitly approved.

## 50-Activity Parallelization Map

These activities can run across five lanes with disjoint file ownership.

1. Inventory existing assembly-related detectors.
2. Inventory existing low-level call summaries.
3. Inventory existing returndata hardening fields.
4. Inventory delegatecall storage aliasing contract fields.
5. Inventory SlithIR/Yul/opcode data available from tool outputs.
6. Define `YulAssemblyBlock` schema.
7. Define `YulMemoryEffect` schema.
8. Define `YulStorageEffect` schema.
9. Define `YulCalldataEffect` schema.
10. Define `YulAssemblySafetyPlan` schema.
11. Add strict parser for canonical output key.
12. Add aliases for assembly safety plans.
13. Add bounded list/text sanitization.
14. Add no-provider-binding regression tests.
15. Export public facade symbols.
16. Implement assembly block extraction.
17. Preserve source anchors and enclosing function names.
18. Tokenize `mload`, `mstore`, and `mstore8`.
19. Tokenize `sload` and `sstore`.
20. Tokenize `calldataload`, `calldatacopy`, and calldata offset/length usage.
21. Tokenize `returndatasize` and `returndatacopy`.
22. Tokenize `call`, `delegatecall`, and `staticcall`.
23. Tokenize `create`, `create2`, and `selfdestruct`.
24. Detect `memory-safe` annotations.
25. Detect deprecated memory-safe comments.
26. Classify scratch-space overflow hazards.
27. Classify free-memory pointer corruption hazards.
28. Classify zero-slot corruption hazards.
29. Classify arbitrary storage write hazards.
30. Classify unchecked downcast hazards.
31. Classify manual calldata decode without bounds.
32. Classify unbounded returndata copy.
33. Classify custom dispatcher ambiguity.
34. Classify low-level call side effects.
35. Add negative checks for bounded scratch-space idioms.
36. Add negative checks for restored free-memory pointer.
37. Add negative checks for dominated calldata bounds.
38. Add negative checks for fixed storage-slot constants.
39. Bridge summaries into semantic graph gates.
40. Bridge summaries into interprocedural state/taint summaries.
41. Bridge returndata hazards into external-call returndata plans.
42. Bridge delegatecall hazards into storage aliasing plans.
43. Generate Foundry property metadata.
44. Generate Echidna property metadata.
45. Generate Halmos assertion metadata.
46. Add vulnerable fixture for unsafe downcast in assembly.
47. Add safe fixture for bounded downcast.
48. Add vulnerable fixture for unbounded returndata copy.
49. Add safe fixture for memory-safe returndata copy.
50. Add runbook notes for reviewing assembly plans against confirmed findings.

Parallel lanes:

- Lane A: schemas, parser, exports, and provider-neutral tests.
- Lane B: deterministic block extraction and opcode/effect tokenizer.
- Lane C: hazard classifiers and negative checks.
- Lane D: bridges into semantic graph, SSA summaries, delegatecall, and returndata plans.
- Lane E: fixtures, validation obligations, non-canonical evidence, and runbook notes.

## Validation

For this SDD:

```bash
test -s docs/SDD_YUL_ASSEMBLY_MEMORY_SAFETY_HARDENING_20260811.md
rg -n "interchangeable security reasoning agent|provider-neutral|50-Activity" docs/SDD_YUL_ASSEMBLY_MEMORY_SAFETY_HARDENING_20260811.md
git diff --check -- docs/SDD_YUL_ASSEMBLY_MEMORY_SAFETY_HARDENING_20260811.md
```

Provider/model-name checks should run against the document content during review and should return no requirement binding the capability to one provider.

For future implementation:

- Unit tests for block extraction and source anchors.
- Parser tests for bounded provider-neutral output.
- Fixture tests for unsafe and safe variants of each hazard family.
- Integration tests proving raw assembly warnings stay advisory.
- Non-canonical benchmark probes before any claimed uplift.

## References

- Solidity documentation: Inline Assembly and memory safety. https://docs.soliditylang.org/en/latest/assembly.html
- Solidity documentation: Yul. https://docs.soliditylang.org/en/latest/yul.html
- OWASP SCWE-039: Insecure Use of Inline Assembly. https://scs.owasp.org/SCWE/SCSVS-CODE/SCWE-039/
- Slither detector documentation: `assembly` and low-level call detectors. https://github.com/crytic/slither/wiki/Detector-Documentation
- A Study of Inline Assembly in Solidity Smart Contracts, OOPSLA 2022. https://doi.org/10.1145/3563328
- Local reference: `docs/SDD_DELEGATECALL_STORAGE_ALIASING_20260711.md`
- Local reference: `docs/SDD_EXTERNAL_CALL_RETURNDATA_HARDENING_20260712.md`
- Local reference: `docs/SDD_TRANSIENT_STORAGE_DETECTION_20260709.md`
