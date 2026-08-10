# SDD: Delegatecall Storage Aliasing

Date: 2026-07-11
Owner: Codex lane
Status: proposed, first provider-neutral plan contract implemented

## 1. Signal

MIESC already has regex/static delegatecall detectors, proxy-upgrade checks, and
upgrade-evolution analysis. The remaining gap is a more precise agentic artifact:
not "delegatecall exists", but whether a delegatecall target, selector, and callee
write path can reinterpret or corrupt caller storage.

The technique is delegatecall storage aliasing: inventory delegatecall surfaces,
target trust boundaries, selector control, caller/callee slot semantics, callee
writes, and validation tests that prove or reject owner/admin/initializer/value
context corruption.

Relevant external signals:

- DelegateTracker frames delegatecall detection around read/write data-flow
  capture, attack-path search, and attack-path validation rather than keyword
  matching.
- CRUSH studies storage collision as a cross-contract vulnerability where two
  contracts share storage through delegatecall but interpret slots differently.
- OWASP SCWE-035 treats insecure delegatecall as a communication weakness that
  can expose unauthorized actions, callee vulnerabilities, and asset/data loss.
- SWC-112 recommends treating delegatecall to untrusted or user-derived targets
  as dangerous unless targets are explicitly trusted.

## 2. Spec

Add a provider-neutral capability:

`delegatecall_storage_aliasing`

The capability emits `delegatecall_storage_aliasing_plans`, each containing:

- `delegatecall_surfaces`: entry points, target source, selector source, trust
  boundary, guards, value context, and evidence.
- `storage_alias_paths`: caller slot, callee slot, caller semantics, callee
  semantics, callee write source, path condition, and evidence.
- `risks`: target control, selector control, storage collision, slot semantics,
  callee write, initializer takeover, selfdestruct, value context, and access
  context hypotheses.
- `validation_tests`: Foundry/symbolic checks such as malicious callee writes
  to owner/admin slot, selector mutation, and whitelisted-target bypass.

Parser aliases:

- `delegatecall_storage_aliasing_plans`
- `delegatecall_aliasing_plans`
- `storage_collision_plans`

Non-goals:

- Replacing generic proxy-upgrade analysis.
- Replacing local regex detection for SWC-112.
- Claiming exploitability without a concrete callee write path or slot-semantics
  mismatch.
- Binding to any specific model, hosted API, or vendor.
- Editing frozen paper artifacts or canonical benchmark outputs.

## 3. Design

Implemented first checkpoint:

1. Add `AgentCapability.DELEGATECALL_STORAGE_ALIASING`.
2. Add `DelegatecallSurface`.
3. Add `StorageAliasPath`.
4. Add `DelegatecallAliasRisk`.
5. Add `DelegatecallStorageAliasingPlan`.
6. Add `DelegatecallStorageAliasingAgent`.
7. Add `parse_delegatecall_storage_aliasing_plans()`.
8. Export the contract through `src.llm` and `miesc.llm`.

The plan is validation guidance. It should feed Foundry tests, symbolic
execution, Slither review, or a future local heuristic provider. It does not by
itself become a vulnerability finding.

False-positive controls:

- Require delegatecall evidence before producing surfaces.
- Keep target trust boundary explicit.
- Treat standard immutable/library patterns differently from user-controlled
  target selection.
- Require storage slot evidence or validation test evidence before high
  confidence.
- Keep upgrade-evolution risks separate unless old/new implementation state is
  actually supplied.

## 4. Validation

Focused tests:

- Provider-neutral agent capability and prompt tests.
- Parser alias and confidence-bound tests.
- Incomplete item rejection.
- Direct dataclass `to_dict()` sanitization.
- Public `miesc.llm` facade export and parser usability.

No frozen papers, canonical benchmark outputs, or claims matrices are part of
this checkpoint.

## 5. Integration Plan: 50 Activities

Discovery:

1. Inventory Solidity `.delegatecall(...)` expressions.
2. Inventory inline assembly `delegatecall` opcodes.
3. Inventory fallback/receive delegation paths.
4. Inventory diamond/facet dispatch paths.
5. Inventory plugin/module execution paths.
6. Inventory implementation slot sources.
7. Inventory registry-derived targets.
8. Inventory user-supplied targets.
9. Inventory selector forwarding sources.
10. Classify target trust boundaries.

Storage and path reasoning:

11. Extract caller storage layout when available.
12. Extract callee storage layout when available.
13. Map caller slots to callee slots.
14. Detect slot type/semantic mismatch.
15. Detect callee writes to owner/admin slots.
16. Detect callee writes to initializer slots.
17. Detect callee writes to balance/accounting slots.
18. Detect callee selfdestruct paths.
19. Detect msg.sender context assumptions.
20. Detect msg.value context assumptions.

Contract and parser:

21. Add provider-neutral capability.
22. Add delegatecall surface schema.
23. Add storage alias path schema.
24. Add risk schema.
25. Add hardening plan schema.
26. Add parser aliases.
27. Add direct sanitization tests.
28. Add public exports.
29. Add public facade tests.
30. Keep no-signal output empty.

Validation generation:

31. Generate malicious callee slot-write test.
32. Generate selector mutation test.
33. Generate untrusted-target bypass test.
34. Generate whitelisted-target negative test.
35. Generate initializer replay/takeover test.
36. Generate owner/admin slot corruption test.
37. Generate selfdestruct context test.
38. Generate msg.sender privilege-context test.
39. Generate msg.value accounting-context test.
40. Generate diamond facet collision test.

Evaluation:

41. Add safe immutable-library fixture.
42. Add unsafe user-target fixture.
43. Add Parity-style library fixture.
44. Add diamond facet slot alias fixture.
45. Add registry-controlled target fixture.
46. Add layout mismatch fixture.
47. Run non-canonical fixture suite.
48. Compare delegatecall aliasing TPR/FPR only on ground-truth fixtures.
49. Prepare promotion memo for Fernando.
50. Update paper/benchmark claims only after explicit approval.

## 6. References

- DelegateTracker: Delegatecall vulnerability detection tool based on
  read-write data flow capture:
  https://www.sciencedirect.com/science/article/pii/S209672092500065X
- CRUSH / Not your Type! Detecting Storage Collision Vulnerabilities in
  Ethereum Smart Contracts:
  https://www.ndss-symposium.org/ndss-paper/not-your-type-detecting-storage-collision-vulnerabilities-in-ethereum-smart-contracts/
- CRUSH artifact:
  https://github.com/ucsb-seclab/crush
- OWASP SCWE-035 Insecure Delegatecall Usage:
  https://scs.owasp.org/SCWE/SCSVS-COMM/SCWE-035/
- SWC-112 Delegatecall to Untrusted Callee:
  https://swcregistry.io/docs/SWC-112/
