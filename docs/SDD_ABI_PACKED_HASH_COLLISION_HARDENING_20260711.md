# SDD: ABI Packed Hash Collision Hardening

Date: 2026-07-11
Owner: Codex lane
Status: implemented checkpoint

## Signal

MIESC already has provider-neutral contracts for signature-domain replay,
cross-chain message hardening, randomness hardening, CREATE2 deployment risks,
ERC4626 inflation, and other Solidity audit surfaces. The residual gap is
ambiguous packed ABI hashing: `keccak256(abi.encodePacked(...))` over multiple
dynamic or attacker-controlled variable-length arguments can collapse different
logical tuples into identical packed bytes.

This is distinct from the existing signature-domain agent. A signature hash can
have chain/contract/nonce separation and still be ambiguous if it packs multiple
dynamic fields without separators, length prefixes, or typed ABI encoding.

## External Basis

- OWASP SCWE-011 covers insecure ABI encoding/decoding and recommends safer
  encoding discipline.
- OWASP SCWE-074 specifically covers hash collisions with multiple variable
  length arguments.
- The Solidity ABI specification warns that packed mode is ambiguous as soon as
  more than one dynamically-sized element is encoded, and recommends checking
  that at most one argument is dynamic unless ambiguity is intended.
- Public auditor guidance documents concrete collision pairs such as logically
  different string tuples that produce the same packed byte sequence.

## Goal

Add a provider-neutral agent capability that asks an interchangeable security
reasoning provider to identify ABI packed hash collision surfaces and return
structured hardening plans with evidence, mitigations, and validation tests.

Capability:

```text
abi_packed_hash_collision_hardening
```

Canonical output key:

```text
abi_packed_hash_collision_hardening_plans
```

Accepted aliases include:

```text
packed_hash_collision_plans
abi_encode_packed_collision_plans
hash_domain_hardening_plans
packed_encoding_plans
```

## Contract

`AbiPackedHashSurface` records:

- `hash_function`
- `packed_expression`
- `argument_types`
- `dynamic_argument_count`
- `user_controlled_arguments`
- `hash_usage`
- `domain_separator`
- `delimiter_or_length_guard`
- `safer_encoding`
- `evidence`

`AbiPackedHashRisk` records:

- `category`
- `affected_surface_id`
- `severity_hint`
- `description`
- `evidence`
- `recommended_check`

`AbiPackedHashCollisionHardeningPlan` records:

- `objective`
- `surfaces`
- `risks`
- `mitigations`
- `validation_tests`
- `recommended_tools`
- `confidence`
- `evidence`
- `metadata`

## Prompt Requirements

The prompt must:

- refer to an interchangeable security reasoning agent, not a specific model or
  API;
- focus on `abi.encodePacked`, packed byte concatenation, and typed hash inputs;
- require concrete collision reasoning or property tests for shifted dynamic
  boundaries such as `("a", "bc")` versus `("ab", "c")`;
- prefer `abi.encode`, fixed-width typed values, explicit length prefixes, or
  delimiters that cannot occur in the encoded domain;
- ask for source-level evidence, not regex-only conclusions;
- avoid duplicating signature-domain replay work, randomness/commit-reveal
  hardening, and cross-chain message hardening unless packed ambiguity is the
  actual failure mode.

## 50-Activity Parallelization Map

The long loop can be partitioned without overlapping file ownership:

1. Define capability and canonical schema.
2. Add output-key aliases.
3. Add dataclasses.
4. Add safe export methods.
5. Add parser entry point.
6. Add surface parser.
7. Add risk parser.
8. Add prompt.
9. Add agent wrapper.
10. Add public `src.llm` exports.
11. Add `miesc.llm` facade exports.
12. Add task construction test.
13. Add provider-neutral wording test.
14. Add no-specific-provider regression.
15. Add no-duplicate-signature-domain assertion.
16. Add no-duplicate-randomness assertion.
17. Add no-duplicate-cross-chain assertion.
18. Add no-regex-only assertion.
19. Add canonical parser test.
20. Add alias parser test.
21. Add confidence clamp test.
22. Add incomplete-plan rejection test.
23. Add surface field parsing assertions.
24. Add risk field parsing assertions.
25. Add mitigation parsing assertions.
26. Add validation-test parsing assertions.
27. Add direct instance sanitization test.
28. Add text truncation sanitization test.
29. Add label sanitization test.
30. Add evidence sanitization test.
31. Add facade smoke test.
32. Run focused lint.
33. Run focused pytest.
34. Fix import ordering.
35. Fix public export gaps.
36. Review docs for provider-neutral language.
37. Review boundaries against signature-domain agent.
38. Review boundaries against randomness agent.
39. Review boundaries against cross-chain agent.
40. Review boundaries against CREATE2 and ERC4626 claims.
41. Confirm LANES claim.
42. Stage only claimed files.
43. Commit local checkpoint.
44. Mark claim DONE.
45. Run final status check.
46. Check worktree locks.
47. Check no lingering pytest/git processes.
48. Close subagents.
49. Report commit and validation.
50. Queue next local-provider heuristic as a separate claim if needed.

## Non-Goals

- No claim that MIESC benchmark performance improves until evaluated on a
  benchmark containing this bug class.
- No hard dependency on DeepSeek, OpenAI, Anthropic, or any single external API.
- No direct edits to frozen paper, claims matrix, or canonical benchmark output.
- No local heuristic implementation in this checkpoint; the adapter can be
  added as a separate claimed loop.

## Validation

Focused validation for this checkpoint:

```bash
ruff check src/llm/agentic_contracts.py src/llm/__init__.py miesc/llm/__init__.py tests/test_agentic_contracts.py tests/test_miesc_llm_exports.py
pytest tests/test_agentic_contracts.py tests/test_miesc_llm_exports.py -q
```

## Implementation

Implemented in:

- `src/llm/agentic_contracts.py`
- `src/llm/__init__.py`
- `miesc/llm/__init__.py`
- `tests/test_agentic_contracts.py`
- `tests/test_miesc_llm_exports.py`

## References

- OWASP SCWE-011: Insecure ABI Encoding and Decoding
  https://scs.owasp.org/SCWE/SCSVS-CODE/SCWE-011/
- OWASP SCWE-074: Hash Collisions with Multiple Variable Length Arguments
  https://scs.owasp.org/SCWE/SCSVS-CRYPTO/SCWE-074/
- Solidity ABI Specification, non-standard packed mode
  https://docs.soliditylang.org/en/latest/abi-spec.html
- Nethermind: Understanding hash collisions with `abi.encodePacked`
  https://www.nethermind.io/blog/understanding-hash-collisions-abi-encodepacked-in-solidity
