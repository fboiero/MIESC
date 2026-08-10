# SDD: External Call Returndata Hardening

Date: 2026-07-12
Owner: Codex lane
Status: implemented checkpoint

## Signal

MIESC already detects unchecked low-level calls and reentrancy-oriented external
call effects. Those checks are useful, but they do not model a separate
returndata surface: a low-level `call` or `staticcall` can return untrusted
bytes that are oversized, malformed, decoded without a shape check, bubbled as
revert data, or treated as authentic error information.

This gap is distinct from:

- token hook reentrancy, which focuses on ERC777/ERC1363/ERC1820 callbacks;
- ERC20 compatibility, which focuses on token transfer semantics and optional
  returns;
- delegatecall storage aliasing, which focuses on caller/callee storage
  corruption;
- ABI packed hash collision, which focuses on `abi.encodePacked` ambiguity;
- generic unchecked-call triage, which focuses on the boolean success value.

## Goal

Add a provider-neutral planning surface:

```text
external_call_returndata_hardening
```

Canonical output key:

```text
external_call_returndata_hardening_plans
```

Accepted aliases:

```text
low_level_call_returndata_hardening_plans
returndata_griefing_hardening_plans
returndata_decode_hardening_plans
external_call_return_value_hardening_plans
```

## Contract

`ExternalCallReturndataSurface` records low-level call evidence:

- `entrypoint`
- `target_source`
- `call_kind`
- `calldata_source`
- `returndata_source`
- `decode_site`
- `returndata_size_bound`
- `success_guard`
- `trust_boundary`
- `value_forwarding`
- `evidence`

`ExternalCallReturndataRisk` records risk hypotheses:

- `unbounded_returndata_copy`
- `unsafe_abi_decode`
- `malformed_returndata_dos`
- `revert_data_bubbling_dos`
- `untrusted_staticcall_decode`
- `unchecked_success`
- `returndata_ignored`
- `success_without_code_check`

`ExternalCallReturndataHardeningPlan` groups surfaces, risks, mitigations,
validation tests, tools, confidence, evidence, and metadata.

## Prompt Requirements

The prompt must:

- refer to an interchangeable security reasoning agent, not a specific model or
  API;
- focus on untrusted returned bytes from `call` and `staticcall`;
- require evidence for call kind, target trust boundary, success guard,
  returndata source, decode or bubbling path, size bound, and downstream state or
  assumptions affected by malformed returndata;
- avoid duplicating delegatecall storage-aliasing hardening;
- avoid duplicating token hook reentrancy hardening;
- avoid duplicating ERC20 token compatibility hardening;
- avoid reducing the issue to generic unchecked-call triage;
- avoid duplicating ABI packed hash collision hardening.

## 50-Activity Parallelization Map

1. Confirm unchecked-call detectors exist.
2. Confirm reentrancy detectors exist.
3. Confirm no dedicated returndata SDD exists.
4. Confirm no returndata capability exists in `AgentCapability`.
5. Confirm token hook hardening excludes generic returndata.
6. Confirm ERC20 hardening excludes generic unchecked-return triage.
7. Confirm delegatecall hardening focuses on storage aliasing.
8. Confirm ABI packed hardening focuses on encode ambiguity.
9. Claim shared SDD and Codex-owned LLM files.
10. Add capability enum.
11. Add `ExternalCallReturndataSurface`.
12. Add `ExternalCallReturndataRisk`.
13. Add `ExternalCallReturndataHardeningPlan`.
14. Add safe `to_dict` methods.
15. Add agent wrapper.
16. Add call summary input.
17. Add canonical output schema.
18. Add prompt builder.
19. Add parser entry point.
20. Add `low_level_call_returndata` alias.
21. Add `returndata_griefing` alias.
22. Add `returndata_decode` alias.
23. Add `external_call_return_value` alias.
24. Add surface parser.
25. Add risk parser.
26. Add `agentic_contracts.__all__` exports.
27. Add `miesc.llm` imports.
28. Add `miesc.llm.__all__` exports.
29. Add provider-neutral agent test.
30. Add no-specific-provider regression.
31. Add no-delegatecall duplication assertion.
32. Add no-token-hook duplication assertion.
33. Add no-ERC20 duplication assertion.
34. Add no-generic-unchecked-call assertion.
35. Add call summary input assertion.
36. Add malformed returndata fixture shape.
37. Add unbounded returndata fixture shape.
38. Add unsafe `abi.decode` fixture shape.
39. Add parser alias test.
40. Add confidence clamp test.
41. Add incomplete item rejection test.
42. Add direct instance sanitization test.
43. Add facade smoke test.
44. Add SDD references.
45. Run focused ruff.
46. Run focused py_compile.
47. Run focused pytest.
48. Stage only claimed files.
49. Commit local checkpoint.
50. Mark LANES claim DONE.

## Non-Goals

- No benchmark uplift claim until evaluated against ground-truth fixtures.
- No local heuristic provider in this checkpoint.
- No broad generic reentrancy/effects capability.
- No replacement for unchecked-call detectors.
- No dependency on any specific model, vendor, or API.

## Validation

```bash
ruff check miesc/llm/agentic_contracts.py miesc/llm/__init__.py tests/test_agentic_contracts.py tests/test_miesc_llm_exports.py
python3 -m py_compile miesc/llm/agentic_contracts.py miesc/llm/__init__.py
pytest tests/test_agentic_contracts.py tests/test_miesc_llm_exports.py -q
```

## References

- Solidity ABI specification, errors and error-data trust boundary
  https://docs.soliditylang.org/en/latest/abi-spec.html
- OWASP SCWE-011: Insecure ABI Encoding and Decoding
  https://scs.owasp.org/SCWE/SCSVS-CODE/SCWE-011/
- OWASP SCWE-048: Unchecked Call Return Value
  https://scs.owasp.org/SCWE/SCSVS-CODE/SCWE-048/
- Solidity issue 12306: external calls and RETURNDATACOPY behavior
  https://github.com/ethereum/solidity/issues/12306
- Unbounded Return Data
  https://kadenzipfel.github.io/smart-contract-vulnerabilities/vulnerabilities/unbounded-return-data.html
