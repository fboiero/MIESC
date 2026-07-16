# SDD: Account Abstraction UserOperation Hardening

Date: 2026-07-12
Owner: Codex lane
Status: implemented checkpoint

## Signal

MIESC has RAG knowledge for ERC-4337 account abstraction, but no
provider-neutral agent contract or SDD dedicated to UserOperation validation.
Existing hardening contracts cover adjacent areas such as signature-domain
replay, CREATE2 deployment, cross-chain message validation, ERC20 compatibility,
and token hooks. ERC-4337 adds a distinct validation surface: smart accounts,
paymasters, factories, aggregators, and EntryPoint integrations must agree on
UserOperation hash scope, nonce scope, prefund accounting, validationData time
bounds, paymaster context, and postOp charging.

## Goal

Add a provider-neutral planning surface:

```text
account_abstraction_userop_hardening
```

Canonical output key:

```text
account_abstraction_userop_hardening_plans
```

Accepted aliases:

```text
erc4337_userop_hardening_plans
erc_4337_useroperation_hardening_plans
useroperation_validation_hardening_plans
paymaster_validation_hardening_plans
```

## Contract

`AccountAbstractionUserOpSurface` records ERC-4337 validation evidence:

- `component`
- `entrypoint_function`
- `entrypoint_guard`
- `userop_fields`
- `signature_scheme`
- `nonce_source`
- `prefund_source`
- `paymaster_context`
- `post_op_path`
- `validation_data_source`
- `evidence`

`AccountAbstractionUserOpRisk` records risk hypotheses:

- `entrypoint_guard`
- `userop_replay`
- `nonce_scope`
- `signature_scope`
- `prefund_accounting`
- `paymaster_drain`
- `postop_revert`
- `validation_data_bounds`
- `aggregator_trust`
- `initcode_factory`

`AccountAbstractionUserOpHardeningPlan` groups surfaces, risks, mitigations,
validation tests, tools, confidence, evidence, and metadata.

## Prompt Requirements

The prompt must:

- refer to an interchangeable security reasoning agent, not a specific model or
  API;
- focus on ERC-4337 UserOperation validation, sponsorship, prefund, postOp,
  nonce, validationData, aggregator, factory, and EntryPoint assumptions;
- require evidence for EntryPoint guard, validation function, UserOperation
  fields, nonce/signature scope, prefund handling, paymaster context, postOp
  behavior, and validationData bounds when present;
- avoid duplicating signature-domain hardening unless the issue is specific to
  ERC-4337 userOpHash or validationData semantics;
- avoid duplicating CREATE2 hardening unless initCode or factory behavior
  affects sender creation through a UserOperation;
- avoid duplicating cross-chain message hardening unless UserOperation replay
  exists across chains due to missing chain, EntryPoint, sender, or nonce scope;
- avoid duplicating ERC20 token compatibility unless paymaster charging or
  sponsorship accounting can be bypassed.

## 50-Activity Parallelization Map

1. Confirm ERC-4337 appears only as RAG knowledge.
2. Confirm no dedicated SDD exists for UserOperation validation.
3. Confirm signature-domain hardening is adjacent but not sufficient.
4. Confirm CREATE2 hardening covers deployment, not UserOperation validation.
5. Confirm cross-chain hardening covers messages, not account abstraction.
6. Claim shared SDD and Codex-owned LLM files.
7. Add capability enum.
8. Add `AccountAbstractionUserOpSurface`.
9. Add `AccountAbstractionUserOpRisk`.
10. Add `AccountAbstractionUserOpHardeningPlan`.
11. Add safe `to_dict` methods.
12. Add agent wrapper.
13. Add account summary input.
14. Add canonical output schema.
15. Add prompt builder.
16. Add parser entry point.
17. Add ERC-4337 alias keys.
18. Add paymaster alias key.
19. Add surface parser.
20. Add risk parser.
21. Add `agentic_contracts.__all__` exports.
22. Add `miesc.llm` imports.
23. Add `miesc.llm.__all__` exports.
24. Add agent capability test.
25. Add provider-neutral wording test.
26. Add no-specific-provider regression.
27. Add no-signature-domain duplication assertion.
28. Add no-CREATE2 duplication assertion.
29. Add no-cross-chain duplication assertion.
30. Add no-ERC20 duplication assertion.
31. Add account summary input assertion.
32. Add EntryPoint guard fixture shape.
33. Add UserOperation fields assertion.
34. Add paymaster surface fixture shape.
35. Add postOp risk fixture shape.
36. Add validationData fixture shape.
37. Add parser alias test.
38. Add confidence clamp test.
39. Add incomplete item rejection test.
40. Add facade smoke test.
41. Add SDD references.
42. Run focused ruff.
43. Run focused py_compile.
44. Run focused pytest.
45. Fix import ordering.
46. Review provider-neutral language.
47. Review boundaries against adjacent capabilities.
48. Stage only claimed files.
49. Commit local checkpoint.
50. Mark LANES claim DONE.

## Non-Goals

- No benchmark uplift claim until evaluated against ground-truth ERC-4337
  fixtures.
- No replacement for signature-domain hardening.
- No replacement for CREATE2 deployment hardening.
- No replacement for cross-chain message hardening.
- No replacement for ERC20 token compatibility hardening.
- No dependency on any specific model, vendor, or API.
- No local heuristic provider in this checkpoint.

## Validation

```bash
ruff check miesc/llm/agentic_contracts.py miesc/llm/__init__.py tests/test_agentic_contracts.py tests/test_miesc_llm_exports.py
python3 -m py_compile miesc/llm/agentic_contracts.py miesc/llm/__init__.py
pytest tests/test_agentic_contracts.py tests/test_miesc_llm_exports.py -q
```

## References

- ERC-4337: Account Abstraction Using Alt Mempool
  https://eips.ethereum.org/EIPS/eip-4337
- OpenZeppelin Account Abstraction documentation
  https://docs.openzeppelin.com/contracts/5.x/account-abstraction
- OpenZeppelin ERC-4337 Account Abstraction Incremental Audit
  https://www.openzeppelin.com/news/erc-4337-account-abstraction-incremental-audit
- Trail of Bits, Six mistakes in ERC-4337 smart accounts
  https://blog.trailofbits.com/2026/03/11/six-mistakes-in-erc-4337-smart-accounts/
- eth-infinitism account-abstraction releases
  https://github.com/eth-infinitism/account-abstraction/releases
