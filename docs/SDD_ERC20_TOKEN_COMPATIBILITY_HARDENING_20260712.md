# SDD: ERC20 Token Compatibility Accounting Hardening

Date: 2026-07-12
Owner: Codex lane
Status: implemented checkpoint

## Signal

MIESC already has provider-neutral hardening contracts for ERC4626 vault
inflation and token hook reentrancy. The remaining ERC20 integration gap is
more general: many protocols credit accounting from the requested transfer
amount while the token's actual balance delta is lower, higher, delayed, or
otherwise non-standard.

This applies to fee-on-transfer or deflationary tokens, rebasing tokens,
missing-return tokens, blacklist/pause behavior, zero-value transfer reverts,
and allowance quirks. SafeERC20 helps with return-value compatibility, but does
not by itself prove that protocol accounting uses the actual amount received.

## Goal

Add a provider-neutral planning surface:

```text
erc20_token_compatibility_hardening
```

Canonical output key:

```text
erc20_token_compatibility_hardening_plans
```

Accepted aliases:

```text
erc20_compatibility_accounting_hardening_plans
token_accounting_hardening_plans
fee_on_transfer_accounting_plans
rebasing_token_accounting_plans
actual_received_hardening_plans
safe_erc20_compatibility_plans
```

## Contract

`ERC20TokenFlowSurface` records token integration evidence:

- `entrypoint`
- `token_call`
- `requested_amount_source`
- `balance_before_source`
- `balance_after_source`
- `credited_amount_source`
- `token_traits`
- `accounting_fields`
- `guard`
- `evidence`

`ERC20TokenCompatibilityRisk` records risk hypotheses:

- `fee_on_transfer_misaccounting`
- `rebasing_balance_drift`
- `nonstandard_return`
- `zero_transfer_revert`
- `blacklist_pause_incompatibility`
- `allowance_race`

`ERC20TokenCompatibilityHardeningPlan` groups surfaces, risks, mitigations,
validation tests, tools, confidence, evidence, and metadata.

## Prompt Requirements

The prompt must:

- refer to an interchangeable security reasoning agent, not a specific model or
  API;
- focus on requested-vs-actual token movement and accounting;
- require evidence for token call, requested amount, credited amount,
  balance-before/after availability, and accounting fields;
- avoid duplicating ERC4626 vault inflation hardening unless the issue is
  actual-received ERC20 accounting;
- avoid duplicating token hook reentrancy hardening unless callback behavior
  also creates requested-vs-actual drift;
- avoid reducing the problem to generic unchecked return-value triage;
- prefer SafeERC20, balance-delta crediting, internal accounting for rebasing,
  explicit token allowlists, and tests with fee-on-transfer, rebasing, and
  missing-return mock tokens.

## 50-Activity Parallelization Map

1. Confirm ERC4626 hardening is not general ERC20 compatibility.
2. Confirm token hook hardening excludes transfer-fee/non-standard ERC20.
3. Confirm RAG/remediation has SafeERC20 knowledge but no agent contract.
4. Claim shared SDD and Codex-owned LLM files.
5. Add capability enum.
6. Add `ERC20TokenFlowSurface`.
7. Add `ERC20TokenCompatibilityRisk`.
8. Add `ERC20TokenCompatibilityHardeningPlan`.
9. Add safe export methods.
10. Add agent wrapper.
11. Add token summary input.
12. Add canonical output schema.
13. Add prompt builder.
14. Add parser entry point.
15. Add alias keys.
16. Add surface parser.
17. Add risk parser.
18. Add `miesc.llm` exports.
19. Add `agentic_contracts.__all__` exports.
20. Add agent capability test.
21. Add provider-neutral wording test.
22. Add no-specific-provider regression.
23. Add no-ERC4626 duplication assertion.
24. Add no-token-hook duplication assertion.
25. Add no-generic-unchecked-return assertion.
26. Add token summary input assertion.
27. Add parser alias test.
28. Add confidence clamp test.
29. Add incomplete item rejection test.
30. Add facade smoke test.
31. Add fee-on-transfer fixture shape.
32. Add rebasing fixture shape.
33. Add missing-return fixture shape.
34. Add balance-delta field assertions.
35. Add accounting field assertions.
36. Add validation test assertions.
37. Add SDD references.
38. Run focused ruff.
39. Run focused py_compile.
40. Run focused pytest.
41. Fix export ordering.
42. Fix parser gaps.
43. Review provider-neutral language.
44. Review boundary against ERC4626.
45. Review boundary against token hooks.
46. Stage only claimed files.
47. Commit local checkpoint.
48. Mark LANES claim DONE.
49. Run final sanity checks.
50. Queue local heuristic provider as a separate claimed loop if needed.

## Non-Goals

- No benchmark uplift claim until evaluated against ground-truth fixtures.
- No replacement for ERC4626 share inflation hardening.
- No replacement for token hook reentrancy hardening.
- No dependency on DeepSeek, OpenAI, Anthropic, or any specific API.
- No local heuristic provider in this checkpoint.

## Validation

```bash
ruff check miesc/llm/agentic_contracts.py miesc/llm/__init__.py tests/test_agentic_contracts.py tests/test_miesc_llm_exports.py
pytest tests/test_agentic_contracts.py tests/test_miesc_llm_exports.py -q
```

## References

- OWASP SCWE-110: Fee-On-Transfer Token Misaccounting
  https://scs.owasp.org/SCWE/SCSVS-COMP/SCWE-110/
- OWASP Component-Specific Security overview
  https://scs.owasp.org/SCSTG/tests/SCSVS-COMP/overview/
- OpenZeppelin ERC20 documentation
  https://docs.openzeppelin.com/contracts/5.x/api/token/ERC20
- OpenZeppelin SafeERC20 source
  https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/utils/SafeERC20.sol
- OpenZeppelin Zaiffer token audit, fee-on-transfer accounting issue
  https://www.openzeppelin.com/news/zaiffer-token-audit
