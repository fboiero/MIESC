# SDD: Financial Math Precision Hardening

Date: 2026-07-12
Lane: codex
Status: implemented as provider-neutral agent contract

## Signal

Recent Solidity guidance keeps treating arithmetic precision as a live DeFi
failure mode, not only as legacy overflow/underflow. OWASP SC07:2026 covers
arithmetic errors including rounding and precision, and SCSTG-TEST-0016 calls
for arithmetic and logic security tests. Public postmortems and advisories also
continue to highlight division-before-multiplication, fixed-point scale drift,
rounding-to-zero, and incorrect rounding direction in financial formulas.

MIESC already has useful partial coverage:

- `miesc/ml/defi_patterns.py` detects classic precision-loss patterns such as
  division before multiplication.
- `oracle_feed_hardening` covers oracle decimals and normalization when the
  feed itself is the trust boundary.
- `erc4626_vault_inflation_hardening` covers share math inside ERC4626 vault
  lifecycle, first-depositor, donation, preview, and empty-vault flows.
- `benign_context_verifier` already keeps division/rounding warnings alive
  because Solidity 0.8 overflow checks do not prevent precision loss.

The missing product surface is an agentic, provider-replaceable contract that
turns broad formula evidence into validation plans for financial math precision
risks across reward distribution, interest accrual, fee math, AMMs, share
accounting, liquidation math, and fixed-point conversion.

## Goal

Add `financial_math_precision_hardening` as a stable capability for
interchangeable reasoning agents. The capability must produce bounded JSON
plans under the canonical key:

`financial_math_precision_hardening_plans`

Accepted aliases:

- `precision_loss_hardening_plans`
- `rounding_error_hardening_plans`
- `fixed_point_math_hardening_plans`
- `defi_math_precision_hardening_plans`
- `division_before_multiplication_hardening_plans`

## Contract

Each plan contains:

- `id`, `objective`
- `surfaces`: formula entrypoints with expression, value flow, unit sources,
  scale factor, rounding direction, operation order, helper/library, unchecked
  context, state fields, and evidence
- `risks`: category, affected surface, severity hint, description, evidence,
  and recommended check
- `mitigations`
- `validation_tests`
- `recommended_tools`
- `confidence`
- `evidence`
- `metadata`

Risk categories:

- `division_before_multiplication`
- `rounding_to_zero`
- `scale_mismatch`
- `basis_point_denominator`
- `muldiv_precision`
- `unchecked_financial_arithmetic`
- `rounding_direction_bias`
- `accumulator_drift`
- `unit_conversion_loss`
- `overflow_in_intermediate`

## Prompt Requirements

The prompt must:

- Address an interchangeable security reasoning agent.
- Avoid any dependency on a specific model, vendor, or external API.
- Ask for financial math precision hardening plans, not confirmed bugs.
- Require evidence for formula, operation order, scale factor, units, rounding
  direction, affected state fields, and unchecked context when present.
- Prefer full-precision `mulDiv`, explicit rounding direction, consistent
  units/decimals, safe multiply-before-divide ordering, and boundary tests with
  small, large, and adversarial values.
- State that Solidity 0.8 overflow checks do not prevent precision/rounding
  loss.

## Non-Goals

- Do not claim benchmark uplift from this checkpoint. It adds a contract and
  tests; measured arena improvement requires a separate benchmark run.
- Do not add a local heuristic provider while `reasoning_provider_adapter.py`
  is under an active separate claim.
- Do not replace ERC4626 vault inflation hardening. Vault-specific donation,
  first-depositor, preview, and lifecycle issues stay there.
- Do not replace oracle feed hardening. Feed freshness, source trust, stale
  reads, and sequencer guards stay there.
- Do not replace ERC20 compatibility hardening. Requested-vs-actual token
  movement and fee-on-transfer/rebasing behavior stay there.
- Do not reduce the capability to Solidity pre-0.8 overflow/underflow triage.

## 50-Activity Parallelization Map

1. Enumerate formulas from Solidity AST and source text.
2. Identify division-before-multiplication expressions.
3. Identify fixed-point scale factors such as `1e18`, wad, ray, and bps.
4. Extract numerator and denominator sources.
5. Extract token, share, debt, price, and reward unit sources.
6. Detect implicit decimal assumptions.
7. Detect explicit oracle decimals normalization inside formulas.
8. Separate feed trust issues from formula scale issues.
9. Detect basis-point denominators and percent/rate constants.
10. Detect missing denominator guards.
11. Detect rounding-to-zero paths for small user values.
12. Detect rounding direction bias against users.
13. Detect rounding direction bias against protocol solvency.
14. Detect accumulator update formulas.
15. Detect reward-per-share and debt-index formulas.
16. Detect interest accrual formulas.
17. Detect AMM invariant and quote formulas.
18. Detect liquidation threshold and health-factor formulas.
19. Detect fee skimming and protocol-fee formulas.
20. Detect share price formulas outside ERC4626 lifecycle.
21. Detect unchecked arithmetic around financial formulas.
22. Detect casts that truncate financial values.
23. Detect intermediate overflow risks before final division.
24. Detect opportunities for full-precision `mulDiv`.
25. Detect unsafe custom fixed-point helpers.
26. Detect library requirements already present.
27. Extract affected state fields.
28. Extract user-controlled operands.
29. Extract governance-controlled constants.
30. Extract external input operands.
31. Build formula-surface evidence snippets.
32. Classify each risk category.
33. Generate mitigation candidates.
34. Generate Foundry unit boundary tests.
35. Generate Foundry invariant test ideas.
36. Generate fuzz seeds for small denominators.
37. Generate fuzz seeds for tiny numerators.
38. Generate fuzz seeds for large operands.
39. Generate tests for decimal mismatch.
40. Generate tests for bps denominator mismatch.
41. Generate tests for accumulator monotonicity.
42. Generate tests for value conservation.
43. Generate tests for no rounding-to-zero theft.
44. Generate tests for explicit rounding direction.
45. Rank risks by value flow and state impact.
46. Compare with existing static detector findings.
47. Suppress duplicates already owned by ERC4626.
48. Suppress duplicates already owned by oracle feed hardening.
49. Suppress duplicates already owned by ERC20 compatibility.
50. Emit provider-neutral JSON plans for downstream validation.

These activities can run in parallel as read-only explorers over the same source
snapshot, then merge into a bounded plan list.

## Validation

Focused validation for this checkpoint:

```bash
ruff check --fix miesc/llm/agentic_contracts.py miesc/llm/__init__.py tests/test_agentic_contracts.py tests/test_miesc_llm_exports.py
python3 -m py_compile miesc/llm/agentic_contracts.py miesc/llm/__init__.py
pytest tests/test_agentic_contracts.py tests/test_miesc_llm_exports.py -q
git diff --check -- docs/SDD_FINANCIAL_MATH_PRECISION_HARDENING_20260712.md miesc/llm/agentic_contracts.py miesc/llm/__init__.py tests/test_agentic_contracts.py tests/test_miesc_llm_exports.py
```

## References

- OWASP Smart Contract Top 10 SC07:2026 Arithmetic Errors:
  https://scs.owasp.org/sctop10/SC07-ArithmeticErrors/
- OWASP SCSTG-TEST-0016 Testing Arithmetic and Logic Security:
  https://scs.owasp.org/SCSTG/tests/SCSVS-ORACLE/SCSTG-TEST-0016/
- SolidityScan: Precision Loss in Arithmetic Operations:
  https://blog.solidityscan.com/precision-loss-in-arithmetic-operations-8729aea20be9/
- SolidityScan: zkLend Hack Analysis:
  https://blog.solidityscan.com/zklend-hack-analysis-e494cb794f71/
- Guardian Audits: Division Precision Loss:
  https://lab.guardianaudits.com/encyclopedia-of-common-solidity-bugs/division-precision-loss
- Certora: Problems in Solidity Fixed Point Libraries:
  https://www.certora.com/blog/problems-in-solidity-fixed-point-libraries
