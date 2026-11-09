# SDD: ERC4626 Vault Inflation Hardening Agent Contract

Date: 2026-07-11
Status: implemented in `lane/codex`
Scope: provider-neutral agent contract for ERC4626 and vault share-inflation hardening

## Signal

MIESC already has generic coverage for share-inflation scenarios through sequence oracles, snapshot fuzzing, economic attack simulation, metamorphic relations, DeFi pattern detectors, and PoC generation. The missing piece is a dedicated agent contract that explains and validates the vault share-math surface itself.

This SDD adds a provider-neutral planning surface for ERC4626 and vault inflation review:

- identify `deposit`, `mint`, `withdraw`, `redeem`, `previewDeposit`, `previewMint`, `convertToShares`, `convertToAssets`, `totalAssets`, and `totalSupply` surfaces;
- map how assets and shares are converted, rounded, and initialized in an empty or low-supply vault;
- capture whether `totalAssets()` is raw token balance, internal accounting, strategy accounting, or a mixed source;
- reason about first-depositor donation, zero-share mints, preview/execution mismatch, direct donation exposure, missing virtual shares/assets, missing dead shares, and missing minimum-share checks;
- produce validation tests and hardening guidance without depending on a specific hosted model, API, or local heuristic implementation.

## Why This Matters

ERC4626 vault inflation is now called out directly by OWASP as SCWE-135. The attack class is not just a generic rounding issue: it depends on vault lifecycle, direct donations, low share supply, rounding direction, conversion formulas, and whether preview functions match execution paths.

Generic sequence agents can suggest `donate -> deposit`; economic agents can estimate profit; snapshot agents can suggest state frontiers. This contract fills the missing audit interface: it describes the share accounting surface and the hardening checks that any interchangeable agent or local provider must return.

## Agent Capability

Capability:

```text
erc4626_vault_inflation_hardening
```

Primary output key:

```text
erc4626_vault_inflation_hardening_plans
```

Accepted aliases:

```text
vault_inflation_hardening_plans
share_inflation_hardening_plans
donation_attack_hardening_plans
vault_share_math_plans
```

Aliases are intentionally provider-neutral. They let a hosted model, replacement model, local analyzer, or deterministic heuristic adapter produce equivalent plans without coupling the framework to a vendor.

## Contract Shape

`VaultShareSurface`

- `id`
- `vault_function`
- `asset_function`
- `share_function`
- `total_assets_source`
- `total_supply_source`
- `conversion_formula`
- `rounding_direction`
- `empty_vault_behavior`
- `donation_exposure`
- `mitigation`
- `evidence`

`VaultInflationRisk`

- `id`
- `category`
- `affected_surface_id`
- `severity_hint`
- `description`
- `evidence`
- `recommended_check`

`ERC4626VaultInflationHardeningPlan`

- `id`
- `objective`
- `surfaces`
- `risks`
- `mitigations`
- `validation_tests`
- `recommended_tools`
- `confidence`
- `evidence`
- `metadata`

## Prompt Constraints

The agent prompt must:

- stay provider-neutral and avoid model/API-specific assumptions;
- return validation guidance, not unmeasured confirmed vulnerability claims;
- avoid duplicating sequence-oracle, snapshot-fuzzing, or economic-simulation agents;
- avoid regex-only conclusions and cite semantic evidence from formulas, preview functions, `totalAssets`, `totalSupply`, and guards;
- require a first-depositor, donation, low-supply, preview mismatch, or zero-share validation path before treating risk as plausible;
- keep virtual shares/assets, dead shares, minimum shares, internal accounting, rounding direction, and direct donation assumptions explicit.

## 50-Activity Parallel Plan

Agent contract lane:

1. Define `AgentCapability.ERC4626_VAULT_INFLATION_HARDENING`.
2. Add `VaultShareSurface`.
3. Add `VaultInflationRisk`.
4. Add `ERC4626VaultInflationHardeningPlan`.
5. Add `ERC4626VaultInflationHardeningAgent`.
6. Add canonical output schema.
7. Add `vault_summary` input.
8. Add provider-neutral prompt.
9. Add parser aliases.
10. Add public `__all__`.

Public API lane:

11. Export via `src.llm`.
12. Export via `miesc.llm`.
13. Preserve fallback-to-`None` degradation.
14. Add public facade smoke test.
15. Verify no vendor-specific names appear in prompt.

Parser/test lane:

16. Test canonical key.
17. Test `share_inflation_hardening_plans` alias.
18. Test `donation_attack_hardening_plans` alias.
19. Test confidence upper bound.
20. Test confidence lower bound.
21. Test incomplete item rejection.
22. Test mitigation-only plan acceptance.
23. Test surface parsing.
24. Test risk parsing.
25. Test direct instance sanitization.

Research lane:

26. Compare OWASP SCWE-135 framing.
27. Compare ERC-4626 standard surface names.
28. Compare OpenZeppelin virtual offset mitigation.
29. Confirm direct donation and low-supply rounding assumptions.
30. Capture residual benchmark claim limits.

Future local-provider lane:

31. Claim `src/llm/reasoning_provider_adapter.py` separately.
32. Add dispatch for the new capability.
33. Detect ERC4626 inheritance/imports.
34. Detect `totalAssets` raw `balanceOf`.
35. Detect `convertToShares` formulas.
36. Detect `previewDeposit` formulas.
37. Detect low-supply `totalSupply == 0` behavior.
38. Detect missing minimum-share guard.
39. Detect virtual share/asset offsets.
40. Detect dead share seeding.
41. Detect internal-accounting mitigation.
42. Emit protected-plan lower severity.
43. Emit empty output when no vault signals exist.
44. Test vulnerable vault heuristic.
45. Test protected vault heuristic.

Benchmark/proof lane:

46. Add non-canonical fixture for vulnerable ERC4626-like vault.
47. Add non-canonical fixture for virtual-offset protected vault.
48. Run focused Python tests.
49. Run bounded non-canonical benchmark probe only after adapter work.
50. Record measured uplift only after benchmark evidence exists.

## Implemented In This Checkpoint

- Added provider-neutral agent contract and parser.
- Added public exports through both LLM facades.
- Added focused tests for prompt neutrality, parser aliases, incomplete item rejection, sanitization, and facade usability.
- Left local heuristic adapter support as a separate claim because adapter work is a distinct file scope.

## Non-Goals

- No frozen paper, claims matrix, or canonical benchmark artifact changes.
- No benchmark uplift claim without measured evidence.
- No dependency on a specific hosted model or API.
- No duplicate sequence, snapshot, or economic attack implementation.
- No replacement of existing DeFi detectors.

## Validation

Focused validation for this checkpoint:

```bash
ruff check --fix src/llm/agentic_contracts.py src/llm/__init__.py miesc/llm/__init__.py tests/test_agentic_contracts.py tests/test_miesc_llm_exports.py
pytest tests/test_agentic_contracts.py tests/test_miesc_llm_exports.py -q
```

## References

- OWASP SCWE-135: ERC4626 Share Inflation via Donations.
- EIP-4626: Tokenized Vault Standard.
- OpenZeppelin ERC4626 documentation and inflation mitigation guidance.
- OpenZeppelin notes on virtual shares/assets as an inflation defense.
