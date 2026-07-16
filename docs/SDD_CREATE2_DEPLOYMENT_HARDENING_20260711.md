# SDD: CREATE2 Deployment Hardening Agent Contract

Date: 2026-07-11
Status: implemented in `lane/codex`
Scope: provider-neutral agent contract for CREATE2 and deterministic deployment hardening

## Signal

MIESC already covers metamorphic relations, upgrade evolution, delegatecall storage aliasing, transaction ordering, selfdestruct, and classic access-control risks. The missing surface is deterministic deployment lifecycle hardening: factories that use `CREATE2`, `new Contract{salt: ...}`, precomputed addresses, counterfactual funding, or address trust before code exists.

This SDD adds an agent contract for CREATE2 deployment hardening:

- map factory deploy functions, salt derivation, init-code construction, and predicted-address helpers;
- check whether salt is bound to owner, sender, chain, tenant, or business domain;
- check whether init-code hash and post-deploy runtime codehash are verified;
- reason about salt squatting, front-run deployment, counterfactual funding, address poisoning, factory authorization gaps, cross-chain salt reuse, and metamorphic/redeploy assumptions;
- return validation tests and mitigations through a replaceable provider interface.

## Why This Matters

CREATE2 makes contract addresses predictable before deployment. That enables legitimate account-abstraction and factory flows, but it also creates attack surfaces around salt reuse, pre-funded addresses, deployment front-running, init-code mismatch, and trusting code at an address before it is deployed or verified.

OWASP SCWE-051 tracks improper CREATE2 use as a smart contract weakness. Public incident research and wallet-abuse reports have also highlighted deterministic-address abuse and address poisoning. MIESC has related generic components, but none of them emit a CREATE2-specific plan with salt, factory, init-code hash, and codehash checks.

## Agent Capability

Capability:

```text
create2_deployment_hardening
```

Primary output key:

```text
create2_deployment_hardening_plans
```

Accepted aliases:

```text
deterministic_deployment_hardening_plans
create2_salt_hardening_plans
salt_squatting_hardening_plans
factory_deployment_plans
```

These aliases keep the contract stable across hosted models, replacement agents, and local heuristic providers.

## Contract Shape

`Create2DeploymentSurface`

- `id`
- `deploy_function`
- `factory_contract`
- `salt_source`
- `init_code_source`
- `address_formula`
- `authorization_guard`
- `collision_check`
- `post_deploy_check`
- `redeploy_assumption`
- `evidence`

`Create2DeploymentRisk`

- `id`
- `category`
- `affected_surface_id`
- `severity_hint`
- `description`
- `evidence`
- `recommended_check`

`Create2DeploymentHardeningPlan`

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

The prompt must:

- stay provider-neutral and avoid model/API-specific assumptions;
- return validation guidance, not unmeasured confirmed vulnerabilities;
- avoid duplicating metamorphic differential testing, upgrade analysis, or delegatecall aliasing;
- avoid regex-only conclusions and cite semantic evidence from salt derivation, init-code construction, predicted-address use, factory authorization, or post-deploy checks;
- require a front-run deployment, salt-squatting, address-poisoning, init-code mismatch, or codehash validation path before treating a risk as plausible;
- keep factory address, deployer, salt, chain id, owner, init-code hash, collision checks, codehash checks, and counterfactual funding assumptions explicit.

## 50-Activity Parallel Plan

Agent contract lane:

1. Define `AgentCapability.CREATE2_DEPLOYMENT_HARDENING`.
2. Add `Create2DeploymentSurface`.
3. Add `Create2DeploymentRisk`.
4. Add `Create2DeploymentHardeningPlan`.
5. Add `Create2DeploymentHardeningAgent`.
6. Add canonical schema.
7. Add sanitized `deployment_summary` input.
8. Add provider-neutral prompt.
9. Add parser aliases.
10. Add module exports.

Public API lane:

11. Export via `src.llm`.
12. Export via `miesc.llm`.
13. Preserve degraded import fallbacks.
14. Add facade parser smoke test.
15. Verify vendor-neutral prompt text.

Parser/test lane:

16. Test canonical key.
17. Test deterministic deployment alias.
18. Test salt hardening alias.
19. Test factory deployment alias.
20. Test confidence upper bound.
21. Test confidence lower bound.
22. Test incomplete item rejection.
23. Test validation-only plan acceptance.
24. Test deployment surface parsing.
25. Test deployment risk parsing.
26. Test direct instance sanitization.

Research lane:

27. Compare OWASP SCWE-051 framing.
28. Compare EIP-1014 address formula.
29. Compare public CREATE2 wallet-abuse research.
30. Compare metamorphic contract notes without duplicating the metamorphic agent.
31. Capture benchmark claim limits.

Future local-provider lane:

32. Claim `src/llm/reasoning_provider_adapter.py` separately.
33. Add dispatch for the capability.
34. Detect `create2(...)` inline assembly.
35. Detect `new Contract{salt: salt}`.
36. Detect predicted-address helpers.
37. Detect public user salts.
38. Detect owner/sender-bound salts.
39. Detect chain/domain-bound salts.
40. Detect init-code hash construction.
41. Detect missing collision checks.
42. Detect missing post-deploy codehash checks.
43. Detect counterfactual funding assumptions.
44. Detect CREATE2 plus selfdestruct/redeploy coupling.
45. Return empty output without CREATE2 signals.

Benchmark/proof lane:

46. Add non-canonical vulnerable factory fixture.
47. Add non-canonical protected factory fixture.
48. Run focused Python tests.
49. Run bounded non-canonical benchmark probe after adapter support.
50. Record measured uplift only after benchmark evidence exists.

## Implemented In This Checkpoint

- Added provider-neutral CREATE2 agent contract and parser.
- Added public exports through both LLM facades.
- Added focused tests for prompt neutrality, aliases, incomplete item rejection, sanitization, and facade usability.
- Left local heuristic provider support as a separate claim because `reasoning_provider_adapter.py` is currently owned by another active claim.

## Non-Goals

- No frozen paper, claims matrix, or canonical benchmark artifact changes.
- No benchmark uplift claim without measured evidence.
- No dependency on a specific hosted model or API.
- No duplicate metamorphic, upgrade, delegatecall, or transaction-ordering implementation.
- No replacement of classic selfdestruct or access-control detectors.

## Validation

Focused validation for this checkpoint:

```bash
ruff check --fix src/llm/agentic_contracts.py src/llm/__init__.py miesc/llm/__init__.py tests/test_agentic_contracts.py tests/test_miesc_llm_exports.py
pytest tests/test_agentic_contracts.py tests/test_miesc_llm_exports.py -q
```

## References

- OWASP SCWE-051: Improper Use of CREATE2 for Contract Deployment.
- EIP-1014: Skinny CREATE2.
- Check Point research: Ethereum's CREATE2 as a wallet security bypass vector.
- a16z metamorphic contract detector notes for redeploy/metamorphic context.
