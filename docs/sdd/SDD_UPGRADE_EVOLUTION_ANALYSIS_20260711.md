# SDD: Upgrade Evolution Analysis

Date: 2026-07-11
Owner lane: Codex
Status: proposed, first provider-neutral plan contract implemented

## 1. Signal

MIESC already covers invariant extraction, sequence oracles, semantic graph
gating, snapshot/dataflow fuzzing, economic simulation, and metamorphic or
differential relations. A remaining Solidity risk class is upgrade-induced
failure in proxy-based systems: the bug may not exist in either implementation
alone, but appears when a proxy migrates state from one implementation to
another.

The technique here is evolution-aware upgrade analysis: compare old
implementation, new implementation, and optional proxy code to identify
storage-layout drift, unsafe initializer changes, admin-path changes, selector
collisions, delegatecall-context assumptions, and missing migration checks.

Relevant external signals:

- USCSA proposes AST difference analysis plus assisted reasoning for
  proxy-based upgradeable smart contracts and reports high precision/recall on
  upgrade-induced vulnerabilities.
- OWASP Smart Contract Top 10 2026 includes proxy and upgradeability
  vulnerabilities, calling out initialization, admin controls, delegatecall,
  and storage layout.
- Smart Contract Security Field Guide highlights transparent, UUPS, beacon
  proxies, centralization, and struct storage collision risks.
- Prior proxy research documents storage layout clashes, selector collisions,
  and insufficient compatibility checks in upgradeable smart contracts.

## 2. Spec

Add `upgrade_evolution_analysis` as a provider-neutral plan type.

Inputs:

- Old implementation Solidity source.
- New implementation Solidity source.
- Optional proxy Solidity source.
- Existing findings.
- Optional storage layout before and after.
- Local-first policy constraints.

Output:

```json
{
  "upgrade_evolution_plans": [
    {
      "id": "owner_slot_collision",
      "objective": "Validate whether V2 corrupts proxy owner storage",
      "proxy_pattern": "transparent",
      "old_implementation": "VaultV1",
      "new_implementation": "VaultV2",
      "storage_changes": [
        {
          "slot": "0",
          "before": "address owner",
          "after": "bool openForSale",
          "change_type": "type_change",
          "risk": "owner slot may be overwritten during upgrade",
          "evidence": ["slot 0 type changed across implementations"]
        }
      ],
      "risks": [
        {
          "id": "unprotected_reinitializer",
          "category": "initializer",
          "affected_component": "initializeV2",
          "severity_hint": "high",
          "description": "initializeV2 lacks an initializer guard",
          "evidence": ["public initializeV2 writes owner"],
          "recommended_check": "replay upgrade and assert owner unchanged"
        }
      ],
      "migration_checks": ["dry-run upgrade preserves owner and totalAssets"],
      "recommended_tools": ["openzeppelin-upgrades", "slither", "foundry"],
      "confidence": 0.86,
      "evidence": ["storage layout diff and initializer diff"]
    }
  ]
}
```

Parser aliases:

- `upgrade_evolution_plans`
- `upgrade_analysis_plans`
- `proxy_upgrade_plans`

Non-goals:

- Confirming exploitability without migration replay or counterexample evidence.
- Replacing semantic graph gates, sequence oracles, or metamorphic tests.
- Building a full AST/storage extractor in this checkpoint.
- Binding to a specific model, API, hosted provider, or local tool.
- Editing frozen paper artifacts or canonical benchmark outputs.

## 3. Design

Implemented first checkpoint:

1. Add `AgentCapability.UPGRADE_EVOLUTION_ANALYSIS`.
2. Add `StorageLayoutChange`.
3. Add `UpgradeRisk`.
4. Add `UpgradeEvolutionPlan`.
5. Add `UpgradeEvolutionAnalysisAgent`.
6. Add `parse_upgrade_evolution_plans()`.
7. Export the contract through `src.llm` and `miesc.llm`.

The plan is a transition-risk artifact. It should feed OpenZeppelin upgrade
checks, Slither, Foundry migration dry-runs, or a future local AST/storage
adapter, but it does not become a vulnerability finding by itself.

False-positive controls:

- Plans require an objective.
- Plans require at least one storage change, upgrade risk, or migration check.
- Risks require an id, category, and description.
- Storage changes require a slot and some evidence-bearing content.
- Confidence, evidence, tools, text, and metadata are bounded.
- Prompt text prohibits provider/model/API binding.

## 4. Validation

Focused validation:

```bash
pytest tests/test_agentic_contracts.py tests/test_miesc_llm_exports.py -q
ruff check src/llm/agentic_contracts.py src/llm/__init__.py miesc/llm/__init__.py tests/test_agentic_contracts.py tests/test_miesc_llm_exports.py
```

Required assertions:

- capability is provider-neutral;
- prompts avoid vendor/model binding;
- parser aliases are accepted;
- incomplete upgrade plans are rejected;
- hostile fields are sanitized;
- public `miesc.llm` facade exports remain stable.

## 5. Integration Plan

The next 50 activities should remain additive and non-canonical until Fernando
approves a benchmark or paper baseline update.

Discovery and schema:

1. Inventory proxy patterns in fixtures and examples.
2. Inventory UUPS upgrade functions and authorization checks.
3. Inventory transparent proxy admin paths.
4. Inventory beacon proxy references.
5. Inventory initializer and reinitializer functions.
6. Inventory storage gap declarations.
7. Inventory storage layout JSON availability.
8. Inventory compiler artifacts that expose layout.
9. Define upgrade risk category taxonomy.
10. Define proxy pattern taxonomy.

Contract and local heuristics:

11. Add upgrade evolution plan contracts.
12. Add parser and sanitization tests.
13. Add public exports.
14. Add local heuristic for slot type changes.
15. Add local heuristic for inserted variables before existing slots.
16. Add local heuristic for deleted or reordered variables.
17. Add local heuristic for unsafe storage gap shrink/growth.
18. Add local heuristic for public initializer drift.
19. Add local heuristic for unprotected upgrade functions.
20. Keep no-signal output empty.

Extractor bridge:

21. Parse storage layout from compiler JSON when available.
22. Parse inheritance order changes.
23. Parse initializer modifiers.
24. Parse UUPS `proxiableUUID` presence.
25. Parse upgrade authorization modifiers.
26. Compute selector overlap between proxy and implementation.
27. Detect delegatecall fallback patterns.
28. Detect beacon implementation update paths.
29. Detect custom router implementation maps.
30. Preserve deterministic ordering.

Validation harness:

31. Generate Foundry dry-run migration skeletons.
32. Assert owner/admin slots before and after upgrade.
33. Assert total balances before and after upgrade.
34. Assert initializer cannot be replayed.
35. Assert only authorized admin can upgrade.
36. Assert proxy implementation slot remains valid.
37. Add fixture for storage collision.
38. Add fixture for selector collision.
39. Add fixture for unsafe reinitializer.
40. Add fixture for safe append-only upgrade.

Profile and reporting:

41. Add opt-in profile knob.
42. Add CLI JSON output.
43. Add MCP/schema exposure.
44. Add report section for upgrade risks.
45. Add report section for migration checks.
46. Add report section for rejected safe upgrades.
47. Run non-canonical fixture suite.
48. Compare transition-risk TPR/FPR only on ground-truth fixtures.
49. Prepare promotion memo for Fernando.
50. Update paper/benchmark claims only after explicit approval.

## 6. References

- USCSA: Evolution-Aware Security Analysis for Proxy-Based Upgradeable Smart
  Contracts: https://arxiv.org/abs/2512.08372
- OWASP SC10:2026 Proxy & Upgradeability Vulnerabilities:
  https://scs.owasp.org/sctop10/SC10-ProxyAndUpgradeabilityVulnerabilities/
- Smart Contract Security Field Guide, Upgradeability:
  https://scsfg.io/developers/upgradeability/
- Understanding and Characterizing Proxy-based Upgradeable Smart Contracts:
  https://www.usenix.org/system/files/sec23fall-prepub-415-bodell.pdf
