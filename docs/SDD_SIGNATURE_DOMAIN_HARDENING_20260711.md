# SDD: Signature Domain Hardening

Date: 2026-07-11
Owner lane: Codex
Status: proposed, first provider-neutral plan contract implemented

## 1. Signal

MIESC already covers invariant extraction, sequence oracles, semantic graph
gating, snapshot/dataflow fuzzing, economic simulation, metamorphic testing,
and upgrade evolution analysis. A remaining Solidity risk class is signed
authorization misuse: signatures can authorize sensitive actions, but replay or
domain mistakes may let a signature be reused across chains, contracts, users,
nonces, deadlines, smart accounts, or action scopes.

The technique here is signature-domain hardening: inventory every signed action
and require explicit evidence for domain binding, nonce consumption, deadline
checks, signer binding, value scope, malleability handling, and ERC-1271
contract-signature behavior.

Relevant external signals:

- EIP-712 standardizes typed structured data hashing, but explicitly does not
  include replay protection by itself.
- ERC-2612 permit relies on EIP-712 plus per-owner nonce and deadline semantics.
- OWASP SCSTG secure signature verification recommends EIP-712 validation,
  safe `ecrecover`, and dynamic tests with replayed or malformed signatures.
- ERC-1271 introduces contract signature verification and has seen replay
  issues when smart account domains are not sufficiently bound.
- Recent SRV research studies signature replay vulnerabilities across audited
  contracts and motivates automated detection of missing usage-condition checks.

## 2. Spec

Add `signature_domain_hardening` as a provider-neutral plan type.

Inputs:

- Solidity source.
- Existing findings.
- Optional ABI/function summary.
- Local-first policy constraints.

Output:

```json
{
  "signature_domain_hardening_plans": [
    {
      "id": "permit_domain_plan",
      "objective": "Harden permit signatures against cross-chain replay",
      "signed_actions": [
        {
          "id": "permit_owner_spender_value",
          "function": "permit",
          "signer_source": "owner recovered from ECDSA",
          "digest_scheme": "eip712",
          "domain_fields": ["name", "version", "chainId", "verifyingContract"],
          "nonce_source": "nonces[owner] increments on success",
          "deadline_source": "deadline checked before recover",
          "value_scope": ["owner", "spender", "value"],
          "evidence": ["permit digest includes owner spender value"]
        }
      ],
      "risks": [
        {
          "id": "missing_chain_id",
          "category": "domain_separator",
          "affected_action_id": "permit_owner_spender_value",
          "severity_hint": "high",
          "description": "domain separator does not bind chain id",
          "evidence": ["DOMAIN_SEPARATOR omits chainId"],
          "recommended_check": "replay same signature across chain ids"
        }
      ],
      "replay_tests": ["reuse signature after nonce consumption"],
      "recommended_tools": ["foundry", "echidna", "slither"],
      "confidence": 0.87,
      "evidence": ["permit and ecrecover are present"]
    }
  ]
}
```

Parser aliases:

- `signature_domain_hardening_plans`
- `signature_domain_plans`
- `signed_authorization_plans`

Non-goals:

- Confirming exploitability without replay or malformed-signature tests.
- Replacing invariant extraction for generic replay properties.
- Replacing sequence-oracle or metamorphic plans.
- Implementing a full local heuristic adapter in this checkpoint.
- Binding to a specific model, API, hosted provider, or local backend.
- Editing frozen paper artifacts or canonical benchmark outputs.

## 3. Design

Implemented first checkpoint:

1. Add `AgentCapability.SIGNATURE_DOMAIN_HARDENING`.
2. Add `SignedAction`.
3. Add `SignatureDomainRisk`.
4. Add `SignatureDomainHardeningPlan`.
5. Add `SignatureDomainHardeningAgent`.
6. Add `parse_signature_domain_hardening_plans()`.
7. Export the contract through `src.llm` and `miesc.llm`.

The plan is a hardening and replay-test artifact. It should feed Foundry,
Echidna, Slither, sequence-oracle replay tests, or a future local signature
adapter, but it does not by itself become a vulnerability finding.

False-positive controls:

- Plans require an objective.
- Plans require at least one signed action, risk, or replay test.
- Signed actions require id and function.
- Risks require id, category, and description.
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
- incomplete signature-domain plans are rejected;
- hostile fields are sanitized;
- public `miesc.llm` facade exports remain stable.

## 5. Integration Plan

The next 50 activities should remain additive and non-canonical until Fernando
approves a benchmark or paper baseline update.

Discovery and schema:

1. Inventory functions named `permit`.
2. Inventory functions using `ecrecover`.
3. Inventory functions using OpenZeppelin `ECDSA`.
4. Inventory functions calling `isValidSignature`.
5. Inventory `DOMAIN_SEPARATOR` declarations.
6. Inventory `_hashTypedDataV4` usage.
7. Inventory `nonces` mappings and increments.
8. Inventory deadline or expiry parameters.
9. Inventory off-chain order fill functions.
10. Define signed action taxonomy.

Contract and local heuristics:

11. Add signature-domain plan contracts.
12. Add parser and sanitization tests.
13. Add public exports.
14. Add local heuristic for EIP-712 domain fields.
15. Add local heuristic for missing chainId binding.
16. Add local heuristic for missing verifyingContract binding.
17. Add local heuristic for nonce read without consumption.
18. Add local heuristic for missing deadline check.
19. Add local heuristic for raw `ecrecover` without zero-address check.
20. Keep no-signal output empty.

Replay and malformed-signature checks:

21. Generate Foundry replay test skeletons.
22. Generate expired deadline tests.
23. Generate reused nonce tests.
24. Generate cross-chain domain mutation tests.
25. Generate cross-contract domain mutation tests.
26. Generate wrong signer tests.
27. Generate wrong spender/value scope tests.
28. Generate high-s signature malleability tests.
29. Generate ERC-1271 contract signer tests.
30. Generate smart-account replay tests.

Adapter bridge:

31. Route `SIGNATURE_DOMAIN_HARDENING` in local heuristic provider.
32. Emit canonical `signature_domain_hardening_plans` key.
33. Emit metadata strategy and count.
34. Consume ABI summary when available.
35. Preserve deterministic plan ordering.
36. Add resource/time budget policy.
37. Add MCP/schema exposure.
38. Add CLI JSON output behind opt-in profile.
39. Add report section for signed actions.
40. Add report section for replay tests.

Evaluation:

41. Add fixture for ERC-2612 safe permit.
42. Add fixture for permit missing nonce consumption.
43. Add fixture for permit missing deadline.
44. Add fixture for domain missing chainId.
45. Add fixture for domain missing verifyingContract.
46. Add fixture for raw ecrecover malleability.
47. Add fixture for ERC-1271 replay.
48. Run non-canonical fixture suite.
49. Compare signature-domain TPR/FPR only on ground-truth fixtures.
50. Update paper/benchmark claims only after explicit approval.

## 6. References

- EIP-712 Typed structured data hashing and signing:
  https://eips.ethereum.org/EIPS/eip-712
- ERC-2612 Permit Extension for EIP-20:
  https://eips.ethereum.org/EIPS/eip-2612
- ERC-1271 Standard Signature Validation Method for Contracts:
  https://eips.ethereum.org/EIPS/eip-1271
- OWASP SCSTG Secure Signature Verification:
  https://scs.owasp.org/SCSTG/tests/SCSVS-CRYPTO/SCSTG-TEST-0013/
- Demystifying and Detecting Signature Replay Vulnerabilities:
  https://arxiv.org/abs/2511.09134
- ERC-1271 signature replay vulnerability:
  https://www.alchemy.com/blog/erc-1271-signature-replay-vulnerability
